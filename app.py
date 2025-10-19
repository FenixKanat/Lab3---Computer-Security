from flask import Flask, json, request, jsonify, render_template, session, g
import sqlite3
import os
import base64
import hashlib
import hmac
import bcrypt
import uuid
from enum import Enum
from secrets import compare_digest
from flask_cors import CORS
from argon2 import low_level
from fido2.webauthn import PublicKeyCredentialRpEntity, UserVerificationRequirement, RegistrationResponse, AuthenticationResponse, AttestedCredentialData, Aaguid
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2 import cbor
from fido2.cose import CoseKey


from mfa import (
    random_secret,
    otpauth_uri_totp,
    otpauth_uri_hotp,
    qr_data_url,
    verify_totp,
    verify_hotp_and_advance,
)

app = Flask(__name__)
app.config['PEPPER'] = 'this_is_a_secret_pepper_value'
app.config['SECRET_KEY'] = 'flask-session-secret-key' 

CORS(app)

RP_ID = 'localhost' 
RP_NAME = 'My Secure App'
ORIGIN = 'http://localhost:5000' 

rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
fido2_server = Fido2Server(rp=rp, attestation="direct")

DATABASE = 'users.db'
# ---------------- Hashing parameters ----------------
PBKDF2_ITERATIONS = 200_000
BCRYPT_ROUNDS = 12
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
USE_PEPPER = False
MAC_SECRET_KEY = b'super_secret_mac_key'


# ---------------- Database ----------------
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT,
                        algo TEXT NOT NULL,
                        mfa_secret TEXT)''')
        # MFA) minimal, additive columns ===
        add_column_if_missing(conn, 'mfa_type', 'TEXT')                      # 'totp' or 'hotp'
        add_column_if_missing(conn, 'hotp_counter', 'INTEGER DEFAULT 0')     # for HOTP resync demo
        add_column_if_missing(conn, 'mfa_accepts', 'INTEGER DEFAULT 0')      # stats
        add_column_if_missing(conn, 'mfa_failures', 'INTEGER DEFAULT 0')
        # FIDO2/WebAuthn columns ===
        add_column_if_missing(conn, 'user_handle', 'TEXT')
        # Create the new table for FIDO credentials
        conn.execute('''CREATE TABLE IF NOT EXISTS fido_credentials(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        device_name TEXT, 
                        credential_id TEXT NOT NULL UNIQUE, 
                        public_key TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                   )''')

def add_column_if_missing(conn,column, coldef):
    cur = conn.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cur.fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE users ADD COLUMN {column} {coldef}")

def migrate_user_handles():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE user_handle IS NULL")
        users_to_update = cur.fetchall()
        
        for user in users_to_update:
            # Generate a new, random, stable user handle (UUID is good)
            user_handle = websafe_encode(uuid.uuid4().bytes)
            conn.execute("UPDATE users SET user_handle = ? WHERE id = ?", (user_handle, user['id']))
        print(f"Migrated user_handles for {len(users_to_update)} users.")
        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_user_handle ON users (user_handle)')

# ---------------- Hashing functions ----------------
def generate_salt(length=16):
    return os.urandom(length)

# Both SHA-256 and SHA-3 belong to Password-Based Key Derivation Function 2
def pbkdf2_hash(password: str, salt: bytes, algo: str, iterations=PBKDF2_ITERATIONS):
    password_bytes = password.encode('utf-8')
    if algo == 'sha256':
        hashed_bytes = hashlib.pbkdf2_hmac(algo, password=password_bytes, salt=salt, iterations=iterations)
    elif algo == 'sha3':
        hashed_bytes = hashlib.pbkdf2_hmac("sha3_256", password=password_bytes, salt=salt, iterations=iterations)
    else:
        raise ValueError("Unsupported pbkdf2 algorithm")

    return hashed_bytes.hex(), salt.hex()


def verify_pbkdf2(attempted_password: str, stored_hash: str, salt: str, algo: str, iterations=PBKDF2_ITERATIONS):

    (recomputed_hash, _) = pbkdf2_hash(attempted_password, bytes.fromhex(salt), algo, iterations=iterations)
    return compare_digest(bytes.fromhex(recomputed_hash), bytes.fromhex(stored_hash))



def bcrypt_hash(password: str):
    pw = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    h = bcrypt.hashpw(pw, salt)
    return (h.decode('utf-8'), salt.decode('utf-8'))


def verify_bcrypt(password: str, stored: str):
    if isinstance(stored, str):
        stored = stored.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), stored)

def argon2_hash(password: str, salt: bytes):
    password_bytes = password.encode('utf-8')
    hashed_bytes = low_level.hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=low_level.Type.ID
    )
    return hashed_bytes.hex(), salt.hex()

def verify_argon2(attempted_password: str, stored_hash: str, salt: str):
    (recomputed_hash, _) = argon2_hash(attempted_password, bytes.fromhex(salt))
    return compare_digest(bytes.fromhex(recomputed_hash), bytes.fromhex(stored_hash))

# ---------------- MAC/HMAC functions ----------------

def create_naive_mac(user_id: int):
    
    payload = {'user_id': user_id}
    data_bytes = json.dumps(payload).encode('utf-8')
    data_b64 = base64.b64encode(data_bytes).decode('utf-8')
    mac = hashlib.sha256(MAC_SECRET_KEY + data_bytes).hexdigest()

    return f"{data_b64}.{mac}"

def create_hmac(user_id: int):

    payload = {'user_id': user_id}
    data_bytes = json.dumps(payload).encode('utf-8')
    data_b64 = base64.b64encode(data_bytes).decode('utf-8')

    hmac_tag = hmac.new(MAC_SECRET_KEY, data_bytes, hashlib.sha256)
    h = hmac_tag.hexdigest()

    return f"{data_b64}.{h}"

def verify_hmac(hmac_tag: str):
    try:
        data_b64, received_tag = hmac_tag.split('.', 1)
    except ValueError:
        return None 
        
    try:
        data_str = base64.b64decode(data_b64).decode('utf-8')
    except Exception:
        return None 
    
    expected_tag = hmac.new(
        key=MAC_SECRET_KEY, 
        msg=data_str.encode('utf-8'), 
        digestmod=hashlib.sha256
    ).hexdigest()

    return compare_digest(expected_tag, received_tag)

# ---------------- Helper functions ----------------
def get_current_user():
    user = getattr(g, '_user', None)
    if user is None and 'user_id' in session:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
            user = cur.fetchone()
            g._user = user
    return user


# ---------------- Routes ----------------
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/account')
def account():
    return render_template('account.html')


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    algo = data.get('algo')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    generated_salt = generate_salt()
    effective_password = password
    user_handle = websafe_encode(uuid.uuid4().bytes)
    if USE_PEPPER:
        effective_password = app.config['PEPPER'] + password

    try:
        if algo in ('sha256', 'sha3'):
            password_hash, salt = pbkdf2_hash(effective_password, generated_salt, algo)
        elif algo == 'bcrypt':
            (password_hash, salt) = bcrypt_hash(effective_password)
        elif algo == 'argon2':
            (password_hash, salt) = argon2_hash(effective_password, generated_salt)
        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        with sqlite3.connect(DATABASE) as conn:
            conn.execute("INSERT INTO users (username, password_hash, salt, algo, user_handle) VALUES (?, ?, ?, ?, ?)",
                         (username, password_hash, salt, algo, user_handle))
        print(f"[REGISTER] User '{username}' registered with {algo}")
        return jsonify({'message': 'User registered successfully', 'algo': algo}), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        print("[ERROR REGISTER]", e)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.execute("SELECT id, password_hash, salt, algo FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

    if row is None:
        print(f"[LOGIN] User not found: {username}")
        return jsonify({'error': 'Invalid username or password'}), 401

    user_id, stored_hash, salt, algo = row
    attempted_password = app.config['PEPPER'] + password if USE_PEPPER else password

    print(f"[LOGIN] username={username}, algo={algo}, pepper={USE_PEPPER}")

    verified = False
    if algo in ('sha256', 'sha3'):
        verified = verify_pbkdf2(attempted_password, stored_hash, salt, algo)
    elif algo == 'bcrypt':
        verified = verify_bcrypt(attempted_password, stored_hash)
    elif algo == 'argon2':
        verified = verify_argon2(attempted_password, stored_hash, salt)

    print(f"[LOGIN] verified={verified}")

    if verified:
        # If user has MFA, require OTP before issuing final hmac
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.execute("SELECT mfa_secret, mfa_type FROM users WHERE id = ?", (user_id,))
            mfa_row = cur.fetchone()
        mfa_required = bool(mfa_row and mfa_row[0])
        if mfa_required:
            # Do NOT send final hmac yet. Client must call /mfa/verify to get it.
            return jsonify({
                'message': 'Password OK — MFA required',
                'user_id': user_id,
                'mfa_required': True,
                'mfa_type': mfa_row[1]
            }), 200
        # No MFA → same behavior as before
        naive_mac = create_naive_mac(user_id)
        hmac_tag = create_hmac(user_id)
        session['user_id'] = user_id
        return jsonify({'message': 'Login successful', 'user_id': user_id, 'naive_mac': naive_mac, 'hmac': hmac_tag}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/message', methods=['POST'])
def message():
    data = request.get_json(force=True)
    message = data.get('message')
    hmac_tag = data.get('hmac_tag')

    if not message or not hmac_tag:
        return jsonify({'error': 'Message and HMAC tag are required'}), 400

    
    if not verify_hmac(hmac_tag):
        return jsonify({'error': 'Invalid HMAC tag'}), 403

    print(f"[MESSAGE] {message}")
    return jsonify({'message': 'Message verified successfully with HMAC'}), 200


@app.route('/webauthn/register/begin', methods=['POST'])
def webauthn_register_begin():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT credential_id FROM fido_credentials WHERE user_id = ?", (user['id'],))
        credential_ids_b64 = [row[0] for row in cur.fetchall()]

    credential_ids_bytes = [websafe_decode(cred_id_b64) for cred_id_b64 in credential_ids_b64]

    exclude_credentials_descriptors = [
        {"type": "public-key", "id": cred_id_bytes}
        for cred_id_bytes in credential_ids_bytes
    ]

    registration_data, state = fido2_server.register_begin(
        {
            'id': websafe_decode(user['user_handle']),
            'name': user['username'],
            'displayName': user['username'],
        },
        credentials=exclude_credentials_descriptors,
        user_verification=UserVerificationRequirement.DISCOURAGED
    )

    session['webauthn_register_state'] = state

    data_dict = dict(registration_data) 
    
    return jsonify(data_dict)


@app.route('/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json()
    state = session.pop('webauthn_register_state', None)
    device_name = data.pop('deviceName', 'Unnamed Key') 

    try:
        response = RegistrationResponse.from_dict(data)

        auth_data = fido2_server.register_complete(state, response)
    except Exception as e:
        return jsonify({'error': f'Registration failed: {e}'}), 400

    credential_data = auth_data.credential_data
    credential_id_b64 = websafe_encode(credential_data.credential_id)
    public_key_object = credential_data.public_key
    public_key_cbor = cbor.encode(public_key_object)
    public_key_b64 = websafe_encode(public_key_cbor)
    
    with sqlite3.connect(DATABASE) as conn:
        conn.execute(
            """INSERT INTO fido_credentials 
               (user_id, device_name, credential_id, public_key) 
               VALUES (?, ?, ?, ?)""",
            (
                user['id'],
                device_name,
                credential_id_b64,
                public_key_b64
            )
        )

    return jsonify({'status': 'ok', 'device_name': device_name})


@app.route('/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    username = request.get_json().get('username')
    if not username:
        return jsonify({'error': 'Username required'}), 400

    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        cur.execute("SELECT credential_id FROM fido_credentials WHERE user_id = ?", (user['id'],))
        
        credential_ids_b64 = [row['credential_id'] for row in cur.fetchall()]

        if not credential_ids_b64:
            return jsonify({'error': 'No FIDO credentials registered for this user'}), 400
        
        credential_ids_bytes = [websafe_decode(cred_id_b64) for cred_id_b64 in credential_ids_b64]

        allow_credentials_descriptors = [
            {"type": "public-key", "id": cred_id_bytes}
            for cred_id_bytes in credential_ids_bytes
        ]
    auth_data, state = fido2_server.authenticate_begin(allow_credentials_descriptors, user_verification=UserVerificationRequirement.DISCOURAGED)

    session['webauthn_login_state'] = state
    session['webauthn_login_user_id'] = user['id'] 

    data_dict = dict(auth_data)
    
    return jsonify(data_dict)


@app.route('/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    data = request.get_json()
    state = session.pop('webauthn_login_state', None)
    user_id = session.pop('webauthn_login_user_id', None)

    if not state or not user_id:
        return jsonify({'error': 'Invalid state'}), 400

    credential_id_b64 = data['id']

    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """SELECT public_key FROM fido_credentials
               WHERE credential_id = ? AND user_id = ?""",
            (credential_id_b64, user_id)
        )
        cred = cur.fetchone()

    if not cred:
        return jsonify({'error': 'Credential not found for this user'}), 404

    try:
        credential_id_bytes = websafe_decode(credential_id_b64)
        public_key_cbor = websafe_decode(cred['public_key'])
        public_key_dict = cbor.decode(public_key_cbor)
        public_key_object = CoseKey.parse(public_key_dict)
        stored_attested_credential = AttestedCredentialData.create(
            Aaguid.NONE,
            credential_id_bytes,
            public_key_object
        )

        parsed_response = AuthenticationResponse.from_dict(data)

        verified_credential_data = fido2_server.authenticate_complete(
            state,
            [stored_attested_credential],
            parsed_response 
        )

    except ValueError as e:
        return jsonify({'error': f'Login failed: {e}'}), 401
    except Exception as e: 
        print(f"!!! ERROR during authentication completion: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Login failed: {e}'}), 500

    session.clear()
    session['user_id'] = user_id
    hmac_tag = create_hmac(user_id)
    return jsonify({'message': 'Login successful', 'user_id': user_id, 'hmac': hmac_tag}), 200

# MFA
@app.route('/mfa/enroll', methods=['POST'])
def mfa_enroll():
    """
    Body: { "username": "...", "type": "totp" | "hotp" }
    Creates secret, stores it, returns otpauth URI + QR data URL.
    """
    data = request.get_json(force=True)
    username = data.get('username')
    mfa_type = (data.get('type') or 'totp').lower()
    if mfa_type not in ('totp', 'hotp'):
        return jsonify({'error': 'type must be totp or hotp'}), 400

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'User not found'}), 404

        secret = random_secret()
        if mfa_type == 'totp':
            uri = otpauth_uri_totp(secret, username)
        else:
            uri = otpauth_uri_hotp(secret, username, counter=0)

        conn.execute("""
            UPDATE users SET mfa_secret=?, mfa_type=?, hotp_counter=0 WHERE username=?
        """, (secret, mfa_type, username))

    qr_url = qr_data_url(uri)
    return jsonify({
        'message': f'{mfa_type.upper()} MFA enrolled',
        'secret': secret,
        'otpauth_uri': uri,
        'qr_data_url': qr_url
    }), 200


@app.route('/mfa/verify', methods=['POST'])
def mfa_verify():

    data = request.get_json(force=True)
    username = data.get('username')
    code = (data.get('code') or "").strip()
    window = int(data.get('window') or 0)
    look_ahead = int(data.get('look_ahead') or 0)

    if not username or not code:
        return jsonify({'error': 'username and code required'}), 400

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.execute("""
            SELECT id, mfa_secret, mfa_type, hotp_counter, mfa_accepts, mfa_failures
            FROM users WHERE username=?
        """, (username,))
        row = cur.fetchone()
        if not row or not row[1]:
            return jsonify({'error': 'MFA not enrolled for this user'}), 400

        user_id, secret, mfa_type, hotp_counter, accepts, failures = row

        if mfa_type == 'totp':
            ok = verify_totp(secret, code, window=window)
            if ok:
                accepts = (accepts or 0) + 1
                conn.execute("UPDATE users SET mfa_accepts=? WHERE id=?", (accepts, user_id))
                # Issue final token now that MFA passed
                hmac_tag = create_hmac(user_id)
                return jsonify({'result': 'accepted', 'type': 'totp', 'window': window,
                                'accepts': accepts, 'failures': failures or 0, 'hmac': hmac_tag}), 200
            else:
                failures = (failures or 0) + 1
                conn.execute("UPDATE users SET mfa_failures=? WHERE id=?", (failures, user_id))
                return jsonify({'result': 'rejected', 'type': 'totp', 'window': window,
                                'accepts': accepts or 0, 'failures': failures}), 401

        # HOTP:
        hotp_counter = hotp_counter or 0
        ok, new_counter, matched_offset = verify_hotp_and_advance(secret, code, hotp_counter, look_ahead=look_ahead)
        if ok:
            accepts = (accepts or 0) + 1
            conn.execute("UPDATE users SET mfa_accepts=?, hotp_counter=? WHERE id=?",
                         (accepts, new_counter, user_id))
            hmac_tag = create_hmac(user_id)
            session['user_id'] = user_id
            return jsonify({'result': 'accepted', 'type': 'hotp',
                            'matched_offset': matched_offset, 'new_counter': new_counter,
                            'accepts': accepts, 'failures': failures or 0, 'hmac': hmac_tag}), 200
        else:
            failures = (failures or 0) + 1
            conn.execute("UPDATE users SET mfa_failures=? WHERE id=?", (failures, user_id))
            return jsonify({'result': 'rejected', 'type': 'hotp',
                            'look_ahead': look_ahead, 'server_counter': hotp_counter,
                            'accepts': accepts or 0, 'failures': failures}), 401


if __name__ == '__main__':
    arguments = os.sys.argv
    if len(arguments) > 1 and arguments[1] == 'pepper':
        USE_PEPPER = True
    init_db()
    # Migrate existing users to have user_handles for FIDO
    migrate_user_handles()
    print(f"Starting app with USE_PEPPER = {USE_PEPPER}")
    app.run(host='0.0.0.0', port=5000, debug=False)
