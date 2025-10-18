from flask import Flask, json, request, jsonify, render_template
import sqlite3
import os
import base64
import hashlib
import hmac
from secrets import compare_digest
import bcrypt
from flask_cors import CORS
from argon2 import low_level

app = Flask(__name__)
CORS(app)

DATABASE = 'users.db'
app.config['PEPPER'] = 'this_is_a_secret_pepper_value'

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


# ---------------- Routes ----------------
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')


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
            conn.execute("INSERT INTO users (username, password_hash, salt, algo) VALUES (?, ?, ?, ?)",
                         (username, password_hash, salt, algo))
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
        naive_mac = create_naive_mac(user_id)
        hmac = create_hmac(user_id)
        return jsonify({'message': 'Login successful', 'user_id': user_id, 'naive_mac': naive_mac, 'hmac': hmac}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/message', methods=['POST'])
def message():
    data = request.get_json(force=True)
    message = data.get('message')
    hmac_tag = data.get('hmac_tag')

    if not message or not hmac_tag:
        return jsonify({'error': 'Message and HMAC tag are required'}), 400

    # Verify the HMAC tag
    if not verify_hmac(hmac_tag):
        return jsonify({'error': 'Invalid HMAC tag'}), 403

    print(f"[MESSAGE] {message}")
    return jsonify({'message': 'Message verified successfully with HMAC'}), 200

# @app.route('/salt_pepper_demo', methods=['POST'])
# def salt_pepper_demo():
#     data = request.get_json(force=True)
#     password = data.get('password')
#     if not password:
#         return jsonify({'error': 'Password required'}), 400

#     salt_user = generate_salt()
#     hash_with_salt = pbkdf2_hash(password, salt_user, 'sha256', PBKDF2_ITERATIONS)

#     pepper = app.config.get('PEPPER')
#     hash_with_pepper = pbkdf2_hash(pepper + password, generate_salt(), 'sha256', PBKDF2_ITERATIONS)

#     explanation = [
#         "Per-user salt ensures unique hashes for identical passwords.",
#         "System-wide pepper is stored outside the DB; without it, hashes are useless.",
#         "Best practice: use both salt and pepper with a slow hash like bcrypt."
#     ]

#     return jsonify({
#         'hash_with_salt_example': hash_with_salt,
#         'salt_stored_example': salt_user,
#         'hash_with_pepper_example': hash_with_pepper,
#         'pepper_note': "Pepper is not stored in the database; it's from environment variables.",
#         'explanation': explanation
#     }), 200


# ---------------- Run app ----------------
if __name__ == '__main__':
    arguments = os.sys.argv
    if len(arguments) > 1 and arguments[1] == 'pepper':
        USE_PEPPER = True
    init_db()
    print(f"Starting app with USE_PEPPER = {USE_PEPPER}")
    app.run(host='0.0.0.0', port=5000, debug=False)
