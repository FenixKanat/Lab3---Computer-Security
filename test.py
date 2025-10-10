from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash,check_password_hash
import sqlite3

app = Flask(__name__)
DATABASE = 'users.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        mfa_secret TEXT)''')

@app.route('/register', methods = ['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get ('password')

    if not username or not password:
        return jsonify({'error' : 'Username and password required'}),400
    
    password_hash = generate_password_hash(password)

    try:

        with sqlite3.connect(DATABASE) as conn:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                         (username, password_hash))
            return jsonify({'message' : 'User registered successfully'}),201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}),409



@app.route('/login', methods = ['POST'])
def login():


@app.route('/mfa/setup', methods = ['POST'])
@app.route('/mfa/verify', methods = ['POST'])

