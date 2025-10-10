from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash,check_password_hash
import sqlite3

app = Flask(__name__)
DATABASE = 'users.db'

def init_db():
    with sqlite3.connect(DATABASE) as connect:
        connect.execute('''CREATE TABLE IF NOT EXISTS users(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        mfa_secret TEXT)''')

@app.route('/register', methods = ['POST'])
def register():



@app.route('/login', methods = ['POST'])
def login():


@app.route('/mfa/setup', methods = ['POST'])
@app.route('/mfa/verify', methods = ['POST'])

