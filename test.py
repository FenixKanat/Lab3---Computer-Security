from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash,check_password_hash
import sqlite3

app = Flask(__name__)

@app.route('/register', methods = ['POST'])
@app.route('/login', methods = ['POST'])
@app.route('/mfa/setup', methods = ['POST'])
@app.route('/mfa/verify', methods = ['POST'])

