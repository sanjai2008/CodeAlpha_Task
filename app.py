from flask import Flask, request, render_template, jsonify
import sqlite3
from crypto_utils import encrypt, decrypt
from auth import generate_token, verify_token

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect("secure.db")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    if not username.isalnum() or len(username) < 3:
        return "Invalid username!", 400

    enc_pwd = encrypt(password)
    conn = sqlite3.connect("secure.db")
    try:
        conn.execute("INSERT INTO users(username, password) VALUES (?, ?)", (username, enc_pwd))
        conn.commit()
    except sqlite3.IntegrityError:
        return "Username exists!", 409
    finally:
        conn.close()

    return "Registered OK!", 200

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect("secure.db")
    row = conn.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if row and decrypt(row[0]) == password:
        token = generate_token(username, ["read_user"])
        return jsonify(token=token), 200

    return "Login failed", 401

@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get("Authorization", "").split("Bearer ")[-1]
    if not token or not verify_token(token, "read_user"):
        return "Unauthorized", 401
    return jsonify(secret="Sensitive info here")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
