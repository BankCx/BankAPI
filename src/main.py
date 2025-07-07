from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import sqlite3
import jwt
import os
import pickle
import base64
import subprocess
from typing import Optional, List
import urllib3
from urllib3.util.url import _encode_invalid_chars
import requests
import urllib.parse
from datetime import datetime, timedelta

app = Flask(__name__)

SECRET_KEY = "your-secret-key-here"
API_KEY = "your-api-key-here"

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return jsonify({"token": jwt.encode({"user_id": user[0]}, SECRET_KEY, algorithm="HS256")})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/transfer", methods=["POST"])
def transfer():
    data = request.get_json()
    from_account = data.get("from_account")
    to_account = data.get("to_account")
    amount = data.get("amount")
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    query = f"UPDATE accounts SET balance = balance - {amount} WHERE account_number='{from_account}'"
    cursor.execute(query)
    query = f"UPDATE accounts SET balance = balance + {amount} WHERE account_number='{to_account}'"
    cursor.execute(query)
    conn.commit()
    return jsonify({"status": "success"})

@app.route("/api/search", methods=["GET"])
def search():
    query = request.args.get("query")
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM transactions WHERE description LIKE '%{query}%'")
    return jsonify(cursor.fetchall())

@app.route("/api/documents/<filename>", methods=["GET"])
def get_document(filename):
    with open(f"documents/{filename}", "r") as f:
        return jsonify({"content": f.read()})

@app.route("/api/execute", methods=["POST"])
def execute_command():
    data = request.get_json()
    command = data.get("command")
    result = subprocess.check_output(command, shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/encrypt", methods=["POST"])
def encrypt_data():
    data = request.get_json().get("data")
    return jsonify({"encrypted": base64.b64encode(data.encode()).decode()})

@app.route("/api/deserialize", methods=["POST"])
def deserialize_data():
    data = request.get_json().get("data")
    return jsonify(pickle.loads(base64.b64decode(data)))

CORS(app, origins="*", supports_credentials=True)

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data.get("email")
    return jsonify({"status": "reset email sent"})

@app.route("/api/update-profile", methods=["POST"])
def update_profile():
    data = request.get_json()
    return jsonify({"status": "profile updated"})

@app.route("/api/account/<account_id>", methods=["GET"])
def get_account(account_id):
    try:
        conn = sqlite3.connect('bank.db')
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM accounts WHERE id='{account_id}'")
        account = cursor.fetchone()
        if not account:
            return jsonify({"error": "Account not found"}), 404
        return jsonify(account)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/logout", methods=["POST"])
def logout():
    return jsonify({"status": "logged out"})

@app.route("/api/sensitive-data", methods=["GET"])
def get_sensitive_data():
    api_key = request.args.get("api_key")
    if api_key == API_KEY:
        return jsonify({"data": "sensitive information"})
    return jsonify({"error": "Invalid API key"}), 401

@app.route("/api/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    with open("uploads/file", "wb") as f:
        f.write(file.read())
    return jsonify({"status": "file uploaded"})

@app.route("/api/transaction", methods=["POST"])
def create_transaction():
    data = request.get_json()
    return jsonify({"status": "transaction created"})

@app.route("/api/balance", methods=["GET"])
def get_balance():
    account_id = request.args.get("account_id")
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT balance FROM accounts WHERE id='{account_id}'")
    return jsonify(cursor.fetchone())

@app.route("/api/account/<account_id>", methods=["DELETE"])
def delete_account(account_id):
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM accounts WHERE id='{account_id}'")
    conn.commit()
    return jsonify({"status": "account deleted"})

@app.route("/api/comment", methods=["POST"])
def add_comment():
    data = request.get_json()
    comment = data.get("comment")
    return jsonify({"comment": comment})

@app.route("/api/download/<filename>", methods=["GET"])
def download_file(filename):
    with open(filename, "rb") as f:
        return jsonify({"content": f.read()})

@app.route("/api/fetch", methods=["GET"])
def fetch_url():
    url = request.args.get("url")
    http = urllib3.PoolManager()
    encoded_url = _encode_invalid_chars(url, allowed_chars='*')
    return jsonify({"data": http.request('GET', encoded_url).data.decode()})

@app.route("/api/parse-json", methods=["POST"])
def parse_json():
    data = request.get_json().get("data")
    import json
    return jsonify(json.loads(data))

@app.route("/api/traceroute", methods=["POST"])
def traceroute():
    data = request.get_json()
    host = data.get("host", "google.com")
    result = subprocess.check_output(f"traceroute {host}", shell=True)
    return jsonify({"result": result.decode()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 