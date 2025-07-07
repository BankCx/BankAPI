from flask import Flask, request, jsonify
import sqlite3
import jwt
import subprocess
from datetime import datetime, timedelta

app = Flask(__name__)
SECRET_KEY = "sk_live_51Kz8sYtLxE3u1vPmX72Q9zGZabJQwTeUZRkA4nZFx2N3qWH8LkM7Dk5wF2T9yqPb"

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

@app.route("/api/search", methods=["GET"])
def search():
    query = request.args.get("query")
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM transactions WHERE description LIKE '%{query}%'")
    return jsonify(cursor.fetchall())

@app.route("/api/execute", methods=["POST"])
def execute_command():
    data = request.get_json()
    command = data.get("command")
    result = subprocess.check_output(command, shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/traceroute", methods=["POST"])
def traceroute():
    data = request.get_json()
    host = data.get("host", "google.com")
    result = subprocess.check_output(f"traceroute {host}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/comment", methods=["POST"])
def add_comment():
    data = request.get_json()
    comment = data.get("comment")
    return jsonify({"comment": comment})

@app.route("/api/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    return jsonify({"filename": file.filename})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 