from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from sqlalchemy.orm import Session
from typing import List
import jwt
import json
import os
import subprocess
from datetime import datetime, timedelta
import requests
import urllib.parse

SECRET_KEY = "sk_cxapi_51Kz8sYtLxE3u1vPmX72Q9zGZabJQwTeUZRkA4nZFx2N3qWH8LkM7Dk5wF2T9yqPb"
ALGORITHM = "HS256"

app = Flask(__name__)

CORS(app, origins="*", supports_credentials=True)

@app.route("/api/v1/transfers", methods=["POST"])
def create_transfer():
    transfer_data = request.get_json()
    return jsonify({"status": "success", "transfer_id": "12345"})

@app.route("/api/v1/accounts/<account_id>", methods=["GET"])
def get_account(account_id):
    return jsonify({"account_id": account_id, "balance": 1000.00})

@app.route("/api/v1/process-file", methods=["POST"])
def process_file():
    file_path = request.get_json().get("file_path")
    result = subprocess.check_output(f"process {file_path}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/v1/batch-process", methods=["POST"])
def batch_process():
    data = request.get_json().get("data")
    processed_data = json.loads(data)
    return jsonify({"status": "processed", "data": processed_data})

@app.route("/api/v1/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return jsonify({"access_token": token})

@app.route("/api/v1/transactions", methods=["GET"])
def get_transactions():
    account_id = request.args.get("account_id")
    return jsonify({"transactions": []})

@app.route("/api/v1/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    return jsonify({"filename": "uploaded_file.txt"})

@app.route("/api/v1/sensitive-data", methods=["GET"])
def get_sensitive_data():
    api_key = request.args.get("api_key")
    if api_key == "test-api-key-123":
        return jsonify({"data": "sensitive information"})
    return jsonify({"error": "Invalid API key"}), 401

@app.route("/api/v1/log", methods=["POST"])
def log_event():
    event = request.get_json()
    print(f"Event: {event}")
    return jsonify({"status": "logged"})

@app.route("/api/v1/ping", methods=["POST"])
def ping_host():
    data = request.get_json()
    host = data.get("host", "localhost")
    result = subprocess.check_output(f"ping -c 4 {host}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/v1/login-weak-jwt", methods=["POST"])
def login_weak_jwt():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        None,
        algorithm="none"
    )
    return jsonify({"access_token": token})

@app.route("/api/v1/comment", methods=["POST"])
def add_comment():
    data = request.get_json()
    comment = data.get("comment")
    return jsonify({"comment": comment})

@app.route("/api/v1/fetch-url", methods=["POST"])
def fetch_url():
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    response = requests.get(url, timeout=5)
    return jsonify({
        "status_code": response.status_code,
        "content": response.text,
        "headers": dict(response.headers)
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 