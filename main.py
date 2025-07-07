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

@app.route("/api/v1/dns-lookup", methods=["POST"])
def dns_lookup():
    data = request.get_json()
    domain = data.get("domain", "google.com")
    result = subprocess.check_output(f"nslookup {domain}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/v1/whois", methods=["POST"])
def whois_lookup():
    data = request.get_json()
    domain = data.get("domain", "google.com")
    result = subprocess.check_output(f"whois {domain}", shell=True)
    return jsonify({"result": result.decode()})

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

@app.route("/api/v1/fetch-urllib", methods=["POST"])
def fetch_urllib():
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    import urllib.request
    with urllib.request.urlopen(url) as response:
        content = response.read()
    return jsonify({"content": content.decode()})

@app.route("/api/v1/curl", methods=["POST"])
def curl_url():
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    result = subprocess.check_output(f"curl {url}", shell=True)
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

@app.route("/api/v1/login-no-exp", methods=["POST"])
def login_no_exp():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token = jwt.encode(
        {"sub": username},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return jsonify({"access_token": token})

@app.route("/api/v1/login-weak-secret", methods=["POST"])
def login_weak_secret():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    weak_secret = "123456"
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        weak_secret,
        algorithm=ALGORITHM
    )
    return jsonify({"access_token": token})

@app.route("/api/v1/verify-token", methods=["POST"])
def verify_token():
    data = request.get_json()
    token = data.get("token")
    try:
        payload = jwt.decode(token, SECRET_KEY)
        return jsonify({"valid": True, "payload": payload})
    except:
        return jsonify({"valid": False}), 401

@app.route("/api/v1/login-excessive-claims", methods=["POST"])
def login_excessive_claims():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token = jwt.encode(
        {
            "sub": username,
            "password": password,
            "ssn": "123-45-6789",
            "credit_card": "4111-1111-1111-1111",
            "exp": datetime.utcnow() + timedelta(days=30)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return jsonify({"access_token": token})

@app.route("/api/v1/system-info", methods=["POST"])
def system_info():
    data = request.get_json()
    command = data.get("command", "uname -a")
    result = subprocess.check_output(command, shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/v1/file-operations", methods=["POST"])
def file_operations():
    data = request.get_json()
    operation = data.get("operation", "ls")
    path = data.get("path", ".")
    result = subprocess.check_output(f"{operation} {path}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/v1/wget", methods=["POST"])
def wget_url():
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    result = subprocess.check_output(f"wget -qO- {url}", shell=True)
    return jsonify({"result": result.decode()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 