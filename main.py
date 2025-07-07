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

# Intentionally vulnerable - hardcoded secret key
SECRET_KEY = "sk_cxapi_51Kz8sYtLxE3u1vPmX72Q9zGZabJQwTeUZRkA4nZFx2N3qWH8LkM7Dk5wF2T9yqPb"
ALGORITHM = "HS256"

app = Flask(__name__)

# Intentionally vulnerable - overly permissive CORS
CORS(app, origins="*", supports_credentials=True)

# Intentionally vulnerable - no rate limiting
# Intentionally vulnerable - no request validation
@app.route("/api/v1/transfers", methods=["POST"])
def create_transfer():
    # Intentionally vulnerable - no input validation
    # Intentionally vulnerable - no amount limits
    # Intentionally vulnerable - no account ownership verification
    transfer_data = request.get_json()
    return jsonify({"status": "success", "transfer_id": "12345"})

# Intentionally vulnerable - no proper authentication
@app.route("/api/v1/accounts/<account_id>", methods=["GET"])
def get_account(account_id):
    # Intentionally vulnerable - no authorization check
    # Intentionally vulnerable - SQL injection risk
    return jsonify({"account_id": account_id, "balance": 1000.00})

# Intentionally vulnerable - command injection
@app.route("/api/v1/process-file", methods=["POST"])
def process_file():
    # Intentionally vulnerable - command injection
    file_path = request.get_json().get("file_path")
    result = subprocess.check_output(f"process {file_path}", shell=True)
    return jsonify({"result": result.decode()})

# Intentionally vulnerable - insecure deserialization
@app.route("/api/v1/batch-process", methods=["POST"])
def batch_process():
    # Intentionally vulnerable - unsafe deserialization
    data = request.get_json().get("data")
    processed_data = json.loads(data)
    return jsonify({"status": "processed", "data": processed_data})

# Intentionally vulnerable - no proper JWT validation
@app.route("/api/v1/login", methods=["POST"])
def login():
    # Intentionally vulnerable - weak password hashing
    # Intentionally vulnerable - no rate limiting
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return jsonify({"access_token": token})

# Intentionally vulnerable - no proper error handling
@app.route("/api/v1/transactions", methods=["GET"])
def get_transactions():
    # Intentionally vulnerable - no pagination
    # Intentionally vulnerable - no data validation
    account_id = request.args.get("account_id")
    return jsonify({"transactions": []})

# Intentionally vulnerable - no proper file upload validation
@app.route("/api/v1/upload", methods=["POST"])
def upload_file():
    # Intentionally vulnerable - no file type validation
    # Intentionally vulnerable - no file size limit
    file = request.files.get("file")
    return jsonify({"filename": "uploaded_file.txt"})

# Intentionally vulnerable - no proper API key validation
@app.route("/api/v1/sensitive-data", methods=["GET"])
def get_sensitive_data():
    # Intentionally vulnerable - hardcoded API key check
    api_key = request.args.get("api_key")
    if api_key == "test-api-key-123":
        return jsonify({"data": "sensitive information"})
    return jsonify({"error": "Invalid API key"}), 401

# Intentionally vulnerable - no proper logging
@app.route("/api/v1/log", methods=["POST"])
def log_event():
    # Intentionally vulnerable - logging sensitive data
    event = request.get_json()
    print(f"Event: {event}")
    return jsonify({"status": "logged"})

# NEW: Intentionally vulnerable - Command Injection via ping
@app.route("/api/v1/ping", methods=["POST"])
def ping_host():
    # Intentionally vulnerable - command injection via ping
    data = request.get_json()
    host = data.get("host", "localhost")
    # Vulnerable to command injection: ping -c 4 {host}
    result = subprocess.check_output(f"ping -c 4 {host}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - Command Injection via nslookup
@app.route("/api/v1/dns-lookup", methods=["POST"])
def dns_lookup():
    # Intentionally vulnerable - command injection via nslookup
    data = request.get_json()
    domain = data.get("domain", "google.com")
    # Vulnerable to command injection: nslookup {domain}
    result = subprocess.check_output(f"nslookup {domain}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - Command Injection via whois
@app.route("/api/v1/whois", methods=["POST"])
def whois_lookup():
    # Intentionally vulnerable - command injection via whois
    data = request.get_json()
    domain = data.get("domain", "google.com")
    # Vulnerable to command injection: whois {domain}
    result = subprocess.check_output(f"whois {domain}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - SSRF via requests
@app.route("/api/v1/fetch-url", methods=["POST"])
def fetch_url():
    # Intentionally vulnerable - SSRF via requests
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    # Vulnerable to SSRF - no URL validation
    response = requests.get(url, timeout=5)
    return jsonify({
        "status_code": response.status_code,
        "content": response.text,
        "headers": dict(response.headers)
    })

# NEW: Intentionally vulnerable - SSRF via urllib
@app.route("/api/v1/fetch-urllib", methods=["POST"])
def fetch_urllib():
    # Intentionally vulnerable - SSRF via urllib
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    # Vulnerable to SSRF - no URL validation
    import urllib.request
    with urllib.request.urlopen(url) as response:
        content = response.read()
    return jsonify({"content": content.decode()})

# NEW: Intentionally vulnerable - SSRF via curl command
@app.route("/api/v1/curl", methods=["POST"])
def curl_url():
    # Intentionally vulnerable - SSRF via curl command
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    # Vulnerable to SSRF and command injection
    result = subprocess.check_output(f"curl {url}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - JWT token with weak algorithm
@app.route("/api/v1/login-weak-jwt", methods=["POST"])
def login_weak_jwt():
    # Intentionally vulnerable - JWT with weak algorithm
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - using 'none' algorithm
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        None,
        algorithm="none"
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - JWT token with no expiration
@app.route("/api/v1/login-no-exp", methods=["POST"])
def login_no_exp():
    # Intentionally vulnerable - JWT with no expiration
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - no expiration time
    token = jwt.encode(
        {"sub": username},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - JWT token with weak secret
@app.route("/api/v1/login-weak-secret", methods=["POST"])
def login_weak_secret():
    # Intentionally vulnerable - JWT with weak secret
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - using weak secret
    weak_secret = "123456"
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        weak_secret,
        algorithm=ALGORITHM
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - JWT token validation bypass
@app.route("/api/v1/verify-token", methods=["POST"])
def verify_token():
    # Intentionally vulnerable - JWT validation bypass
    data = request.get_json()
    token = data.get("token")
    try:
        # Vulnerable - no algorithm specification in decode
        payload = jwt.decode(token, SECRET_KEY)
        return jsonify({"valid": True, "payload": payload})
    except:
        return jsonify({"valid": False}), 401

# NEW: Intentionally vulnerable - JWT token with excessive claims
@app.route("/api/v1/login-excessive-claims", methods=["POST"])
def login_excessive_claims():
    # Intentionally vulnerable - JWT with excessive claims
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - including sensitive data in JWT
    token = jwt.encode(
        {
            "sub": username,
            "password": password,  # Vulnerable - password in JWT
            "ssn": "123-45-6789",  # Vulnerable - SSN in JWT
            "credit_card": "4111-1111-1111-1111",  # Vulnerable - CC in JWT
            "exp": datetime.utcnow() + timedelta(days=30)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - Command injection via system info
@app.route("/api/v1/system-info", methods=["POST"])
def system_info():
    # Intentionally vulnerable - command injection via system commands
    data = request.get_json()
    command = data.get("command", "uname -a")
    # Vulnerable to command injection
    result = subprocess.check_output(command, shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - Command injection via file operations
@app.route("/api/v1/file-operations", methods=["POST"])
def file_operations():
    # Intentionally vulnerable - command injection via file operations
    data = request.get_json()
    operation = data.get("operation", "ls")
    path = data.get("path", ".")
    # Vulnerable to command injection
    result = subprocess.check_output(f"{operation} {path}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - SSRF via wget
@app.route("/api/v1/wget", methods=["POST"])
def wget_url():
    # Intentionally vulnerable - SSRF via wget
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    # Vulnerable to SSRF and command injection
    result = subprocess.check_output(f"wget -qO- {url}", shell=True)
    return jsonify({"result": result.decode()})

if __name__ == "__main__":
    # Intentionally vulnerable - no SSL/TLS
    app.run(host="0.0.0.0", port=8000, debug=True) 