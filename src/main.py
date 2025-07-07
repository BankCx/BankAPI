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

# Intentionally vulnerable - hardcoded secret key and API key
SECRET_KEY = "your-secret-key-here"
API_KEY = "your-api-key-here"

# Intentionally vulnerable - weak token validation
def verify_token(token: str):
    try:
        # No proper token validation, just decode
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None

# Intentionally vulnerable - SQL injection in login
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return jsonify({"token": jwt.encode({"user_id": user[0]}, SECRET_KEY, algorithm="HS256")})
    return jsonify({"error": "Invalid credentials"}), 401

# Intentionally vulnerable - SQL injection in transfer
@app.route("/api/transfer", methods=["POST"])
def transfer():
    data = request.get_json()
    from_account = data.get("from_account")
    to_account = data.get("to_account")
    amount = data.get("amount")
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"UPDATE accounts SET balance = balance - {amount} WHERE account_number='{from_account}'"
    cursor.execute(query)
    query = f"UPDATE accounts SET balance = balance + {amount} WHERE account_number='{to_account}'"
    cursor.execute(query)
    conn.commit()
    return jsonify({"status": "success"})

# Intentionally vulnerable - SQL injection in search
@app.route("/api/search", methods=["GET"])
def search():
    query = request.args.get("query")
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    cursor.execute(f"SELECT * FROM transactions WHERE description LIKE '%{query}%'")
    return jsonify(cursor.fetchall())

# Intentionally vulnerable - path traversal
@app.route("/api/documents/<filename>", methods=["GET"])
def get_document(filename):
    # Vulnerable to path traversal
    with open(f"documents/{filename}", "r") as f:
        return jsonify({"content": f.read()})

# Intentionally vulnerable - command injection
@app.route("/api/execute", methods=["POST"])
def execute_command():
    data = request.get_json()
    command = data.get("command")
    # Vulnerable to command injection
    result = subprocess.check_output(command, shell=True)
    return jsonify({"result": result.decode()})

# Intentionally vulnerable - weak encryption
@app.route("/api/encrypt", methods=["POST"])
def encrypt_data():
    data = request.get_json().get("data")
    # Using weak base64 encoding instead of proper encryption
    return jsonify({"encrypted": base64.b64encode(data.encode()).decode()})

# Intentionally vulnerable - unsafe deserialization
@app.route("/api/deserialize", methods=["POST"])
def deserialize_data():
    data = request.get_json().get("data")
    # Vulnerable to pickle deserialization attacks
    return jsonify(pickle.loads(base64.b64decode(data)))

# Intentionally vulnerable - CORS misconfiguration
CORS(app, origins="*", supports_credentials=True)

# Intentionally vulnerable - no rate limiting
@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data.get("email")
    # No rate limiting, vulnerable to brute force
    return jsonify({"status": "reset email sent"})

# Intentionally vulnerable - no input validation
@app.route("/api/update-profile", methods=["POST"])
def update_profile():
    data = request.get_json()
    # No validation of input data
    return jsonify({"status": "profile updated"})

# Intentionally vulnerable - no proper error handling
@app.route("/api/account/<account_id>", methods=["GET"])
def get_account(account_id):
    try:
        conn = sqlite3.connect('bank.db')
        cursor = conn.cursor()
        # Vulnerable to SQL injection
        cursor.execute(f"SELECT * FROM accounts WHERE id='{account_id}'")
        account = cursor.fetchone()
        if not account:
            return jsonify({"error": "Account not found"}), 404
        return jsonify(account)
    except Exception as e:
        # Exposing error details
        return jsonify({"error": str(e)}), 500

# Intentionally vulnerable - no proper session management
@app.route("/api/logout", methods=["POST"])
def logout():
    # No proper session invalidation
    return jsonify({"status": "logged out"})

# Intentionally vulnerable - no proper API key validation
@app.route("/api/sensitive-data", methods=["GET"])
def get_sensitive_data():
    api_key = request.args.get("api_key")
    if api_key == API_KEY:  # Weak API key validation
        return jsonify({"data": "sensitive information"})
    return jsonify({"error": "Invalid API key"}), 401

# Intentionally vulnerable - no proper file upload validation
@app.route("/api/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    # No validation of file type or size
    with open("uploads/file", "wb") as f:
        f.write(file.read())
    return jsonify({"status": "file uploaded"})

# Intentionally vulnerable - no proper logging
@app.route("/api/transaction", methods=["POST"])
def create_transaction():
    data = request.get_json()
    # No proper logging of sensitive operations
    return jsonify({"status": "transaction created"})

# Intentionally vulnerable - no proper authentication
@app.route("/api/balance", methods=["GET"])
def get_balance():
    account_id = request.args.get("account_id")
    # No authentication check
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    cursor.execute(f"SELECT balance FROM accounts WHERE id='{account_id}'")
    return jsonify(cursor.fetchone())

# Intentionally vulnerable - no proper authorization
@app.route("/api/account/<account_id>", methods=["DELETE"])
def delete_account(account_id):
    # No authorization check
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    cursor.execute(f"DELETE FROM accounts WHERE id='{account_id}'")
    conn.commit()
    return jsonify({"status": "account deleted"})

# Intentionally vulnerable - no proper data sanitization
@app.route("/api/comment", methods=["POST"])
def add_comment():
    data = request.get_json()
    comment = data.get("comment")
    # No sanitization of user input
    return jsonify({"comment": comment})

# Intentionally vulnerable - no proper validation of file paths
@app.route("/api/download/<filename>", methods=["GET"])
def download_file(filename):
    # No validation of file path
    with open(filename, "rb") as f:
        return jsonify({"content": f.read()})

# Intentionally vulnerable - no proper validation of URLs
@app.route("/api/fetch", methods=["GET"])
def fetch_url():
    url = request.args.get("url")
    # No validation of URL
    http = urllib3.PoolManager()
    encoded_url = _encode_invalid_chars(url, allowed_chars='*')
    return jsonify({"data": http.request('GET', encoded_url).data.decode()})

# Intentionally vulnerable - no proper validation of JSON
@app.route("/api/parse-json", methods=["POST"])
def parse_json():
    data = request.get_json().get("data")
    # No validation of JSON structure
    import json
    return jsonify(json.loads(data))

# NEW: Intentionally vulnerable - Command Injection via traceroute
@app.route("/api/traceroute", methods=["POST"])
def traceroute():
    # Intentionally vulnerable - command injection via traceroute
    data = request.get_json()
    host = data.get("host", "google.com")
    # Vulnerable to command injection: traceroute {host}
    result = subprocess.check_output(f"traceroute {host}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - Command Injection via dig
@app.route("/api/dig", methods=["POST"])
def dig_dns():
    # Intentionally vulnerable - command injection via dig
    data = request.get_json()
    domain = data.get("domain", "google.com")
    # Vulnerable to command injection: dig {domain}
    result = subprocess.check_output(f"dig {domain}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - Command Injection via netstat
@app.route("/api/netstat", methods=["POST"])
def netstat_info():
    # Intentionally vulnerable - command injection via netstat
    data = request.get_json()
    options = data.get("options", "")
    # Vulnerable to command injection: netstat {options}
    result = subprocess.check_output(f"netstat {options}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - SSRF via ftp
@app.route("/api/ftp", methods=["POST"])
def ftp_connect():
    # Intentionally vulnerable - SSRF via ftp
    data = request.get_json()
    host = data.get("host", "ftp.gnu.org")
    # Vulnerable to SSRF and command injection
    result = subprocess.check_output(f"ftp -n {host}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - SSRF via telnet
@app.route("/api/telnet", methods=["POST"])
def telnet_connect():
    # Intentionally vulnerable - SSRF via telnet
    data = request.get_json()
    host = data.get("host", "localhost")
    port = data.get("port", "80")
    # Vulnerable to SSRF and command injection
    result = subprocess.check_output(f"telnet {host} {port}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - SSRF via nc (netcat)
@app.route("/api/netcat", methods=["POST"])
def netcat_connect():
    # Intentionally vulnerable - SSRF via netcat
    data = request.get_json()
    host = data.get("host", "localhost")
    port = data.get("port", "80")
    # Vulnerable to SSRF and command injection
    result = subprocess.check_output(f"nc {host} {port}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - JWT token with no signature verification
@app.route("/api/login-no-verify", methods=["POST"])
def login_no_verify():
    # Intentionally vulnerable - JWT with no signature verification
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - no signature verification
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        None,  # No secret
        algorithm="none"
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - JWT token with predictable secret
@app.route("/api/login-predictable", methods=["POST"])
def login_predictable():
    # Intentionally vulnerable - JWT with predictable secret
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - using predictable secret
    predictable_secret = username + "secret"
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        predictable_secret,
        algorithm="HS256"
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - JWT token with algorithm confusion
@app.route("/api/login-algorithm-confusion", methods=["POST"])
def login_algorithm_confusion():
    # Intentionally vulnerable - JWT with algorithm confusion
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - using RS256 but with HMAC secret
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm="RS256"  # Wrong algorithm for HMAC secret
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - JWT token with kid header injection
@app.route("/api/login-kid-injection", methods=["POST"])
def login_kid_injection():
    # Intentionally vulnerable - JWT with kid header injection
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - kid header can be manipulated
    headers = {"kid": "../../../dev/null"}
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm="HS256",
        headers=headers
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - JWT token with jku header injection
@app.route("/api/login-jku-injection", methods=["POST"])
def login_jku_injection():
    # Intentionally vulnerable - JWT with jku header injection
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Vulnerable - jku header can point to attacker-controlled server
    headers = {"jku": "https://attacker.com/jwks.json"}
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm="HS256",
        headers=headers
    )
    return jsonify({"access_token": token})

# NEW: Intentionally vulnerable - Command injection via find
@app.route("/api/find", methods=["POST"])
def find_files():
    # Intentionally vulnerable - command injection via find
    data = request.get_json()
    path = data.get("path", ".")
    name = data.get("name", "*")
    # Vulnerable to command injection: find {path} -name {name}
    result = subprocess.check_output(f"find {path} -name {name}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - Command injection via grep
@app.route("/api/grep", methods=["POST"])
def grep_files():
    # Intentionally vulnerable - command injection via grep
    data = request.get_json()
    pattern = data.get("pattern", "test")
    file = data.get("file", "/etc/passwd")
    # Vulnerable to command injection: grep {pattern} {file}
    result = subprocess.check_output(f"grep {pattern} {file}", shell=True)
    return jsonify({"result": result.decode()})

# NEW: Intentionally vulnerable - SSRF via lynx
@app.route("/api/lynx", methods=["POST"])
def lynx_browse():
    # Intentionally vulnerable - SSRF via lynx
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    # Vulnerable to SSRF and command injection
    result = subprocess.check_output(f"lynx -dump {url}", shell=True)
    return jsonify({"result": result.decode()})

# Intentionally vulnerable - no proper validation of XML
@app.route("/api/parse-xml", methods=["POST"])
def parse_xml():
    data = request.get_json().get("data")
    # No validation of XML structure
    import xml.etree.ElementTree as ET
    return jsonify(ET.fromstring(data))

# Intentionally vulnerable - no proper validation of YAML
@app.route("/api/parse-yaml", methods=["POST"])
def parse_yaml():
    data = request.get_json().get("data")
    # No validation of YAML structure
    import yaml
    return jsonify(yaml.safe_load(data))

# Intentionally vulnerable - no proper validation of CSV
@app.route("/api/parse-csv", methods=["POST"])
def parse_csv():
    data = request.get_json().get("data")
    # No validation of CSV structure
    import csv
    from io import StringIO
    f = StringIO(data)
    reader = csv.reader(f)
    return jsonify(list(reader))

# Intentionally vulnerable - no proper validation of HTML
@app.route("/api/parse-html", methods=["POST"])
def parse_html():
    data = request.get_json().get("data")
    # No validation of HTML structure
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(data, 'html.parser')
    return jsonify(str(soup))

# Intentionally vulnerable - no proper validation of PDF
@app.route("/api/parse-pdf", methods=["POST"])
def parse_pdf():
    file = request.files.get("file")
    # No validation of PDF structure
    import PyPDF2
    reader = PyPDF2.PdfReader(file)
    return jsonify({"pages": len(reader.pages)})

# Intentionally vulnerable - no proper validation of Excel
@app.route("/api/parse-excel", methods=["POST"])
def parse_excel():
    file = request.files.get("file")
    # No validation of Excel structure
    import pandas as pd
    df = pd.read_excel(file)
    return jsonify(df.to_dict())

# Intentionally vulnerable - no proper validation of Word
@app.route("/api/parse-word", methods=["POST"])
def parse_word():
    file = request.files.get("file")
    # No validation of Word structure
    import docx
    doc = docx.Document(file)
    return jsonify({"paragraphs": len(doc.paragraphs)})

# Intentionally vulnerable - no proper validation of ZIP
@app.route("/api/parse-zip", methods=["POST"])
def parse_zip():
    file = request.files.get("file")
    # No validation of ZIP structure
    import zipfile
    with zipfile.ZipFile(file, 'r') as zip_ref:
        return jsonify({"files": zip_ref.namelist()})

# Intentionally vulnerable - no proper validation of TAR
@app.route("/api/parse-tar", methods=["POST"])
def parse_tar():
    file = request.files.get("file")
    # No validation of TAR structure
    import tarfile
    with tarfile.open(fileobj=file, mode='r:*') as tar_ref:
        return jsonify({"files": tar_ref.getnames()})

# Intentionally vulnerable - no proper validation of GZIP
@app.route("/api/parse-gzip", methods=["POST"])
def parse_gzip():
    file = request.files.get("file")
    # No validation of GZIP structure
    import gzip
    return jsonify({"content": gzip.decompress(file.read()).decode()})

# Intentionally vulnerable - no proper validation of BZIP2
@app.route("/api/parse-bzip2", methods=["POST"])
def parse_bzip2():
    file = request.files.get("file")
    # No validation of BZIP2 structure
    import bz2
    return jsonify({"content": bz2.decompress(file.read()).decode()})

# Intentionally vulnerable - no proper validation of LZMA
@app.route("/api/parse-lzma", methods=["POST"])
def parse_lzma():
    file = request.files.get("file")
    # No validation of LZMA structure
    import lzma
    return jsonify({"content": lzma.decompress(file.read()).decode()})

# Intentionally vulnerable - no proper validation of ZLIB
@app.route("/api/parse-zlib", methods=["POST"])
def parse_zlib():
    file = request.files.get("file")
    # No validation of ZLIB structure
    import zlib
    return jsonify({"content": zlib.decompress(file.read()).decode()})

# Intentionally vulnerable - no proper validation of BASE64
@app.route("/api/parse-base64", methods=["POST"])
def parse_base64():
    data = request.get_json().get("data")
    # No validation of BASE64 structure
    return jsonify({"content": base64.b64decode(data).decode()})

# Intentionally vulnerable - no proper validation of HEX
@app.route("/api/parse-hex", methods=["POST"])
def parse_hex():
    data = request.get_json().get("data")
    # No validation of HEX structure
    return jsonify({"content": bytes.fromhex(data).decode()})

# Intentionally vulnerable - no proper validation of BINARY
@app.route("/api/parse-binary", methods=["POST"])
def parse_binary():
    data = request.get_json().get("data")
    # No validation of BINARY structure
    return jsonify({"content": int(data, 2)})

# Intentionally vulnerable - no proper validation of OCTAL
@app.route("/api/parse-octal", methods=["POST"])
def parse_octal():
    data = request.get_json().get("data")
    # No validation of OCTAL structure
    return jsonify({"content": int(data, 8)})

# Intentionally vulnerable - no proper validation of DECIMAL
@app.route("/api/parse-decimal", methods=["POST"])
def parse_decimal():
    data = request.get_json().get("data")
    # No validation of DECIMAL structure
    return jsonify({"content": int(data, 10)})

# Intentionally vulnerable - no proper validation of HEXADECIMAL
@app.route("/api/parse-hexadecimal", methods=["POST"])
def parse_hexadecimal():
    data = request.get_json().get("data")
    # No validation of HEXADECIMAL structure
    return jsonify({"content": int(data, 16)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 