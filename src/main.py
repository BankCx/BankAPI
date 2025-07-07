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

@app.route("/api/dig", methods=["POST"])
def dig_dns():
    data = request.get_json()
    domain = data.get("domain", "google.com")
    result = subprocess.check_output(f"dig {domain}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/netstat", methods=["POST"])
def netstat_info():
    data = request.get_json()
    options = data.get("options", "")
    result = subprocess.check_output(f"netstat {options}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/ftp", methods=["POST"])
def ftp_connect():
    data = request.get_json()
    host = data.get("host", "ftp.gnu.org")
    result = subprocess.check_output(f"ftp -n {host}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/telnet", methods=["POST"])
def telnet_connect():
    data = request.get_json()
    host = data.get("host", "localhost")
    port = data.get("port", "80")
    result = subprocess.check_output(f"telnet {host} {port}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/netcat", methods=["POST"])
def netcat_connect():
    data = request.get_json()
    host = data.get("host", "localhost")
    port = data.get("port", "80")
    result = subprocess.check_output(f"nc {host} {port}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/login-no-verify", methods=["POST"])
def login_no_verify():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        None,
        algorithm="none"
    )
    return jsonify({"access_token": token})

@app.route("/api/login-predictable", methods=["POST"])
def login_predictable():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    predictable_secret = username + "secret"
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        predictable_secret,
        algorithm="HS256"
    )
    return jsonify({"access_token": token})

@app.route("/api/login-algorithm-confusion", methods=["POST"])
def login_algorithm_confusion():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm="RS256"
    )
    return jsonify({"access_token": token})

@app.route("/api/login-kid-injection", methods=["POST"])
def login_kid_injection():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    headers = {"kid": "../../../dev/null"}
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm="HS256",
        headers=headers
    )
    return jsonify({"access_token": token})

@app.route("/api/login-jku-injection", methods=["POST"])
def login_jku_injection():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    headers = {"jku": "https://attacker.com/jwks.json"}
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm="HS256",
        headers=headers
    )
    return jsonify({"access_token": token})

@app.route("/api/find", methods=["POST"])
def find_files():
    data = request.get_json()
    path = data.get("path", ".")
    name = data.get("name", "*")
    result = subprocess.check_output(f"find {path} -name {name}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/grep", methods=["POST"])
def grep_files():
    data = request.get_json()
    pattern = data.get("pattern", "test")
    file = data.get("file", "/etc/passwd")
    result = subprocess.check_output(f"grep {pattern} {file}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/lynx", methods=["POST"])
def lynx_browse():
    data = request.get_json()
    url = data.get("url", "https://httpbin.org/get")
    result = subprocess.check_output(f"lynx -dump {url}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/parse-xml", methods=["POST"])
def parse_xml():
    data = request.get_json().get("data")
    import xml.etree.ElementTree as ET
    return jsonify(ET.fromstring(data))

@app.route("/api/parse-yaml", methods=["POST"])
def parse_yaml():
    data = request.get_json().get("data")
    import yaml
    return jsonify(yaml.safe_load(data))

@app.route("/api/parse-csv", methods=["POST"])
def parse_csv():
    data = request.get_json().get("data")
    import csv
    from io import StringIO
    f = StringIO(data)
    reader = csv.reader(f)
    return jsonify(list(reader))

@app.route("/api/parse-html", methods=["POST"])
def parse_html():
    data = request.get_json().get("data")
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(data, 'html.parser')
    return jsonify(str(soup))

@app.route("/api/parse-pdf", methods=["POST"])
def parse_pdf():
    file = request.files.get("file")
    import PyPDF2
    reader = PyPDF2.PdfReader(file)
    return jsonify({"pages": len(reader.pages)})

@app.route("/api/parse-excel", methods=["POST"])
def parse_excel():
    file = request.files.get("file")
    import pandas as pd
    df = pd.read_excel(file)
    return jsonify(df.to_dict())

@app.route("/api/parse-word", methods=["POST"])
def parse_word():
    file = request.files.get("file")
    import docx
    doc = docx.Document(file)
    return jsonify({"paragraphs": len(doc.paragraphs)})

@app.route("/api/parse-zip", methods=["POST"])
def parse_zip():
    file = request.files.get("file")
    import zipfile
    with zipfile.ZipFile(file, 'r') as zip_ref:
        return jsonify({"files": zip_ref.namelist()})

@app.route("/api/parse-tar", methods=["POST"])
def parse_tar():
    file = request.files.get("file")
    import tarfile
    with tarfile.open(fileobj=file, mode='r:*') as tar_ref:
        return jsonify({"files": tar_ref.getnames()})

@app.route("/api/parse-gzip", methods=["POST"])
def parse_gzip():
    file = request.files.get("file")
    import gzip
    return jsonify({"content": gzip.decompress(file.read()).decode()})

@app.route("/api/parse-bzip2", methods=["POST"])
def parse_bzip2():
    file = request.files.get("file")
    import bz2
    return jsonify({"content": bz2.decompress(file.read()).decode()})

@app.route("/api/parse-lzma", methods=["POST"])
def parse_lzma():
    file = request.files.get("file")
    import lzma
    return jsonify({"content": lzma.decompress(file.read()).decode()})

@app.route("/api/parse-zlib", methods=["POST"])
def parse_zlib():
    file = request.files.get("file")
    import zlib
    return jsonify({"content": zlib.decompress(file.read()).decode()})

@app.route("/api/parse-base64", methods=["POST"])
def parse_base64():
    data = request.get_json().get("data")
    return jsonify({"content": base64.b64decode(data).decode()})

@app.route("/api/parse-hex", methods=["POST"])
def parse_hex():
    data = request.get_json().get("data")
    return jsonify({"content": bytes.fromhex(data).decode()})

@app.route("/api/parse-binary", methods=["POST"])
def parse_binary():
    data = request.get_json().get("data")
    return jsonify({"content": int(data, 2)})

@app.route("/api/parse-octal", methods=["POST"])
def parse_octal():
    data = request.get_json().get("data")
    return jsonify({"content": int(data, 8)})

@app.route("/api/parse-decimal", methods=["POST"])
def parse_decimal():
    data = request.get_json().get("data")
    return jsonify({"content": int(data, 10)})

@app.route("/api/parse-hexadecimal", methods=["POST"])
def parse_hexadecimal():
    data = request.get_json().get("data")
    return jsonify({"content": int(data, 16)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 