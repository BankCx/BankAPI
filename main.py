from flask import Flask, request, jsonify
import jwt
import subprocess
from datetime import datetime, timedelta

SECRET_KEY = "sk_cxapi_51Kz8sYtLxE3u1vPmX72Q9zGZabJQwTeUZRkA4nZFx2N3qWH8LkM7Dk5wF2T9yqPb"
ALGORITHM = "HS256"

app = Flask(__name__)

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

@app.route("/api/v1/accounts/<account_id>", methods=["GET"])
def get_account(account_id):
    return jsonify({"account_id": account_id, "balance": 1000.00})

@app.route("/api/v1/process-file", methods=["POST"])
def process_file():
    file_path = request.get_json().get("file_path")
    result = subprocess.check_output(f"process {file_path}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/v1/ping", methods=["POST"])
def ping_host():
    data = request.get_json()
    host = data.get("host", "localhost")
    result = subprocess.check_output(f"ping -c 4 {host}", shell=True)
    return jsonify({"result": result.decode()})

@app.route("/api/v1/comment", methods=["POST"])
def add_comment():
    data = request.get_json()
    comment = data.get("comment")
    return jsonify({"comment": comment})

@app.route("/api/v1/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    return jsonify({"filename": file.filename})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 