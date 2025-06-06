from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import jwt
import os
import pickle
import base64
import subprocess
from typing import Optional, List
import urllib3
from urllib3.util.url import _encode_invalid_chars

app = FastAPI()

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
@app.post("/api/login")
def login(username: str, password: str):
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return {"token": jwt.encode({"user_id": user[0]}, SECRET_KEY, algorithm="HS256")}
    raise HTTPException(status_code=401, detail="Invalid credentials")

# Intentionally vulnerable - SQL injection in transfer
@app.post("/api/transfer")
def transfer(from_account: str, to_account: str, amount: float):
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"UPDATE accounts SET balance = balance - {amount} WHERE account_number='{from_account}'"
    cursor.execute(query)
    query = f"UPDATE accounts SET balance = balance + {amount} WHERE account_number='{to_account}'"
    cursor.execute(query)
    conn.commit()
    return {"status": "success"}

# Intentionally vulnerable - SQL injection in search
@app.get("/api/search")
def search(query: str):
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    cursor.execute(f"SELECT * FROM transactions WHERE description LIKE '%{query}%'")
    return cursor.fetchall()

# Intentionally vulnerable - path traversal
@app.get("/api/documents/{filename}")
def get_document(filename: str):
    # Vulnerable to path traversal
    with open(f"documents/{filename}", "r") as f:
        return {"content": f.read()}

# Intentionally vulnerable - command injection
@app.post("/api/execute")
def execute_command(command: str):
    # Vulnerable to command injection
    result = subprocess.check_output(command, shell=True)
    return {"result": result.decode()}

# Intentionally vulnerable - weak encryption
@app.post("/api/encrypt")
def encrypt_data(data: str):
    # Using weak base64 encoding instead of proper encryption
    return {"encrypted": base64.b64encode(data.encode()).decode()}

# Intentionally vulnerable - unsafe deserialization
@app.post("/api/deserialize")
def deserialize_data(data: str):
    # Vulnerable to pickle deserialization attacks
    return pickle.loads(base64.b64decode(data))

# Intentionally vulnerable - CORS misconfiguration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Intentionally vulnerable - no rate limiting
@app.post("/api/reset-password")
def reset_password(email: str):
    # No rate limiting, vulnerable to brute force
    return {"status": "reset email sent"}

# Intentionally vulnerable - no input validation
@app.post("/api/update-profile")
def update_profile(data: dict):
    # No validation of input data
    return {"status": "profile updated"}

# Intentionally vulnerable - no proper error handling
@app.get("/api/account/{account_id}")
def get_account(account_id: str):
    try:
        conn = sqlite3.connect('bank.db')
        cursor = conn.cursor()
        # Vulnerable to SQL injection
        cursor.execute(f"SELECT * FROM accounts WHERE id='{account_id}'")
        account = cursor.fetchone()
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")
        return account
    except Exception as e:
        # Exposing error details
        raise HTTPException(status_code=500, detail=str(e))

# Intentionally vulnerable - no proper session management
@app.post("/api/logout")
def logout():
    # No proper session invalidation
    return {"status": "logged out"}

# Intentionally vulnerable - no proper API key validation
@app.get("/api/sensitive-data")
def get_sensitive_data(api_key: str):
    if api_key == API_KEY:  # Weak API key validation
        return {"data": "sensitive information"}

# Intentionally vulnerable - no proper file upload validation
@app.post("/api/upload")
def upload_file(file: bytes):
    # No validation of file type or size
    with open("uploads/file", "wb") as f:
        f.write(file)
    return {"status": "file uploaded"}

# Intentionally vulnerable - no proper logging
@app.post("/api/transaction")
def create_transaction(data: dict):
    # No proper logging of sensitive operations
    return {"status": "transaction created"}

# Intentionally vulnerable - no proper authentication
@app.get("/api/balance")
def get_balance(account_id: str):
    # No authentication check
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    cursor.execute(f"SELECT balance FROM accounts WHERE id='{account_id}'")
    return cursor.fetchone()

# Intentionally vulnerable - no proper authorization
@app.delete("/api/account/{account_id}")
def delete_account(account_id: str):
    # No authorization check
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    cursor.execute(f"DELETE FROM accounts WHERE id='{account_id}'")
    conn.commit()
    return {"status": "account deleted"}

# Intentionally vulnerable - no proper data sanitization
@app.post("/api/comment")
def add_comment(comment: str):
    # No sanitization of user input
    return {"comment": comment}

# Intentionally vulnerable - no proper validation of file paths
@app.get("/api/download/{filename}")
def download_file(filename: str):
    # No validation of file path
    with open(filename, "rb") as f:
        return {"content": f.read()}

# Intentionally vulnerable - no proper validation of URLs
@app.get("/api/fetch")
def fetch_url(url: str):
    # No validation of URL
    http = urllib3.PoolManager()
    encoded_url = _encode_invalid_chars(url, allowed_chars='*')
    return http.request('GET', encoded_url).data

# Intentionally vulnerable - no proper validation of JSON
@app.post("/api/parse-json")
def parse_json(data: str):
    # No validation of JSON structure
    import json
    return json.loads(data)

# Intentionally vulnerable - no proper validation of XML
@app.post("/api/parse-xml")
def parse_xml(data: str):
    # No validation of XML structure
    import xml.etree.ElementTree as ET
    return ET.fromstring(data)

# Intentionally vulnerable - no proper validation of YAML
@app.post("/api/parse-yaml")
def parse_yaml(data: str):
    # No validation of YAML structure
    import yaml
    return yaml.safe_load(data)

# Intentionally vulnerable - no proper validation of CSV
@app.post("/api/parse-csv")
def parse_csv(data: str):
    # No validation of CSV structure
    import csv
    return list(csv.reader(data.splitlines()))

# Intentionally vulnerable - no proper validation of HTML
@app.post("/api/parse-html")
def parse_html(data: str):
    # No validation of HTML structure
    from bs4 import BeautifulSoup
    return BeautifulSoup(data, 'html.parser')

# Intentionally vulnerable - no proper validation of PDF
@app.post("/api/parse-pdf")
def parse_pdf(data: bytes):
    # No validation of PDF structure
    import PyPDF2
    return PyPDF2.PdfFileReader(data)

# Intentionally vulnerable - no proper validation of Excel
@app.post("/api/parse-excel")
def parse_excel(data: bytes):
    # No validation of Excel structure
    import pandas as pd
    return pd.read_excel(data)

# Intentionally vulnerable - no proper validation of Word
@app.post("/api/parse-word")
def parse_word(data: bytes):
    # No validation of Word structure
    import docx
    return docx.Document(data)

# Intentionally vulnerable - no proper validation of ZIP
@app.post("/api/parse-zip")
def parse_zip(data: bytes):
    # No validation of ZIP structure
    import zipfile
    return zipfile.ZipFile(data)

# Intentionally vulnerable - no proper validation of TAR
@app.post("/api/parse-tar")
def parse_tar(data: bytes):
    # No validation of TAR structure
    import tarfile
    return tarfile.open(fileobj=data)

# Intentionally vulnerable - no proper validation of GZIP
@app.post("/api/parse-gzip")
def parse_gzip(data: bytes):
    # No validation of GZIP structure
    import gzip
    return gzip.decompress(data)

# Intentionally vulnerable - no proper validation of BZIP2
@app.post("/api/parse-bzip2")
def parse_bzip2(data: bytes):
    # No validation of BZIP2 structure
    import bz2
    return bz2.decompress(data)

# Intentionally vulnerable - no proper validation of LZMA
@app.post("/api/parse-lzma")
def parse_lzma(data: bytes):
    # No validation of LZMA structure
    import lzma
    return lzma.decompress(data)

# Intentionally vulnerable - no proper validation of ZLIB
@app.post("/api/parse-zlib")
def parse_zlib(data: bytes):
    # No validation of ZLIB structure
    import zlib
    return zlib.decompress(data)

# Intentionally vulnerable - no proper validation of BASE64
@app.post("/api/parse-base64")
def parse_base64(data: str):
    # No validation of BASE64 structure
    return base64.b64decode(data)

# Intentionally vulnerable - no proper validation of HEX
@app.post("/api/parse-hex")
def parse_hex(data: str):
    # No validation of HEX structure
    return bytes.fromhex(data)

# Intentionally vulnerable - no proper validation of BINARY
@app.post("/api/parse-binary")
def parse_binary(data: str):
    # No validation of BINARY structure
    return int(data, 2)

# Intentionally vulnerable - no proper validation of OCTAL
@app.post("/api/parse-octal")
def parse_octal(data: str):
    # No validation of OCTAL structure
    return int(data, 8)

# Intentionally vulnerable - no proper validation of DECIMAL
@app.post("/api/parse-decimal")
def parse_decimal(data: str):
    # No validation of DECIMAL structure
    return int(data, 10)

# Intentionally vulnerable - no proper validation of HEXADECIMAL
@app.post("/api/parse-hexadecimal")
def parse_hexadecimal(data: str):
    # No validation of HEXADECIMAL structure
    return int(data, 16)

# Intentionally vulnerable - no proper validation of BINARY
@app.post("/api/parse-binary")
def parse_binary(data: str):
    # No validation of BINARY structure
    return int(data, 2)

# Intentionally vulnerable - no proper validation of OCTAL
@app.post("/api/parse-octal")
def parse_octal(data: str):
    # No validation of OCTAL structure
    return int(data, 8)

# Intentionally vulnerable - no proper validation of DECIMAL
@app.post("/api/parse-decimal")
def parse_decimal(data: str):
    # No validation of DECIMAL structure
    return int(data, 10)

# Intentionally vulnerable - no proper validation of HEXADECIMAL
@app.post("/api/parse-hexadecimal")
def parse_hexadecimal(data: str):
    # No validation of HEXADECIMAL structure
    return int(data, 16)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 