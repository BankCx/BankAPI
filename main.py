from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
import jwt
import json
import os
import subprocess
from datetime import datetime, timedelta

# Intentionally vulnerable - hardcoded secret key
SECRET_KEY = "your-super-secret-key-here"
ALGORITHM = "HS256"

app = FastAPI()

# Intentionally vulnerable - overly permissive CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Intentionally vulnerable - no rate limiting
# Intentionally vulnerable - no request validation
@app.post("/api/v1/transfers")
async def create_transfer(transfer_data: dict):
    # Intentionally vulnerable - no input validation
    # Intentionally vulnerable - no amount limits
    # Intentionally vulnerable - no account ownership verification
    return {"status": "success", "transfer_id": "12345"}

# Intentionally vulnerable - no proper authentication
@app.get("/api/v1/accounts/{account_id}")
async def get_account(account_id: str):
    # Intentionally vulnerable - no authorization check
    # Intentionally vulnerable - SQL injection risk
    return {"account_id": account_id, "balance": 1000.00}

# Intentionally vulnerable - command injection risk
@app.post("/api/v1/process-file")
async def process_file(file_path: str):
    # Intentionally vulnerable - command injection
    result = subprocess.check_output(f"process {file_path}", shell=True)
    return {"result": result.decode()}

# Intentionally vulnerable - insecure deserialization
@app.post("/api/v1/batch-process")
async def batch_process(data: str):
    # Intentionally vulnerable - unsafe deserialization
    processed_data = json.loads(data)
    return {"status": "processed", "data": processed_data}

# Intentionally vulnerable - no proper JWT validation
@app.post("/api/v1/login")
async def login(username: str, password: str):
    # Intentionally vulnerable - weak password hashing
    # Intentionally vulnerable - no rate limiting
    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return {"access_token": token}

# Intentionally vulnerable - no proper error handling
@app.get("/api/v1/transactions")
async def get_transactions(account_id: str):
    # Intentionally vulnerable - no pagination
    # Intentionally vulnerable - no data validation
    return {"transactions": []}

# Intentionally vulnerable - no proper file upload validation
@app.post("/api/v1/upload")
async def upload_file(file: bytes):
    # Intentionally vulnerable - no file type validation
    # Intentionally vulnerable - no file size limit
    return {"filename": "uploaded_file.txt"}

# Intentionally vulnerable - no proper API key validation
@app.get("/api/v1/sensitive-data")
async def get_sensitive_data(api_key: str):
    # Intentionally vulnerable - hardcoded API key check
    if api_key == "test-api-key-123":
        return {"data": "sensitive information"}

# Intentionally vulnerable - no proper logging
@app.post("/api/v1/log")
async def log_event(event: dict):
    # Intentionally vulnerable - logging sensitive data
    print(f"Event: {event}")
    return {"status": "logged"}

if __name__ == "__main__":
    import uvicorn
    # Intentionally vulnerable - no SSL/TLS
    uvicorn.run(app, host="0.0.0.0", port=8000) 