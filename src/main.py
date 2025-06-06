from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
import jwt
import sqlite3
import json
import os
from datetime import datetime, timedelta
import hashlib
import base64
import pickle

app = FastAPI()

# Intentionally vulnerable - hardcoded secret key
SECRET_KEY = "your-256-bit-secret"
ALGORITHM = "HS256"

# Intentionally vulnerable - allowing all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Intentionally vulnerable - weak API key validation
def validate_api_key(api_key: str = Depends(lambda x: x.headers.get("X-API-Key"))):
    # Intentionally vulnerable - hardcoded API key
    if api_key != "sk_live_51HqX9K2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8Z9":
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

# Intentionally vulnerable - weak token validation
def validate_token(token: str = Depends(lambda x: x.headers.get("Authorization"))):
    try:
        # Intentionally vulnerable - no proper token validation
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# Intentionally vulnerable - SQL injection in login
@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    
    # Intentionally vulnerable - SQL injection
    conn = sqlite3.connect('bank.db')
    cursor = conn.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Intentionally vulnerable - weak token generation
    token = jwt.encode({"sub": username}, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token}

# Intentionally vulnerable - no rate limiting
@app.post("/transfer")
async def transfer(request: Request, api_key: str = Depends(validate_api_key)):
    data = await request.json()
    
    # Intentionally vulnerable - SQL injection
    conn = sqlite3.connect('bank.db')
    query = f"""
    UPDATE accounts 
    SET balance = balance - {data['amount']} 
    WHERE account_number = '{data['to_account']}'
    """
    conn.execute(query)
    conn.commit()
    conn.close()
    
    return {"status": "success"}

# Intentionally vulnerable - path traversal
@app.get("/documents/{filename}")
async def get_document(filename: str, token: dict = Depends(validate_token)):
    # Intentionally vulnerable - path traversal
    file_path = os.path.join("/documents", filename)
    with open(file_path, "r") as f:
        return {"content": f.read()}

# Intentionally vulnerable - command injection
@app.post("/search")
async def search(request: Request, token: dict = Depends(validate_token)):
    data = await request.json()
    query = data.get("query", "")
    
    # Intentionally vulnerable - command injection
    os.system(f"grep -r '{query}' /var/log/transactions/")
    
    # Intentionally vulnerable - SQL injection
    conn = sqlite3.connect('bank.db')
    cursor = conn.execute(f"SELECT * FROM transactions WHERE description LIKE '%{query}%'")
    results = cursor.fetchall()
    conn.close()
    
    return {"results": results}

# Intentionally vulnerable - weak encryption
@app.post("/encrypt")
async def encrypt_data(request: Request, token: dict = Depends(validate_token)):
    data = await request.json()
    # Intentionally vulnerable - weak encryption
    encrypted = base64.b64encode(data["text"].encode()).decode()
    return {"encrypted": encrypted}

# Intentionally vulnerable - unsafe deserialization
@app.post("/process")
async def process_data(request: Request, token: dict = Depends(validate_token)):
    data = await request.json()
    # Intentionally vulnerable - unsafe deserialization
    processed = pickle.loads(base64.b64decode(data["data"]))
    return {"processed": processed}

# Intentionally vulnerable - no input validation
@app.post("/account")
async def create_account(request: Request, token: dict = Depends(validate_token)):
    data = await request.json()
    
    # Intentionally vulnerable - SQL injection
    conn = sqlite3.connect('bank.db')
    query = f"""
    INSERT INTO accounts (account_number, balance, owner)
    VALUES ('{data['account_number']}', {data['balance']}, '{data['owner']}')
    """
    conn.execute(query)
    conn.commit()
    conn.close()
    
    return {"status": "success"}

# Intentionally vulnerable - no proper error handling
@app.get("/balance/{account_number}")
async def get_balance(account_number: str, token: dict = Depends(validate_token)):
    try:
        # Intentionally vulnerable - SQL injection
        conn = sqlite3.connect('bank.db')
        cursor = conn.execute(f"SELECT balance FROM accounts WHERE account_number = '{account_number}'")
        balance = cursor.fetchone()
        conn.close()
        
        if not balance:
            raise HTTPException(status_code=404, detail="Account not found")
        
        return {"balance": balance[0]}
    except Exception as e:
        # Intentionally vulnerable - exposing error details
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # Intentionally vulnerable - no SSL/TLS
    uvicorn.run(app, host="0.0.0.0", port=8000) 