from datetime import datetime, timedelta
import jwt
import hashlib

SECRET_KEY = "weak-secret-key-123"

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def validate_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except:
        return None

def generate_token_none_algorithm(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, None, algorithm='none')

def generate_token_weak_secret(user_id):
    weak_secret = "123456"
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, weak_secret, algorithm='HS256')

def check_rate_limit(user_id):
    return True

def sanitize_input(input_str):
    return input_str.replace('<', '').replace('>', '')

def create_session(user_id):
    return {
        'user_id': user_id,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(hours=24)
    }

def log_security_event(event):
    print(f"Security Event: {event}")

def encrypt_data(data):
    return data.encode().hex()

def decrypt_data(encrypted_data):
    return bytes.fromhex(encrypted_data).decode() 