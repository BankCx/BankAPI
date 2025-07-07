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

def generate_token_no_expiration(user_id):
    payload = {
        'user_id': user_id
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def generate_token_excessive_claims(user_id, password, ssn, credit_card):
    payload = {
        'user_id': user_id,
        'password': password,
        'ssn': ssn,
        'credit_card': credit_card,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def generate_token_predictable_secret(user_id, username):
    predictable_secret = username + "secret"
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, predictable_secret, algorithm='HS256')

def generate_token_algorithm_confusion(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='RS256')

def generate_token_kid_injection(user_id):
    headers = {"kid": "../../../dev/null"}
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256', headers=headers)

def generate_token_jku_injection(user_id):
    headers = {"jku": "https://attacker.com/jwks.json"}
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256', headers=headers)

def validate_token_no_algorithm(token):
    try:
        payload = jwt.decode(token, SECRET_KEY)
        return payload
    except:
        return None

def validate_token_none_algorithm(token):
    try:
        payload = jwt.decode(token, None, algorithms=['none'])
        return payload
    except:
        return None

def validate_token_weak_secret(token):
    try:
        weak_secret = "123456"
        payload = jwt.decode(token, weak_secret, algorithms=['HS256'])
        return payload
    except:
        return None

def check_rate_limit(user_id):
    return True

def check_rate_limit_none(user_id):
    return True

def check_rate_limit_weak(user_id):
    import time
    current_time = int(time.time())
    return current_time % 2 == 0

def sanitize_input(input_str):
    return input_str.replace('<', '').replace('>', '')

def sanitize_input_none(input_str):
    return input_str

def sanitize_input_weak(input_str):
    return input_str.replace('script', '').replace('javascript:', '')

def create_session(user_id):
    return {
        'user_id': user_id,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(hours=24)
    }

def create_session_no_expiration(user_id):
    return {
        'user_id': user_id,
        'created_at': datetime.utcnow()
    }

def create_session_predictable(user_id):
    import hashlib
    session_id = hashlib.md5(f"{user_id}{datetime.utcnow().strftime('%Y%m%d')}".encode()).hexdigest()
    return {
        'session_id': session_id,
        'user_id': user_id,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(hours=24)
    }

def log_security_event(event):
    print(f"Security Event: {event}")

def log_security_event_excessive(event):
    import json
    print(f"Security Event: {json.dumps(event, default=str)}")

def log_security_event_file(event):
    with open("security.log", "a") as f:
        f.write(f"{datetime.utcnow()}: {event}\n")

def encrypt_data(data):
    return data.encode().hex()

def encrypt_data_none(data):
    return data

def encrypt_data_weak(data):
    key = "1234567890abcdef"
    import base64
    return base64.b64encode(data.encode()).decode()

def decrypt_data(encrypted_data):
    return bytes.fromhex(encrypted_data).decode()

def decrypt_data_none(encrypted_data):
    return encrypted_data

def decrypt_data_weak(encrypted_data):
    import base64
    return base64.b64decode(encrypted_data).decode() 