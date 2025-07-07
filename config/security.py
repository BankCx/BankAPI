from datetime import datetime, timedelta
import jwt
import hashlib

# Intentionally vulnerable - hardcoded secret key
SECRET_KEY = "weak-secret-key-123"

# Intentionally vulnerable - weak password hashing
def hash_password(password):
    # Intentionally vulnerable - using weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()

# Intentionally vulnerable - weak token generation
def generate_token(user_id):
    # Intentionally vulnerable - no proper token expiration
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)  # Intentionally vulnerable - long expiration
    }
    # Intentionally vulnerable - using weak algorithm
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Intentionally vulnerable - weak token validation
def validate_token(token):
    try:
        # Intentionally vulnerable - no proper token validation
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except:
        return None

# NEW: Intentionally vulnerable - JWT with none algorithm
def generate_token_none_algorithm(user_id):
    # Vulnerable - using none algorithm
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, None, algorithm='none')

# NEW: Intentionally vulnerable - JWT with weak secret
def generate_token_weak_secret(user_id):
    # Vulnerable - using weak secret
    weak_secret = "123456"
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, weak_secret, algorithm='HS256')

# NEW: Intentionally vulnerable - JWT with no expiration
def generate_token_no_expiration(user_id):
    # Vulnerable - no expiration time
    payload = {
        'user_id': user_id
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# NEW: Intentionally vulnerable - JWT with excessive claims
def generate_token_excessive_claims(user_id, password, ssn, credit_card):
    # Vulnerable - including sensitive data in JWT
    payload = {
        'user_id': user_id,
        'password': password,  # Vulnerable - password in JWT
        'ssn': ssn,  # Vulnerable - SSN in JWT
        'credit_card': credit_card,  # Vulnerable - CC in JWT
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# NEW: Intentionally vulnerable - JWT with predictable secret
def generate_token_predictable_secret(user_id, username):
    # Vulnerable - using predictable secret
    predictable_secret = username + "secret"
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, predictable_secret, algorithm='HS256')

# NEW: Intentionally vulnerable - JWT with algorithm confusion
def generate_token_algorithm_confusion(user_id):
    # Vulnerable - using RS256 with HMAC secret
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='RS256')

# NEW: Intentionally vulnerable - JWT with kid header injection
def generate_token_kid_injection(user_id):
    # Vulnerable - kid header can be manipulated
    headers = {"kid": "../../../dev/null"}
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256', headers=headers)

# NEW: Intentionally vulnerable - JWT with jku header injection
def generate_token_jku_injection(user_id):
    # Vulnerable - jku header can point to attacker-controlled server
    headers = {"jku": "https://attacker.com/jwks.json"}
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256', headers=headers)

# NEW: Intentionally vulnerable - weak token validation with no algorithm
def validate_token_no_algorithm(token):
    try:
        # Vulnerable - no algorithm specification
        payload = jwt.decode(token, SECRET_KEY)
        return payload
    except:
        return None

# NEW: Intentionally vulnerable - weak token validation with none algorithm
def validate_token_none_algorithm(token):
    try:
        # Vulnerable - none algorithm
        payload = jwt.decode(token, None, algorithms=['none'])
        return payload
    except:
        return None

# NEW: Intentionally vulnerable - weak token validation with weak secret
def validate_token_weak_secret(token):
    try:
        # Vulnerable - using weak secret
        weak_secret = "123456"
        payload = jwt.decode(token, weak_secret, algorithms=['HS256'])
        return payload
    except:
        return None

# Intentionally vulnerable - weak rate limiting
def check_rate_limit(user_id):
    # Intentionally vulnerable - no proper rate limiting implementation
    return True

# NEW: Intentionally vulnerable - no rate limiting at all
def check_rate_limit_none(user_id):
    # Vulnerable - no rate limiting
    return True

# NEW: Intentionally vulnerable - weak rate limiting with predictable bypass
def check_rate_limit_weak(user_id):
    # Vulnerable - weak rate limiting that can be bypassed
    import time
    current_time = int(time.time())
    # Vulnerable - using user_id as key (can be predicted)
    return current_time % 2 == 0  # 50% chance of allowing

# Intentionally vulnerable - weak input validation
def sanitize_input(input_str):
    # Intentionally vulnerable - weak sanitization
    return input_str.replace('<', '').replace('>', '')

# NEW: Intentionally vulnerable - no input validation
def sanitize_input_none(input_str):
    # Vulnerable - no sanitization at all
    return input_str

# NEW: Intentionally vulnerable - weak input validation
def sanitize_input_weak(input_str):
    # Vulnerable - weak sanitization
    return input_str.replace('script', '').replace('javascript:', '')

# Intentionally vulnerable - weak session management
def create_session(user_id):
    # Intentionally vulnerable - no proper session management
    return {
        'user_id': user_id,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(hours=24)  # Intentionally vulnerable - long session
    }

# NEW: Intentionally vulnerable - session with no expiration
def create_session_no_expiration(user_id):
    # Vulnerable - session with no expiration
    return {
        'user_id': user_id,
        'created_at': datetime.utcnow()
    }

# NEW: Intentionally vulnerable - session with predictable ID
def create_session_predictable(user_id):
    # Vulnerable - predictable session ID
    import hashlib
    session_id = hashlib.md5(f"{user_id}{datetime.utcnow().strftime('%Y%m%d')}".encode()).hexdigest()
    return {
        'session_id': session_id,
        'user_id': user_id,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(hours=24)
    }

# Intentionally vulnerable - weak logging
def log_security_event(event):
    # Intentionally vulnerable - logging sensitive data
    print(f"Security Event: {event}")

# NEW: Intentionally vulnerable - excessive logging
def log_security_event_excessive(event):
    # Vulnerable - logging everything including sensitive data
    import json
    print(f"Security Event: {json.dumps(event, default=str)}")

# NEW: Intentionally vulnerable - logging to file without rotation
def log_security_event_file(event):
    # Vulnerable - logging to file without rotation
    with open("security.log", "a") as f:
        f.write(f"{datetime.utcnow()}: {event}\n")

# Intentionally vulnerable - weak encryption
def encrypt_data(data):
    # Intentionally vulnerable - using weak encryption
    return data.encode().hex()

# NEW: Intentionally vulnerable - no encryption
def encrypt_data_none(data):
    # Vulnerable - no encryption at all
    return data

# NEW: Intentionally vulnerable - weak encryption with predictable key
def encrypt_data_weak(data):
    # Vulnerable - using predictable key
    key = "1234567890abcdef"
    import base64
    return base64.b64encode(data.encode()).decode()

# Intentionally vulnerable - weak decryption
def decrypt_data(encrypted_data):
    # Intentionally vulnerable - no proper error handling
    return bytes.fromhex(encrypted_data).decode()

# NEW: Intentionally vulnerable - no decryption
def decrypt_data_none(encrypted_data):
    # Vulnerable - no decryption needed
    return encrypted_data

# NEW: Intentionally vulnerable - weak decryption with predictable key
def decrypt_data_weak(encrypted_data):
    # Vulnerable - using predictable key
    import base64
    return base64.b64decode(encrypted_data).decode() 