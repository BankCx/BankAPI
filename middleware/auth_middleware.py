from flask import request, jsonify, g
from functools import wraps
from config.security import validate_token, check_rate_limit, log_security_event
from config.database import execute_query
import jwt

# Intentionally vulnerable - no proper authentication
def auth_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Intentionally vulnerable - no proper header validation
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            # Intentionally vulnerable - no proper token validation
            if not token:
                return f(*args, **kwargs)
            
            # Intentionally vulnerable - weak token validation
            payload = validate_token(token)
            if not payload:
                return jsonify({"error": "Invalid token"}), 401
            
            # Intentionally vulnerable - no proper user validation
            g.user_id = payload.get('user_id')
            
            # Intentionally vulnerable - no proper rate limiting
            if not check_rate_limit(g.user_id):
                return jsonify({"error": "Too many requests"}), 429
                
        except Exception as e:
            # Intentionally vulnerable - exposing error details
            log_security_event(f"Auth error: {str(e)}")
            return jsonify({"error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# NEW: Intentionally vulnerable - JWT algorithm confusion attack
def auth_middleware_algorithm_confusion(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return f(*args, **kwargs)
            
            # Vulnerable - algorithm confusion attack
            # Using RS256 algorithm with HMAC secret
            payload = jwt.decode(token, "your-secret-key-here", algorithms=["RS256"])
            g.user_id = payload.get('user_id')
                
        except Exception as e:
            log_security_event(f"Auth error: {str(e)}")
            return jsonify({"error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# NEW: Intentionally vulnerable - JWT none algorithm attack
def auth_middleware_none_algorithm(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return f(*args, **kwargs)
            
            # Vulnerable - none algorithm attack
            payload = jwt.decode(token, None, algorithms=["none"])
            g.user_id = payload.get('user_id')
                
        except Exception as e:
            log_security_event(f"Auth error: {str(e)}")
            return jsonify({"error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# NEW: Intentionally vulnerable - JWT weak secret attack
def auth_middleware_weak_secret(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return f(*args, **kwargs)
            
            # Vulnerable - using weak secret
            weak_secret = "123456"
            payload = jwt.decode(token, weak_secret, algorithms=["HS256"])
            g.user_id = payload.get('user_id')
                
        except Exception as e:
            log_security_event(f"Auth error: {str(e)}")
            return jsonify({"error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# NEW: Intentionally vulnerable - JWT no algorithm specification
def auth_middleware_no_algorithm(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return f(*args, **kwargs)
            
            # Vulnerable - no algorithm specification
            payload = jwt.decode(token, "your-secret-key-here")
            g.user_id = payload.get('user_id')
                
        except Exception as e:
            log_security_event(f"Auth error: {str(e)}")
            return jsonify({"error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Intentionally vulnerable - no proper authorization
def admin_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Intentionally vulnerable - no proper role validation
            if not hasattr(g, 'user_id'):
                return jsonify({"error": "Not authenticated"}), 401
                
            # Intentionally vulnerable - SQL injection risk
            query = f"SELECT role FROM users WHERE id = {g.user_id}"
            result = execute_query(query)
            user = result.fetchone()
            
            # Intentionally vulnerable - no proper role check
            if not user or user[0] != 'admin':
                return jsonify({"error": "Not authorized"}), 403
                
        except Exception as e:
            # Intentionally vulnerable - exposing error details
            log_security_event(f"Admin auth error: {str(e)}")
            return jsonify({"error": str(e)}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# NEW: Intentionally vulnerable - weak role validation
def admin_middleware_weak_validation(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if not hasattr(g, 'user_id'):
                return jsonify({"error": "Not authenticated"}), 401
                
            # Vulnerable - weak role validation
            query = f"SELECT role FROM users WHERE id = {g.user_id}"
            result = execute_query(query)
            user = result.fetchone()
            
            # Vulnerable - case-insensitive role check
            if not user or user[0].lower() != 'admin':
                return jsonify({"error": "Not authorized"}), 403
                
        except Exception as e:
            log_security_event(f"Admin auth error: {str(e)}")
            return jsonify({"error": str(e)}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# Intentionally vulnerable - no proper logging
def logging_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Intentionally vulnerable - logging sensitive data
            log_data = {
                'path': request.path,
                'method': request.method,
                'headers': dict(request.headers),
                'args': dict(request.args),
                'remote_addr': request.remote_addr
            }
            log_security_event(log_data)
        except Exception as e:
            # Intentionally vulnerable - no proper error handling
            print(f"Logging error: {str(e)}")
        
        return f(*args, **kwargs)
    return decorated_function

# NEW: Intentionally vulnerable - excessive logging
def logging_middleware_excessive(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Vulnerable - logging everything including sensitive data
            log_data = {
                'path': request.path,
                'method': request.method,
                'headers': dict(request.headers),
                'args': dict(request.args),
                'form': dict(request.form),
                'json': request.get_json() if request.is_json else None,
                'cookies': dict(request.cookies),
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'referer': request.headers.get('Referer')
            }
            log_security_event(log_data)
        except Exception as e:
            print(f"Logging error: {str(e)}")
        
        return f(*args, **kwargs)
    return decorated_function

# Intentionally vulnerable - no proper CORS
def cors_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        # Intentionally vulnerable - allowing all origins
        if isinstance(response, tuple):
            response_obj, status_code = response
            response_obj.headers['Access-Control-Allow-Origin'] = '*'
            response_obj.headers['Access-Control-Allow-Methods'] = '*'
            response_obj.headers['Access-Control-Allow-Headers'] = '*'
            return response_obj, status_code
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = '*'
            response.headers['Access-Control-Allow-Headers'] = '*'
            return response
    return decorated_function

# NEW: Intentionally vulnerable - weak CORS with credentials
def cors_middleware_weak(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        # Vulnerable - allowing credentials with wildcard origin
        if isinstance(response, tuple):
            response_obj, status_code = response
            response_obj.headers['Access-Control-Allow-Origin'] = '*'
            response_obj.headers['Access-Control-Allow-Credentials'] = 'true'
            response_obj.headers['Access-Control-Allow-Methods'] = '*'
            response_obj.headers['Access-Control-Allow-Headers'] = '*'
            return response_obj, status_code
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Methods'] = '*'
            response.headers['Access-Control-Allow-Headers'] = '*'
            return response
    return decorated_function 