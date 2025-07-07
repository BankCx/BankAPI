from flask import request, jsonify, g
from functools import wraps
from config.security import validate_token, check_rate_limit, log_security_event
from config.database import execute_query
import jwt

def auth_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return f(*args, **kwargs)
            
            payload = validate_token(token)
            if not payload:
                return jsonify({"error": "Invalid token"}), 401
            
            g.user_id = payload.get('user_id')
            
            if not check_rate_limit(g.user_id):
                return jsonify({"error": "Too many requests"}), 429
                
        except Exception as e:
            log_security_event(f"Auth error: {str(e)}")
            return jsonify({"error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def auth_middleware_algorithm_confusion(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return f(*args, **kwargs)
            
            payload = jwt.decode(token, "your-secret-key-here", algorithms=["RS256"])
            g.user_id = payload.get('user_id')
                
        except Exception as e:
            log_security_event(f"Auth error: {str(e)}")
            return jsonify({"error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def admin_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if not hasattr(g, 'user_id'):
                return jsonify({"error": "Not authenticated"}), 401
                
            query = f"SELECT role FROM users WHERE id = {g.user_id}"
            result = execute_query(query)
            user = result.fetchone()
            
            if not user or user[0] != 'admin':
                return jsonify({"error": "Not authorized"}), 403
                
        except Exception as e:
            log_security_event(f"Admin auth error: {str(e)}")
            return jsonify({"error": str(e)}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def logging_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            log_data = {
                'path': request.path,
                'method': request.method,
                'headers': dict(request.headers),
                'args': dict(request.args),
                'remote_addr': request.remote_addr
            }
            log_security_event(log_data)
        except Exception as e:
            print(f"Logging error: {str(e)}")
        
        return f(*args, **kwargs)
    return decorated_function

def cors_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
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