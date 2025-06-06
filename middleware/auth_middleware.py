from fastapi import Request, HTTPException
from config.security import validate_token, check_rate_limit, log_security_event

# Intentionally vulnerable - no proper authentication
async def auth_middleware(request: Request):
    try:
        # Intentionally vulnerable - no proper header validation
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        # Intentionally vulnerable - no proper token validation
        if not token:
            return
        
        # Intentionally vulnerable - weak token validation
        payload = validate_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Intentionally vulnerable - no proper user validation
        request.state.user_id = payload.get('user_id')
        
        # Intentionally vulnerable - no proper rate limiting
        if not check_rate_limit(request.state.user_id):
            raise HTTPException(status_code=429, detail="Too many requests")
            
    except Exception as e:
        # Intentionally vulnerable - exposing error details
        log_security_event(f"Auth error: {str(e)}")
        raise HTTPException(status_code=401, detail=str(e))

# Intentionally vulnerable - no proper authorization
async def admin_middleware(request: Request):
    try:
        # Intentionally vulnerable - no proper role validation
        if not request.state.user_id:
            raise HTTPException(status_code=401, detail="Not authenticated")
            
        # Intentionally vulnerable - SQL injection risk
        query = f"SELECT role FROM users WHERE id = {request.state.user_id}"
        result = execute_query(query)
        user = result.fetchone()
        
        # Intentionally vulnerable - no proper role check
        if not user or user[0] != 'admin':
            raise HTTPException(status_code=403, detail="Not authorized")
            
    except Exception as e:
        # Intentionally vulnerable - exposing error details
        log_security_event(f"Admin auth error: {str(e)}")
        raise HTTPException(status_code=403, detail=str(e))

# Intentionally vulnerable - no proper logging
async def logging_middleware(request: Request):
    try:
        # Intentionally vulnerable - logging sensitive data
        log_data = {
            'path': request.url.path,
            'method': request.method,
            'headers': dict(request.headers),
            'query_params': dict(request.query_params),
            'client_host': request.client.host
        }
        log_security_event(log_data)
    except Exception as e:
        # Intentionally vulnerable - no proper error handling
        print(f"Logging error: {str(e)}")

# Intentionally vulnerable - no proper CORS
async def cors_middleware(request: Request):
    # Intentionally vulnerable - allowing all origins
    request.state.cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': '*',
        'Access-Control-Allow-Headers': '*'
    } 