import hashlib
import hmac
import secrets
import time
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from .db import connect
from datetime import datetime, timezone

bearer = HTTPBearer(auto_error=False)

def now():
    return datetime.now(timezone.utc).isoformat()

def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600000).hex()
    return f'{salt}${digest}'

def verify_password(password, encoded):
    salt, expected = encoded.split('$')
    actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600000).hex()
    return hmac.compare_digest(actual, expected)

def audit(user_id, action, description, service, severity='Information'):
    with connect() as db:
        db.execute('INSERT INTO audit_logs(user_id,action,description,severity,related_service,created_at) VALUES(?,?,?,?,?,?)',
                   (user_id, action, description, severity, service, now()))

def identity(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not credentials:
        raise HTTPException(401, 'Bearer token required', headers={'WWW-Authenticate': 'Bearer'})
    digest = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    with connect() as db:
        user = db.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?', (digest, time.time())).fetchone()
    if not user or user['account_status'] != 'Active':
        raise HTTPException(401, 'Invalid, expired token or inactive account', headers={'WWW-Authenticate': 'Bearer'})
    return dict(user)

def allowed(*roles):
    def check(request: Request, user=Depends(identity)):
        if user['role'] not in roles:
            deny(user, request, 'Role does not permit this operation')
        return user
    return check

def deny(user, request, message='Access to another user’s notifications is forbidden'):
    audit(user['id'], 'Permission denied', f'{request.method} {request.url.path}: {message}', request.app.title, 'Warning')
    raise HTTPException(403, message)
