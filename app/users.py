"""Service 1 — Hassan Nasrallah. Uses the team's existing opaque sessions."""
import hashlib
import secrets
import sqlite3
import time
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials
from .auth import allowed, audit, bearer, deny, hash_password, identity, now, verify_password
from .common import create_app
from .db import connect
from .models import Message
from .sprint123_models import (PREFIX, AccountChange, Register, RoleChange, TokenRecord,
                               UserLogin, UserRecord, UserUpdate)

app = create_app('Service 1: Users and Identity Management — Hassan Nasrallah', PREFIX)
r = APIRouter(prefix=PREFIX + '/users', tags=['Users and Identity'])
USER_SELECT = '''SELECT u.id,u.full_name,u.username,u.role,u.account_status,
 p.email,p.department,p.created_at,p.last_login_at FROM users u
 LEFT JOIN user_profiles p ON p.user_id=u.id'''

def user_record(db, user_id):
    row = db.execute(USER_SELECT + ' WHERE u.id=? AND NOT EXISTS (SELECT 1 FROM deleted_users d WHERE d.user_id=u.id)', (user_id,)).fetchone()
    if row is None:
        raise HTTPException(404, 'User not found')
    return dict(row)

def optional_identity(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    return identity(request, credentials) if credentials else None

@r.post('/register', status_code=201, response_model=UserRecord,
        summary='Register account', description='Public registration creates employees only. An authenticated administrator may create any role. Duplicate username/email returns 409.')
def register(body: Register, request: Request, actor=Depends(optional_identity)):
    if actor is not None and actor['role'] not in ('admin', 'employee'):
        deny(actor, request, 'Role does not permit registration')
    if body.role != 'employee' and (actor is None or actor['role'] != 'admin'):
        if actor:
            deny(actor, request, 'Only administrators can assign privileged roles')
        audit(None, 'Permission denied', 'Public registration requested a privileged role', app.title, 'Warning')
        raise HTTPException(403, 'Public registration may only create an employee')
    encoded = hash_password(body.password)
    try:
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            cursor = db.execute('INSERT INTO users(full_name,username,password_hash,role) VALUES(?,?,?,?)',
                                (body.full_name, body.username, encoded, body.role))
            db.execute('INSERT INTO user_profiles(user_id,email,department,created_at) VALUES(?,?,?,?)',
                       (cursor.lastrowid, body.email, body.department, now()))
            result = user_record(db, cursor.lastrowid)
    except sqlite3.IntegrityError:
        raise HTTPException(409, 'Username or email already exists') from None
    audit(result['id'], 'Registration', 'User account created', app.title)
    return result

@r.post('/login', response_model=TokenRecord, summary='Authenticate account',
        description='Username or email and password produce a one-hour bearer session. Only a token hash is stored. Inactive/suspended accounts return 401.')
def login(body: UserLogin):
    with connect() as db:
        # Serialize login with role/status/deletion changes so stale sessions cannot be issued.
        db.execute('BEGIN IMMEDIATE')
        user = db.execute('''SELECT u.* FROM users u LEFT JOIN user_profiles p ON p.user_id=u.id
                             WHERE u.username=? OR p.email=? COLLATE NOCASE''',
                          (body.username, body.username)).fetchone()
        valid = user is not None and verify_password(body.password, user['password_hash']) and user['account_status'] == 'Active'
        if valid:
            token = secrets.token_urlsafe(48)
            db.execute('INSERT INTO sessions VALUES(?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(), user['id'], time.time() + 3600))
            db.execute('UPDATE user_profiles SET last_login_at=? WHERE user_id=?', (now(), user['id']))
    if not valid:
        audit(None, 'Login failed', 'Invalid credentials or inactive account', app.title, 'Warning')
        raise HTTPException(401, 'Invalid credentials or inactive account', headers={'WWW-Authenticate': 'Bearer'})
    audit(user['id'], 'Login', 'Successful authentication', app.title)
    return {'access_token': token, 'token_type': 'bearer', 'expires_in': 3600, 'user_id': user['id'], 'role': user['role']}

@r.get('/session', response_model=UserRecord, summary='Verify current session',
       description='Any authenticated team service can verify the bearer token and retrieve current identity, role and account status.')
def session(user=Depends(identity)):
    with connect() as db:
        return user_record(db, user['id'])

@r.post('/logout', response_model=Message, summary='Revoke current session')
def logout(credentials=Depends(bearer), user=Depends(identity)):
    with connect() as db:
        db.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(credentials.credentials.encode()).hexdigest(),))
    return {'message': 'Session revoked'}

@r.get('', response_model=list[UserRecord], summary='List users', description='Administrator/auditor only; paginated safe profile records exclude passwords and tokens.')
def list_users(user=Depends(allowed('admin', 'auditor')), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with connect() as db:
        return [dict(row) for row in db.execute(USER_SELECT + ' WHERE NOT EXISTS (SELECT 1 FROM deleted_users d WHERE d.user_id=u.id) ORDER BY u.id LIMIT ? OFFSET ?', (limit, offset))]

@r.get('/{id}/roles', summary='View role and permissions', description='Administrator/auditor only. Role codes are shared across all team services.')
def roles(id: int, user=Depends(allowed('admin', 'auditor'))):
    with connect() as db:
        record = user_record(db, id)
    permissions = {
        'admin': ['users:manage', 'assets:manage', 'incidents:manage'],
        'analyst': ['assets:read-related', 'assets:search', 'incidents:read-assigned', 'incidents:investigate-assigned'],
        'employee': ['users:read-self', 'users:update-self', 'incidents:report', 'incidents:read-submitted'],
        'auditor': ['users:read', 'assets:read', 'incidents:read'],
    }
    return {'user_id': id, 'role': record['role'], 'permissions': permissions[record['role']]}

@r.put('/{id}/role', response_model=UserRecord, summary='Assign or update user role', description='Administrator only. Protects the final active administrator and revokes sessions on role changes.')
def change_role(id: int, body: RoleChange, user=Depends(allowed('admin'))):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old = user_record(db, id)
        protect_last_admin(db, old, body.role, old['account_status'])
        if old['role'] == 'analyst' and body.role != 'analyst' and db.execute(
                "SELECT 1 FROM incidents WHERE assigned_analyst_id=? AND status!='Closed'", (id,)).fetchone():
            raise HTTPException(409, 'Reassign active incidents before removing analyst role')
        db.execute('UPDATE users SET role=? WHERE id=?', (body.role, id))
        db.execute('DELETE FROM sessions WHERE user_id=?', (id,))
        return user_record(db, id)

@r.delete('/{id}/role', response_model=UserRecord, summary='Remove privileged role assignment', description='Resets the role to employee and revokes sessions. Same protections as role assignment.')
def remove_role(id: int, user=Depends(allowed('admin'))):
    return change_role(id, RoleChange(role='employee'), user)

def protect_last_admin(db, old, role, status):
    if old['role'] == 'admin' and old['account_status'] == 'Active' and (role != 'admin' or status != 'Active'):
        if db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND account_status='Active'").fetchone()[0] <= 1:
            raise HTTPException(409, 'Cannot remove the final active administrator')

@r.put('/{id}/account-status', response_model=UserRecord, summary='Activate, deactivate or suspend account', description='Administrator only; any status change revokes existing sessions.')
def account_status(id: int, body: AccountChange, user=Depends(allowed('admin'))):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old = user_record(db, id)
        protect_last_admin(db, old, old['role'], body.account_status)
        db.execute('UPDATE users SET account_status=? WHERE id=?', (body.account_status, id))
        db.execute('DELETE FROM sessions WHERE user_id=?', (id,))
        return user_record(db, id)

@r.put('/{id}', response_model=UserRecord, summary='Update profile', description='Administrator or owning employee updates name/email/department. Empty, null and unknown fields are rejected.')
def update(id: int, body: UserUpdate, request: Request, user=Depends(allowed('admin', 'employee'))):
    if user['role'] == 'employee' and id != user['id']:
        deny(user, request, 'Employees may only update their own profile')
    with connect() as db:
        user_record(db, id)
        fields = body.model_dump(exclude_unset=True)
        if 'full_name' in fields:
            db.execute('UPDATE users SET full_name=? WHERE id=?', (fields.pop('full_name'), id))
        if fields:
            if not db.execute('SELECT 1 FROM user_profiles WHERE user_id=?', (id,)).fetchone():
                if 'email' not in fields or 'department' not in fields:
                    raise HTTPException(422, 'Legacy users need email and department on their first profile update')
                db.execute('INSERT INTO user_profiles(user_id,email,department,created_at) VALUES(?,?,?,?)',
                           (id, fields['email'], fields['department'], now()))
            else:
                db.execute('UPDATE user_profiles SET ' + ','.join(k + '=?' for k in fields) + ' WHERE user_id=?', (*fields.values(), id))
        return user_record(db, id)

@r.delete('/{id}', response_model=Message, summary='Delete user account', description='Administrator only. Revokes sessions, removes personal profile information and hides the account. An inactive tombstone preserves foreign keys and immutable audit history. Cannot delete self or the final administrator.')
def delete(id: int, user=Depends(allowed('admin'))):
    if id == user['id']:
        raise HTTPException(409, 'Administrators cannot delete their own account')
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old = user_record(db, id)
        protect_last_admin(db, old, 'employee', 'Inactive')
        if db.execute("SELECT 1 FROM incidents WHERE assigned_analyst_id=? AND status!='Closed'", (id,)).fetchone():
            raise HTTPException(409, 'Reassign active incidents before deleting this analyst')
        db.execute('DELETE FROM sessions WHERE user_id=?', (id,))
        db.execute('DELETE FROM user_profiles WHERE user_id=?', (id,))
        db.execute("UPDATE users SET full_name='Deleted account',username=?,password_hash=?,role='employee',account_status='Inactive' WHERE id=?",
                   ('deleted.' + secrets.token_hex(16), hash_password(secrets.token_urlsafe(48)), id))
        db.execute('INSERT INTO deleted_users VALUES(?,?)', (id, now()))
    return {'message': 'User deleted'}

@r.get('/{username}', response_model=UserRecord, summary='Retrieve user by username', description='Administrator/auditor may read any profile. An employee may read only their own; analysts have no user management access.')
def retrieve(username: str, request: Request, user=Depends(allowed('admin', 'employee', 'auditor'))):
    if user['role'] == 'employee' and username != user['username']:
        deny(user, request, 'Employees may only view their own profile')
    with connect() as db:
        row = db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
        if row is None:
            raise HTTPException(404, 'User not found')
        return user_record(db, row['id'])

app.include_router(r)
