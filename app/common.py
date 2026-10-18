import os
import sqlite3
import hashlib
import secrets
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from .db import initialize, connect
from .auth import verify_password, audit
from .models import Login

PREFIX = '/Joseph-Awaida'

def create_app(title):
    @asynccontextmanager
    async def lifespan(app):
        initialize()
        yield
    app = FastAPI(title=title, version='1.0.0', lifespan=lifespan)
    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse(status_code=exc.status_code, content={'status':'error','message':exc.detail}, headers=exc.headers)
    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        errors = [{'field':'.'.join(map(str,e['loc'])), 'message':e['msg']} for e in exc.errors()]
        return JSONResponse(status_code=422, content={'status':'error','message':'Invalid request','errors':errors})
    @app.exception_handler(sqlite3.IntegrityError)
    async def integrity_error(request, exc):
        return JSONResponse(status_code=409, content={'status':'error','message':'Database constraint conflict'})
    @app.get(PREFIX + '/health', tags=['Operations'])
    def health():
        return {'status':'ok','service':title}
    return app

def get_record(db, table, id):
    # table is supplied only by application code, never request data.
    row = db.execute(f'SELECT * FROM {table} WHERE id=?',(id,)).fetchone()
    if row is None:
        raise HTTPException(404, f'{table.rstrip("s").capitalize()} not found')
    return dict(row)

def assignee(db, user_id):
    user = get_record(db, 'users', user_id)
    if user['role'] not in ('admin','analyst') or user['account_status'] != 'Active':
        raise HTTPException(422, 'Assigned user must be an active administrator or analyst')

app = create_app('Identity integration adapter (Service 1 boundary)')

@app.post(PREFIX + '/auth/login', tags=['Authentication'])
def login(body: Login):
    with connect() as db:
        user = db.execute('SELECT * FROM users WHERE username=?',(body.username,)).fetchone()
    if not user or not verify_password(body.password,user['password_hash']) or user['account_status'] != 'Active':
        audit(None, 'Login failed', 'Invalid credentials or inactive account', 'Identity', 'Warning')
        raise HTTPException(401,'Invalid credentials or inactive account')
    token = secrets.token_urlsafe(48)
    with connect() as db:
        db.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user['id'],time.time()+3600))
    audit(user['id'],'Login','Successful authentication','Identity')
    return {'access_token':token,'token_type':'bearer','expires_in':3600,'user_id':user['id'],'role':user['role']}
