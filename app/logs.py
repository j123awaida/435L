"""Service 5: Security Audit Logging (Mohammad Nasrallah).

Reuses the existing immutable ``audit_logs`` table and the automatic logging already
performed by ``common.create_app``'s middleware and ``auth.deny``. This service adds
the read, search and retention APIs, plus an idempotent ingestion endpoint that
Services 1–3 and 7–9 call so a delivery retry cannot record an event twice.
"""
import hashlib
import json
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from .auth import allowed, now
from .common import create_app
from .db import connect
from .models import Message
from .sprint456_models import PREFIX, LogCreate, LogRecord, LogSeverity

app = create_app('Service 5: Security Audit Logging', PREFIX)
r = APIRouter(prefix=PREFIX + '/logs', tags=['Security Audit Logging'])

# Service 5 authorization table. Employees have no access to audit logs.
# Analysts may read a specific record and search, but not list all or read by user.
read_all = allowed('admin', 'auditor')
read_one = allowed('admin', 'analyst', 'auditor')


def fetch(db, id):
    row = db.execute('SELECT * FROM audit_logs WHERE id=?', (id,)).fetchone()
    if row is None:
        raise HTTPException(404, 'Log not found')
    return dict(row)


def suppress_modification_audit(request):
    """Stop the shared middleware from adding a 'Data modification' row for this request.

    An ingested log already *is* the audit record for the teammate's event. Letting the
    middleware append a second row would duplicate every forwarded event and inflate the
    activity report. Deletions keep the middleware entry on purpose.
    """
    request.state.user_id = None


@r.post('', status_code=201, summary='Create log record',
        description='Administrators and integrating services record a security activity. '
                    'Supply an Idempotency-Key header to make delivery retries safe: replaying a key returns the '
                    'original record with HTTP 200 instead of creating a second row. Reusing a key with a different '
                    'payload returns 409.',
        response_model=LogRecord)
def create(body: LogCreate, request: Request, response: Response,
           idempotency_key: str | None = Header(default=None, alias='Idempotency-Key', max_length=200),
           user=Depends(allowed('admin'))):
    payload = body.model_dump()
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if idempotency_key:
            receipt = db.execute('SELECT * FROM log_receipts WHERE idempotency_key=?', (idempotency_key,)).fetchone()
            if receipt is not None:
                if receipt['payload_hash'] != digest:
                    raise HTTPException(409, 'Idempotency-Key was already used for a different log payload')
                suppress_modification_audit(request)
                response.status_code = 200
                return fetch(db, receipt['log_id'])
        if payload['user_id'] is not None and db.execute('SELECT 1 FROM users WHERE id=?', (payload['user_id'],)).fetchone() is None:
            raise HTTPException(422, 'Referenced user does not exist')
        fields = payload | {'created_at': now()}
        cursor = db.execute(f'INSERT INTO audit_logs({",".join(fields)}) VALUES({",".join("?" for _ in fields)})', tuple(fields.values()))
        if idempotency_key:
            db.execute('INSERT INTO log_receipts VALUES(?,?,?,?)', (idempotency_key, cursor.lastrowid, digest, now()))
        suppress_modification_audit(request)
        return fetch(db, cursor.lastrowid)


@r.get('', summary='Retrieve all logs',
        description='Administrators and auditors list audit records newest first, with limit/offset pagination.',
        response_model=list[LogRecord])
def all_records(user=Depends(read_all), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with connect() as db:
        return [dict(x) for x in db.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?', (limit, offset))]


# Declared before /{id} so these literal paths are not captured as identifiers.
@r.get('/search', summary='Search logs',
        description='Administrators, analysts and auditors filter by user, action, severity, related service and an '
                    'inclusive date range. Action matching is a literal case-insensitive substring; other filters are '
                    'exact. Filters combine with AND and no matches return an empty array.',
        response_model=list[LogRecord])
def search(user_id: int | None = Query(None, gt=0), action: str | None = Query(None, min_length=1, max_length=200),
           severity: LogSeverity | None = None, related_service: str | None = Query(None, min_length=1, max_length=200),
           date_from: str | None = Query(None, pattern=r'^\d{4}-\d{2}-\d{2}$', description='Inclusive UTC start date'),
           date_to: str | None = Query(None, pattern=r'^\d{4}-\d{2}-\d{2}$', description='Inclusive UTC end date'),
           user=Depends(read_one)):
    clauses, values = [], []
    if user_id is not None:
        clauses.append('user_id=?')
        values.append(user_id)
    if action is not None:
        clauses.append("action LIKE '%' || ? || '%' ESCAPE '\\'")
        values.append(action.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_'))
    if severity is not None:
        clauses.append('severity=?')
        values.append(severity)
    if related_service is not None:
        clauses.append('related_service=?')
        values.append(related_service)
    # created_at holds ISO-8601 UTC timestamps, so a lexicographic date comparison is correct.
    if date_from is not None:
        clauses.append('substr(created_at,1,10)>=?')
        values.append(date_from)
    if date_to is not None:
        clauses.append('substr(created_at,1,10)<=?')
        values.append(date_to)
    where = ' AND '.join(clauses) or '1=1'
    with connect() as db:
        return [dict(x) for x in db.execute(f'SELECT * FROM audit_logs WHERE {where} ORDER BY id DESC', tuple(values))]


@r.get('/user/{user_id}', summary='Retrieve logs by user',
        description='Administrators and auditors retrieve every activity recorded for one user, newest first. '
                    'A user with no recorded activity returns an empty array; an unknown user returns 404.',
        response_model=list[LogRecord])
def by_user(user_id: int, user=Depends(read_all), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with connect() as db:
        if db.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone() is None:
            raise HTTPException(404, 'User not found')
        return [dict(x) for x in db.execute('SELECT * FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT ? OFFSET ?', (user_id, limit, offset))]


@r.get('/{id}', summary='Retrieve specific log',
        description='Administrators, analysts and auditors read one audit record. An invalid identifier returns 404.',
        response_model=LogRecord)
def retrieve(id: int, user=Depends(read_one)):
    with connect() as db:
        return fetch(db, id)


@r.delete('/{id}', summary='Delete log',
        description='Administrator only, as required for audit retention. Analysts, auditors and employees receive 403 '
                    'and the denial is itself recorded. The removed identifier, the administrator and the time are '
                    'retained in an immutable deletion record. Audit records cannot be updated at all: no update '
                    'endpoint exists and a database trigger rejects any UPDATE.',
        response_model=Message)
def delete(id: int, user=Depends(allowed('admin'))):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        record = fetch(db, id)
        # Clear ingestion bookkeeping first; log_receipts references audit_logs(id).
        db.execute('DELETE FROM log_receipts WHERE log_id=?', (id,))
        db.execute('DELETE FROM audit_logs WHERE id=?', (id,))
        # Deleting an audit record is itself a security-relevant act, so retain who did it.
        db.execute('INSERT INTO log_tombstones(log_id,deleted_by,action,recorded_at,deleted_at) VALUES(?,?,?,?,?)',
                   (id, user['id'], record['action'], record['created_at'], now()))
    return {'message': 'Log deleted'}


app.include_router(r)
