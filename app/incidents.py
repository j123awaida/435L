"""Service 3 — Hassan Nasrallah. Sequential lifecycle and scoped investigations."""
import json
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from .auth import allowed, deny, now
from .common import create_app, get_record
from .db import connect
from .sprint123_models import (PREFIX, Assignment, IncidentCreate, IncidentDetail,
                               IncidentRecord, NoteCreate, NoteRecord, StatusChange)

app = create_app('Service 3: Incident Management — Hassan Nasrallah', PREFIX)
r = APIRouter(prefix=PREFIX + '/incidents', tags=['Incidents'])
read = allowed('admin', 'analyst', 'employee', 'auditor')

def visible(record, user):
    return (user['role'] in ('admin', 'auditor') or
            user['role'] == 'employee' and record['reporter_id'] == user['id'] or
            user['role'] == 'analyst' and record['assigned_analyst_id'] == user['id'])

def check_access(id, request, user):
    with connect() as db:
        record = get_record(db, 'incidents', id)
    if not visible(record, user):
        deny(user, request, 'Access is limited to submitted or assigned incidents')
    return record

@r.post('', status_code=201, response_model=IncidentRecord, summary='Report incident', description='Administrator/employee only. Employees must report as themselves. Asset and reporter must exist; status starts Open.')
def create(body: IncidentCreate, request: Request, user=Depends(allowed('admin', 'employee'))):
    if user['role'] == 'employee' and body.reporter_id != user['id']:
        deny(user, request, 'Employees must report incidents as themselves')
    with connect() as db:
        reporter = get_record(db, 'users', body.reporter_id)
        if reporter['account_status'] != 'Active':
            raise HTTPException(422, 'Reporter must have an active account')
        get_record(db, 'assets', body.asset_id)
        fields = body.model_dump() | {'created_at': now()}
        cursor = db.execute('INSERT INTO incidents(' + ','.join(fields) + ') VALUES(' + ','.join('?' for _ in fields) + ')', tuple(fields.values()))
        return get_record(db, 'incidents', cursor.lastrowid)

@r.get('', response_model=list[IncidentRecord], summary='List visible incidents', description='Administrator/auditor see all; employees see submitted incidents and analysts see assigned incidents. Paginated.')
def list_incidents(user=Depends(read), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    clause, params = '1=1', ()
    if user['role'] == 'analyst':
        clause, params = 'assigned_analyst_id=?', (user['id'],)
    elif user['role'] == 'employee':
        clause, params = 'reporter_id=?', (user['id'],)
    with connect() as db:
        return [dict(row) for row in db.execute('SELECT * FROM incidents WHERE ' + clause + ' ORDER BY id LIMIT ? OFFSET ?', (*params, limit, offset))]

@r.get('/{id}', response_model=IncidentDetail, summary='Retrieve incident and notes', description='Applies reporter/assigned-analyst ownership checks. Employees can track their incident status; private investigation notes are returned only to security staff/auditors.')
def retrieve(id: int, request: Request, user=Depends(read)):
    record = check_access(id, request, user)
    with connect() as db:
        record['investigation_notes'] = [] if user['role'] == 'employee' else [dict(row) for row in db.execute('SELECT * FROM investigation_notes WHERE incident_id=? ORDER BY id', (id,))]
    return record

@r.put('/{id}/assign', response_model=IncidentRecord, summary='Assign incident to analyst', description='Administrator only. Requires an active analyst. Commits the assignment, audit entry and retriable Service 8 notification together.')
def assign(id: int, body: Assignment, user=Depends(allowed('admin'))):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old = get_record(db, 'incidents', id)
        analyst = get_record(db, 'users', body.analyst_id)
        if analyst['role'] != 'analyst' or analyst['account_status'] != 'Active':
            raise HTTPException(422, 'Assigned user must be an active security analyst')
        if old['status'] == 'Closed':
            raise HTTPException(409, 'Closed incidents cannot be reassigned')
        if old['assigned_analyst_id'] != body.analyst_id:
            db.execute('UPDATE incidents SET assigned_analyst_id=? WHERE id=?', (body.analyst_id, id))
            db.execute('INSERT INTO audit_logs(user_id,action,description,severity,related_service,created_at) VALUES(?,?,?,?,?,?)',
                       (user['id'], 'Incident assigned', f'Incident {id} assigned to analyst {body.analyst_id}', 'Information', app.title, now()))
            payload = {'user_id': body.analyst_id, 'title': f'Incident assigned: {old["title"]}'[:2000],
                       'message': f'Investigate incident {id}: {old["description"]}'[:2000],
                       'notification_type': 'Incident Assignment', 'severity': old['severity']}
            db.execute('INSERT INTO notification_outbox(event_id,payload_json,created_at) VALUES(?,?,?)', (str(uuid.uuid4()), json.dumps(payload, sort_keys=True), now()))
        return get_record(db, 'incidents', id)

@r.put('/{id}/status', response_model=IncidentRecord, summary='Advance incident lifecycle', description='Administrator/assigned analyst only. Open → Under Investigation → Mitigated → Resolved → Closed, one step per request. Resolution date is server-generated and preserved.')
def status(id: int, body: StatusChange, request: Request, user=Depends(allowed('admin', 'analyst'))):
    check_access(id, request, user)
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old = get_record(db, 'incidents', id)
        if not visible(old, user):
            # Assignment may have changed between the precheck and transaction.
            denied = True
        else:
            denied = False
            states = ['Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed']
            index = states.index(old['status'])
            if body.status != old['status']:
                if index == len(states) - 1 or body.status != states[index + 1]:
                    raise HTTPException(409, 'Incident must advance one lifecycle step at a time')
                db.execute('UPDATE incidents SET status=?,resolution_date=? WHERE id=?', (body.status, now() if body.status == 'Resolved' else old['resolution_date'], id))
            result = get_record(db, 'incidents', id)
    if denied:
        deny(user, request, 'Incident is no longer assigned to this analyst')
    return result

@r.post('/{id}/notes', status_code=201, response_model=NoteRecord, summary='Add investigation note', description='Administrator/assigned analyst only. Author and timestamp come from the authenticated session and server. Closed incidents reject new notes.')
def notes(id: int, body: NoteCreate, request: Request, user=Depends(allowed('admin', 'analyst'))):
    check_access(id, request, user)
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old = get_record(db, 'incidents', id)
        denied = not visible(old, user)
        if not denied:
            if old['status'] == 'Closed':
                raise HTTPException(409, 'Closed incidents cannot receive new notes')
            cursor = db.execute('INSERT INTO investigation_notes(incident_id,analyst_id,content,created_at) VALUES(?,?,?,?)', (id, user['id'], body.content, now()))
            result = get_record(db, 'investigation_notes', cursor.lastrowid)
    if denied:
        deny(user, request, 'Incident is no longer assigned to this analyst')
    return result

app.include_router(r)
