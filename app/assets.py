"""Service 2 — Hassan Nasrallah."""
import json
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from .auth import allowed, deny, now
from .common import create_app, get_record
from .db import connect
from .models import Message, Severity
from .sprint123_models import (PREFIX, AssetCreate, AssetDetail, AssetRecord, AssetType,
                               AssetUpdate, HistoryRecord)

app = create_app('Service 2: Asset Management — Hassan Nasrallah', PREFIX)
r = APIRouter(prefix=PREFIX + '/assets', tags=['Assets'])
ASSET_SELECT = '''SELECT a.id,a.name,a.owner_id,p.asset_type,p.ip_address,p.operating_system,
 p.department,p.location,p.criticality,p.status,p.created_at FROM assets a
 LEFT JOIN asset_profiles p ON p.asset_id=a.id'''

def asset_record(db, id):
    row = db.execute(ASSET_SELECT + ' WHERE a.id=?', (id,)).fetchone()
    if row is None:
        raise HTTPException(404, 'Asset not found')
    return dict(row)

def history(db, record, actor_id, action):
    db.execute('INSERT INTO asset_history(asset_id,actor_id,action,snapshot_json,created_at) VALUES(?,?,?,?,?)',
               (record['id'], actor_id, action, json.dumps(record), now()))

def check_owner(db, owner_id):
    owner = get_record(db, 'users', owner_id)
    if owner['account_status'] != 'Active':
        raise HTTPException(422, 'Asset owner must have an active account')

@r.post('', status_code=201, response_model=AssetRecord, summary='Add organizational asset', description='Administrator only. Validates owner, IP address, type, criticality and status; records an immutable initial snapshot.')
def create(body: AssetCreate, user=Depends(allowed('admin'))):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        check_owner(db, body.owner_id)
        # Existing assets use INTEGER PRIMARY KEY, which may reuse a deleted ID.
        # Allocate beyond retained history so a new asset cannot inherit old snapshots.
        next_id = db.execute('SELECT COALESCE(MAX(id),0)+1 FROM (SELECT id FROM assets UNION ALL SELECT asset_id AS id FROM asset_history)').fetchone()[0]
        cursor = db.execute('INSERT INTO assets(id,name,owner_id) VALUES(?,?,?)', (next_id, body.name, body.owner_id))
        fields = body.model_dump(exclude={'name', 'owner_id'}) | {'asset_id': cursor.lastrowid, 'created_at': now()}
        db.execute('INSERT INTO asset_profiles(' + ','.join(fields) + ') VALUES(' + ','.join('?' for _ in fields) + ')', tuple(fields.values()))
        record = asset_record(db, cursor.lastrowid)
        history(db, record, user['id'], 'Created')
        return record

@r.get('', response_model=list[AssetRecord], summary='List all assets', description='Administrator/auditor only. Legacy reference assets retain null metadata until completed through the update API.')
def list_assets(user=Depends(allowed('admin', 'auditor')), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with connect() as db:
        return [dict(row) for row in db.execute(ASSET_SELECT + ' ORDER BY a.id LIMIT ? OFFSET ?', (limit, offset))]

@r.get('/search', response_model=list[AssetRecord], summary='Search assets', description='Administrator/analyst/auditor. Name is a literal case-insensitive substring; other filters are exact and combine with AND.')
def search(name: str | None = Query(None, min_length=1, max_length=2000), asset_type: AssetType | None = None,
           ip_address: str | None = None, department: str | None = None, criticality: Severity | None = None,
           limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
           user=Depends(allowed('admin', 'analyst', 'auditor'))):
    clauses, params = [], []
    if name is not None:
        clauses.append('instr(lower(a.name),lower(?))>0')
        params.append(name)
    if ip_address is not None:
        from ipaddress import ip_address as parse_ip
        try:
            ip_address = str(parse_ip(ip_address))
        except ValueError:
            raise HTTPException(422, 'Invalid IP address') from None
    for column, value in {'asset_type': asset_type, 'ip_address': ip_address, 'department': department, 'criticality': criticality}.items():
        if value is not None:
            clauses.append('p.' + column + '=?')
            params.append(value)
    with connect() as db:
        return [dict(row) for row in db.execute(ASSET_SELECT + ' WHERE ' + (' AND '.join(clauses) or '1=1') + ' ORDER BY a.id LIMIT ? OFFSET ?', (*params, limit, offset))]

@r.get('/{id}/history', response_model=list[HistoryRecord], summary='View asset history', description='Administrator/auditor only. Immutable before/after snapshots survive asset deletion.')
def asset_history(id: int, user=Depends(allowed('admin', 'auditor'))):
    with connect() as db:
        rows = db.execute('SELECT * FROM asset_history WHERE asset_id=? ORDER BY id', (id,)).fetchall()
        if not rows:
            asset_record(db, id)
        return [{k: row[k] for k in row.keys() if k != 'snapshot_json'} | {'snapshot': json.loads(row['snapshot_json'])} for row in rows]

@r.get('/{id}', response_model=AssetDetail, summary='Retrieve asset and relationships', description='Administrator/auditor can read any asset. An analyst can retrieve assets linked to incidents assigned to them; search remains available.')
def retrieve(id: int, request: Request, user=Depends(allowed('admin', 'analyst', 'auditor'))):
    with connect() as db:
        record = asset_record(db, id)
        related = user['role'] != 'analyst' or db.execute('SELECT 1 FROM incidents WHERE asset_id=? AND assigned_analyst_id=?', (id, user['id'])).fetchone()
        record['incident_ids'] = [row[0] for row in db.execute('SELECT id FROM incidents WHERE asset_id=?' + (' AND assigned_analyst_id=?' if user['role'] == 'analyst' else ''), (id, user['id']) if user['role'] == 'analyst' else (id,))]
        record['vulnerability_ids'] = [row[0] for row in db.execute('SELECT id FROM vulnerabilities WHERE asset_id=?', (id,))]
    if not related:
        deny(user, request, 'Analysts may retrieve only assets related to their assigned incidents')
    return record

@r.put('/{id}', response_model=AssetRecord, summary='Update asset', description='Administrator only. Records before/after snapshots. Completing a legacy asset requires all mandatory metadata fields.')
def update(id: int, body: AssetUpdate, user=Depends(allowed('admin'))):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old = asset_record(db, id)
        fields = body.model_dump(exclude_unset=True)
        if 'owner_id' in fields:
            check_owner(db, fields['owner_id'])
        if old['asset_type'] is None:
            # Validate a complete replacement profile for pre-existing reference assets.
            candidate = {k: v for k, v in old.items() if k not in ('id', 'created_at') and v is not None} | fields
            try:
                completed = AssetCreate(**candidate)
            except ValueError:
                raise HTTPException(422, 'Legacy assets require asset_type, ip_address, department, location, criticality on first update') from None
            profile = completed.model_dump(exclude={'name', 'owner_id'}) | {'asset_id': id, 'created_at': now()}
            db.execute('INSERT INTO asset_profiles(' + ','.join(profile) + ') VALUES(' + ','.join('?' for _ in profile) + ')', tuple(profile.values()))
        history(db, old, user['id'], 'Before update')
        base = {k: fields.pop(k) for k in ('name', 'owner_id') if k in fields}
        if base:
            db.execute('UPDATE assets SET ' + ','.join(k + '=?' for k in base) + ' WHERE id=?', (*base.values(), id))
        if fields:
            db.execute('UPDATE asset_profiles SET ' + ','.join(k + '=?' for k in fields) + ' WHERE asset_id=?', (*fields.values(), id))
        record = asset_record(db, id)
        history(db, record, user['id'], 'Updated')
        return record

@r.delete('/{id}', response_model=Message, summary='Delete asset', description='Administrator only. Foreign-key references from incidents/vulnerabilities prevent deletion (409). Historical snapshots remain.')
def delete(id: int, user=Depends(allowed('admin'))):
    with connect() as db:
        record = asset_record(db, id)
        db.execute('DELETE FROM assets WHERE id=?', (id,))
        history(db, record, user['id'], 'Deleted')
    return {'message': 'Asset deleted'}

app.include_router(r)
