"""Service 4: Threat Intelligence (Mohammad Nasrallah)."""
from fastapi import APIRouter, Depends, HTTPException, Query
from .auth import allowed, now
from .common import create_app, get_record
from .db import connect
from .models import Message, Severity
from .sprint456_models import PREFIX, ThreatCreate, ThreatRecord, ThreatType, ThreatUpdate, validate_threat_value

app = create_app('Service 4: Threat Intelligence', PREFIX)
r = APIRouter(prefix=PREFIX + '/threats', tags=['Threat Intelligence'])

# Service 4 authorization table: employees have no access to threat intelligence.
# Auditors are deliberately absent from search; see docs/MOHAMMAD-SPRINT1.md.
read = allowed('admin', 'analyst', 'auditor')
search_roles = allowed('admin', 'analyst')


@r.post('', status_code=201, summary='Add threat indicator',
        description='Administrator records a threat indicator. The value is validated against its type and stored in canonical form. A repeated type/value pair returns 409.',
        response_model=ThreatRecord)
def create(body: ThreatCreate, user=Depends(allowed('admin'))):
    fields = body.model_dump() | {'created_at': now()}
    with connect() as db:
        cursor = db.execute(f'INSERT INTO threats({",".join(fields)}) VALUES({",".join("?" for _ in fields)})', tuple(fields.values()))
        return get_record(db, 'threats', cursor.lastrowid)


@r.get('', summary='Retrieve all threat indicators',
        description='Administrators, analysts and auditors list stored indicators with limit/offset pagination.',
        response_model=list[ThreatRecord])
def all_records(user=Depends(read), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with connect() as db:
        return [dict(x) for x in db.execute('SELECT * FROM threats ORDER BY id LIMIT ? OFFSET ?', (limit, offset))]


# Declared before /{id} so the literal path is not captured as an identifier.
@r.get('/search', summary='Search threat indicators',
        description='Administrators and analysts filter by type, value, severity and source. Value matching is a literal case-insensitive substring; other filters are exact. Filters combine with AND and no matches return an empty array.',
        response_model=list[ThreatRecord])
def search(threat_type: ThreatType | None = None, threat_value: str | None = Query(None, min_length=1, max_length=512),
           severity: Severity | None = None, source: str | None = Query(None, min_length=1, max_length=200),
           user=Depends(search_roles)):
    clauses, values = [], []
    if threat_type is not None:
        clauses.append('threat_type=?')
        values.append(threat_type)
    if threat_value is not None:
        # Canonicalize a complete indicator so a search for 192.000.002.001 finds 192.0.2.1,
        # while partial input still works as a substring.
        probe = threat_value.strip()
        if threat_type is not None:
            try:
                probe = validate_threat_value(threat_type, probe)
            except ValueError:
                pass
        clauses.append("threat_value LIKE '%' || ? || '%' ESCAPE '\\'")
        values.append(probe.lower().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_'))
    if severity is not None:
        clauses.append('severity=?')
        values.append(severity)
    if source is not None:
        clauses.append('source=?')
        values.append(source)
    where = ' AND '.join(clauses) or '1=1'
    with connect() as db:
        return [dict(x) for x in db.execute(f'SELECT * FROM threats WHERE {where} ORDER BY id', tuple(values))]


@r.get('/{id}', summary='Retrieve specific threat indicator',
        description='Returns the complete indicator record, or 404 when it does not exist.',
        response_model=ThreatRecord)
def retrieve(id: int, user=Depends(read)):
    with connect() as db:
        return get_record(db, 'threats', id)


@r.put('/{id}', summary='Update threat information',
        description='Administrator edits description, severity or source. Threat type and value are immutable, because changing them would bypass the duplicate-indicator constraint.',
        response_model=ThreatRecord)
def update(id: int, body: ThreatUpdate, user=Depends(allowed('admin'))):
    fields = body.model_dump(exclude_unset=True)
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        get_record(db, 'threats', id)
        db.execute(f'UPDATE threats SET {",".join(k + "=?" for k in fields)} WHERE id=?', (*fields.values(), id))
        return get_record(db, 'threats', id)


@r.delete('/{id}', summary='Delete threat indicator',
        description='Administrator only. Analysts, auditors and employees receive 403 and the denial is recorded in the audit log. Deleting a missing record returns 404.',
        response_model=Message)
def delete(id: int, user=Depends(allowed('admin'))):
    with connect() as db:
        get_record(db, 'threats', id)
        db.execute('DELETE FROM threats WHERE id=?', (id,))
    return {'message': 'Threat indicator deleted'}


app.include_router(r)
