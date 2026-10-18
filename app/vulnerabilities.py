from fastapi import APIRouter, Depends, HTTPException, Query
from .common import create_app, PREFIX, get_record
from .db import connect
from .auth import allowed, now
from .models import VulnerabilityCreate, VulnerabilityUpdate, Severity, VStatus

app = create_app('Service 7: Vulnerability Management')
r = APIRouter(prefix=PREFIX + '/vulnerabilities', tags=['Vulnerabilities'])
read = allowed('admin','analyst','auditor')

@r.post('', status_code=201)
def create(body: VulnerabilityCreate, user=Depends(allowed('admin'))):
    with connect() as db:
        get_record(db,'assets',body.asset_id)
        fields = body.model_dump()
        fields['created_at'] = now()
        cursor = db.execute(f'INSERT INTO vulnerabilities({",".join(fields)}) VALUES({",".join("?" for _ in fields)})',tuple(fields.values()))
        return get_record(db,'vulnerabilities',cursor.lastrowid)

@r.get('')
def all_records(user=Depends(read), limit: int=Query(100,ge=1,le=500), offset: int=Query(0,ge=0)):
    with connect() as db:
        return [dict(x) for x in db.execute('SELECT * FROM vulnerabilities ORDER BY id LIMIT ? OFFSET ?',(limit,offset))]

@r.get('/search')
def search(cve_identifier: str | None=None, severity: Severity | None=None, asset_id: int | None=Query(None,gt=0), status: VStatus | None=None, user=Depends(read)):
    filters = {k:v for k,v in locals().items() if k!='user' and v is not None}
    where = ' AND '.join(f'{k}=?' for k in filters) or '1=1'
    with connect() as db:
        return [dict(x) for x in db.execute(f'SELECT * FROM vulnerabilities WHERE {where} ORDER BY id',tuple(filters.values()))]

@r.get('/{id}')
def retrieve(id: int, user=Depends(read)):
    with connect() as db:
        return get_record(db,'vulnerabilities',id)

@r.put('/{id}')
def update(id: int, body: VulnerabilityUpdate, user=Depends(allowed('admin','analyst'))):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old = get_record(db,'vulnerabilities',id)
        fields = body.model_dump(exclude_unset=True)
        if 'status' in fields and fields['status'] != old['status']:
            states = ['Open','Under Investigation','In Progress','Resolved','Closed']
            position = states.index(old['status'])
            if position == 4 or fields['status'] != states[position+1]:
                raise HTTPException(409,'Vulnerability must advance one lifecycle step at a time')
            if fields['status']=='Resolved':
                fields['resolution_date'] = now()
        db.execute(f'UPDATE vulnerabilities SET {",".join(k+"=?" for k in fields)} WHERE id=?',(*fields.values(),id))
        return get_record(db,'vulnerabilities',id)

@r.delete('/{id}')
def delete(id: int, user=Depends(allowed('admin'))):
    with connect() as db:
        get_record(db,'vulnerabilities',id)
        db.execute('DELETE FROM vulnerabilities WHERE id=?',(id,))
    return {'message':'Vulnerability deleted'}

app.include_router(r)
