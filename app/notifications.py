from .models import NotificationRecord, Message
import json
from fastapi import APIRouter, Depends, Request, Query, Header, HTTPException
from .integration import payload_digest
from .common import create_app, PREFIX, get_record
from .db import connect
from .auth import allowed, deny, now
from .models import NotificationCreate, Severity, NType
from typing import Literal

app = create_app('Service 8: Notification and Alert Management')
r = APIRouter(prefix=PREFIX+'/notifications', tags=['Notifications'])
read = allowed('admin','analyst','employee','auditor')

def ownership(user, owner_id, request):
    if user['role'] in ('analyst','employee') and user['id'] != owner_id:
        deny(user,request)

@r.post('', status_code=201, summary='Create notification', description='Administrator or authenticated administrator service session creates a user alert. Optional Idempotency-Key prevents duplicate delivery; payload mismatch returns 409.', response_model=NotificationRecord)
def create(body: NotificationCreate, idempotency_key: str | None = Header(None, min_length=1, max_length=100), user=Depends(allowed('admin'))):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        digest = payload_digest(body.model_dump())
        if idempotency_key:
            receipt = db.execute('SELECT * FROM notification_receipts WHERE event_id=?', (idempotency_key,)).fetchone()
            if receipt:
                if receipt['payload_hash'] != digest:
                    raise HTTPException(409, 'Idempotency key was already used for another notification')
                return json.loads(receipt['response_json'])
        get_record(db,'users',body.user_id)
        fields=body.model_dump()
        fields['created_at']=now()
        cursor=db.execute(f'INSERT INTO notifications({",".join(fields)}) VALUES({",".join("?" for _ in fields)})',tuple(fields.values()))
        record = get_record(db,'notifications',cursor.lastrowid)
        if idempotency_key:
            db.execute('INSERT INTO notification_receipts VALUES(?,?,?)', (idempotency_key, digest, json.dumps(record)))
        return record

@r.get('/user/{user_id}', summary='Retrieve user notifications', description='Analysts and employees may access only their own notifications. Administrators and auditors may read across users. Existing recipients with no alerts return an empty array.', response_model=list[NotificationRecord])
def by_user(user_id: int, request: Request, user=Depends(read)):
    ownership(user,user_id,request)
    with connect() as db:
        get_record(db,'users',user_id)
        return [dict(x) for x in db.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id',(user_id,))]

@r.get('/search', summary='Search notifications', description='Filter by user, type, severity and read status. Analysts are restricted to their own records; employees cannot search.', response_model=list[NotificationRecord])
def search(request: Request, user_id: int | None=Query(None,gt=0), notification_type: NType | None=None, severity: Severity | None=None, status: Literal['Unread','Read'] | None=None, user=Depends(allowed('admin','analyst','auditor'))):
    if user['role']=='analyst':
        if user_id is not None:
            ownership(user,user_id,request)
        user_id=user['id']
    filters={'user_id':user_id,'notification_type':notification_type,'severity':severity,'status':status}
    filters={k:v for k,v in filters.items() if v is not None}
    where=' AND '.join(k+'=?' for k in filters) or '1=1'
    with connect() as db:
        return [dict(x) for x in db.execute(f'SELECT * FROM notifications WHERE {where} ORDER BY id',tuple(filters.values()))]

@r.get('/{id}', summary='Retrieve notification', description='Returns a notification after role and ownership checks, or 404 for an invalid identifier.', response_model=NotificationRecord)
def retrieve(id: int, request: Request, user=Depends(read)):
    with connect() as db:
        record=get_record(db,'notifications',id)
    ownership(user,record['user_id'],request)
    return record

@r.put('/{id}/read', summary='Mark notification read', description='Administrator or owning analyst/employee marks read. Repeated calls preserve the first read timestamp. Auditors cannot mutate.', response_model=NotificationRecord)
def mark_read(id: int, request: Request, user=Depends(allowed('admin','analyst','employee'))):
    with connect() as db:
        record=get_record(db,'notifications',id)
    ownership(user,record['user_id'],request)
    with connect() as db:
        db.execute("UPDATE notifications SET status='Read', read_date=COALESCE(read_date,?) WHERE id=?",(now(),id))
        return get_record(db,'notifications',id)

@r.delete('/{id}', summary='Delete notification', description='Administrator only. Idempotency receipts remain so retries do not recreate deleted alerts.', response_model=Message)
def delete(id: int, user=Depends(allowed('admin'))):
    with connect() as db:
        get_record(db,'notifications',id)
        db.execute('DELETE FROM notifications WHERE id=?',(id,))
    return {'message':'Notification deleted'}

app.include_router(r)
