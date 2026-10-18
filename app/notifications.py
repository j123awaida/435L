from fastapi import APIRouter, Depends, Request, Query
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

@r.post('', status_code=201)
def create(body: NotificationCreate, user=Depends(allowed('admin'))):
    with connect() as db:
        get_record(db,'users',body.user_id)
        fields=body.model_dump()
        fields['created_at']=now()
        cursor=db.execute(f'INSERT INTO notifications({",".join(fields)}) VALUES({",".join("?" for _ in fields)})',tuple(fields.values()))
        return get_record(db,'notifications',cursor.lastrowid)

@r.get('/user/{user_id}')
def by_user(user_id: int, request: Request, user=Depends(read)):
    ownership(user,user_id,request)
    with connect() as db:
        get_record(db,'users',user_id)
        return [dict(x) for x in db.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id',(user_id,))]

@r.get('/search')
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

@r.get('/{id}')
def retrieve(id: int, request: Request, user=Depends(read)):
    with connect() as db:
        record=get_record(db,'notifications',id)
    ownership(user,record['user_id'],request)
    return record

@r.put('/{id}/read')
def mark_read(id: int, request: Request, user=Depends(allowed('admin','analyst','employee'))):
    with connect() as db:
        record=get_record(db,'notifications',id)
    ownership(user,record['user_id'],request)
    with connect() as db:
        db.execute("UPDATE notifications SET status='Read', read_date=COALESCE(read_date,?) WHERE id=?",(now(),id))
        return get_record(db,'notifications',id)

@r.delete('/{id}')
def delete(id: int, user=Depends(allowed('admin'))):
    with connect() as db:
        get_record(db,'notifications',id)
        db.execute('DELETE FROM notifications WHERE id=?',(id,))
    return {'message':'Notification deleted'}

app.include_router(r)
