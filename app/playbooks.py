from .models import PlaybookRecord, PlaybookDetail, ActionRecord, Message
from fastapi import APIRouter, Depends, HTTPException
from .common import create_app, PREFIX, get_record, assignee
from .db import connect
from .auth import allowed, now
from .models import PlaybookCreate, ActionCreate, ActionUpdate

app=create_app('Service 9: Security Playbook and Response Automation')
r=APIRouter(prefix=PREFIX, tags=['Playbooks and actions'])
read=allowed('admin','analyst','auditor')
write=allowed('admin','analyst')

@r.post('/playbooks',status_code=201, summary='Create response playbook', description='Administrator creates a playbook organized by incident category and severity.', response_model=PlaybookRecord)
def create(body: PlaybookCreate,user=Depends(allowed('admin'))):
    with connect() as db:
        fields=body.model_dump()
        fields.update(created_by=user['id'],created_at=now())
        cursor=db.execute(f'INSERT INTO playbooks({",".join(fields)}) VALUES({",".join("?" for _ in fields)})',tuple(fields.values()))
        return get_record(db,'playbooks',cursor.lastrowid)

@r.get('/playbooks', summary='List response playbooks', description='Administrators, analysts and auditors list available playbooks.', response_model=list[PlaybookRecord])
def all_records(user=Depends(read)):
    with connect() as db:
        return [dict(x) for x in db.execute('SELECT * FROM playbooks ORDER BY id')]

@r.get('/playbooks/{id}', summary='Retrieve response playbook', description='Returns playbook metadata, ordered actions and append-only execution history.', response_model=PlaybookDetail)
def retrieve(id:int,user=Depends(read)):
    with connect() as db:
        record=get_record(db,'playbooks',id)
        record['actions']=[dict(x) for x in db.execute('SELECT * FROM actions WHERE playbook_id=? ORDER BY step_number',(id,))]
        record['execution_history']=[dict(x) for x in db.execute('SELECT * FROM action_history WHERE playbook_id=? ORDER BY id',(id,))]
        return record

@r.post('/playbooks/{id}/actions',status_code=201, summary='Add response action', description='Administrator or analyst adds a unique positive step; new steps cannot precede already started actions.', response_model=ActionRecord)
def add_action(id:int,body:ActionCreate,user=Depends(write)):
    with connect() as db:
        get_record(db,'playbooks',id)
        if db.execute("SELECT id FROM actions WHERE playbook_id=? AND step_number>=? AND status!='Pending'", (id, body.step_number)).fetchone():
            raise HTTPException(409, 'Cannot insert a step before an action that has already started')
        if body.assigned_user_id is not None:
            assignee(db,body.assigned_user_id)
        cursor=db.execute('INSERT INTO actions(playbook_id,description,step_number,assigned_user_id) VALUES(?,?,?,?)',(id,body.description,body.step_number,body.assigned_user_id))
        action=get_record(db,'actions',cursor.lastrowid)
        db.execute('INSERT INTO action_history(action_id,playbook_id,actor_id,new_status,assigned_user_id,recorded_at) VALUES(?,?,?,?,?,?)',(action['id'],id,user['id'],'Pending',body.assigned_user_id,now()))
        return action

@r.put('/actions/{id}/status', summary='Update response action status', description='Administrator or analyst advances Pending to In Progress to Completed. Requires an active qualified assignee and completed earlier steps. Completion time is server-generated.', response_model=ActionRecord)
def update_action(id:int,body:ActionUpdate,user=Depends(write)):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old=get_record(db,'actions',id)
        transitions={'Pending':'In Progress','In Progress':'Completed'}
        if body.status!=old['status'] and transitions.get(old['status'])!=body.status:
            raise HTTPException(409,'Action must progress Pending → In Progress → Completed')
        assigned=body.assigned_user_id if 'assigned_user_id' in body.model_fields_set else old['assigned_user_id']
        if assigned is not None:
            assignee(db,assigned)
        if body.status!='Pending':
            if assigned is None:
                raise HTTPException(422,'Assign an active analyst or administrator before starting')
            earlier=db.execute("SELECT id FROM actions WHERE playbook_id=? AND step_number<? AND status!='Completed'",(old['playbook_id'],old['step_number'])).fetchone()
            if earlier:
                raise HTTPException(409,'Complete earlier response steps first')
        completion=old['completion_date'] or (now() if body.status=='Completed' else None)
        db.execute('UPDATE actions SET status=?,assigned_user_id=?,completion_date=? WHERE id=?',(body.status,assigned,completion,id))
        db.execute('INSERT INTO action_history(action_id,playbook_id,actor_id,old_status,new_status,assigned_user_id,recorded_at) VALUES(?,?,?,?,?,?,?)',(id,old['playbook_id'],user['id'],old['status'],body.status,assigned,now()))
        return get_record(db,'actions',id)

@r.delete('/playbooks/{id}', summary='Delete response playbook', description='Administrator deletes playbook and current actions; immutable execution history survives.', response_model=Message)
def delete(id:int,user=Depends(allowed('admin'))):
    with connect() as db:
        get_record(db,'playbooks',id)
        db.execute('DELETE FROM playbooks WHERE id=?',(id,))
    return {'message':'Playbook and actions deleted; execution history preserved'}

app.include_router(r)
