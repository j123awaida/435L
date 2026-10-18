import hashlib
import time
import pytest
from fastapi.testclient import TestClient
from app import db
from app.auth import hash_password
from app.common import app as identity_app, PREFIX
from app.vulnerabilities import app as vapp
from app.notifications import app as napp
from app.playbooks import app as papp

@pytest.fixture
def clients(tmp_path,monkeypatch):
    monkeypatch.setattr(db,'DB_PATH',str(tmp_path/'test.sqlite3'))
    db.initialize()
    with db.connect() as conn:
        for id,role in enumerate(('admin','analyst','employee','auditor'),1):
            conn.execute('INSERT INTO users(id,full_name,username,password_hash,role) VALUES(?,?,?,?,?)',(id,role,role,hash_password('TestPassword123!'),role))
            conn.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(role.encode()).hexdigest(),id,time.time()+3600))
        conn.execute("INSERT INTO assets VALUES(1,'Server',1)")
    with TestClient(vapp) as v,TestClient(napp) as n,TestClient(papp) as p,TestClient(identity_app) as auth:
        yield v,n,p,auth

def headers(role='admin'):
    return {'Authorization':f'Bearer {role}'}

def test_vulnerability_lifecycle_and_validation(clients):
    v,*_=clients
    path=PREFIX+'/vulnerabilities'
    body={'title':'Server flaw','description':'Investigate','cve_identifier':'CVE-2026-12345','cvss_score':9.2,'severity':'Critical','asset_id':1,'discovery_source':'Scanner'}
    assert v.post(path,json=body).status_code==401
    assert v.post(path,json=body,headers=headers('analyst')).status_code==403
    for change in ({'cvss_score':11},{'severity':'Invalid'},{'cve_identifier':'bad'},{'title':'  '},{'extra':True}):
        assert v.post(path,json=body|change,headers=headers()).status_code==422
    assert v.post(path,json=body|{'asset_id':999},headers=headers()).status_code==404
    created=v.post(path,json=body,headers=headers())
    assert created.status_code==201
    id=created.json()['id']
    assert len(v.get(path+'/search?severity=Critical&asset_id=1',headers=headers('auditor')).json())==1
    assert v.get(path+'/search?cve_identifier=unknown',headers=headers()).json()==[]
    assert v.put(f'{path}/{id}',json={'status':'Closed'},headers=headers()).status_code==409
    for status in ('Under Investigation','In Progress','Resolved','Closed'):
        result=v.put(f'{path}/{id}',json={'status':status},headers=headers('analyst'))
        assert result.status_code==200
    assert result.json()['resolution_date']
    assert v.put(f'{path}/{id}',json={},headers=headers()).status_code==422
    assert v.put(f'{path}/{id}',json={'severity':None},headers=headers()).status_code==422
    assert v.delete(f'{path}/{id}',headers=headers('auditor')).status_code==403
    assert v.delete(f'{path}/{id}',headers=headers()).status_code==200
    assert v.get(f'{path}/{id}',headers=headers()).status_code==404
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action='Permission denied'").fetchone()[0]==2

def test_notification_ownership_and_idempotent_read(clients):
    _,n,*_=clients
    path=PREFIX+'/notifications'
    body={'user_id':3,'title':'Alert','message':'Investigate','notification_type':'Security Alert','severity':'High'}
    id=n.post(path,json=body,headers=headers()).json()['id']
    assert n.get(f'{path}/{id}',headers=headers('analyst')).status_code==403
    assert n.get(path+'/user/3',headers=headers('analyst')).status_code==403
    assert n.get(path+'/user/2',headers=headers('analyst')).json()==[]
    assert n.get(path+'/search',headers=headers('employee')).status_code==403
    assert n.get(path+'/search',headers=headers('analyst')).json()==[]
    assert len(n.get(path+'/search?status=Unread&severity=High',headers=headers('auditor')).json())==1
    assert n.put(f'{path}/{id}/read',headers=headers('auditor')).status_code==403
    first=n.put(f'{path}/{id}/read',headers=headers('employee'))
    second=n.put(f'{path}/{id}/read',headers=headers('employee'))
    assert first.json()['read_date']==second.json()['read_date']
    assert n.delete(f'{path}/{id}',headers=headers('employee')).status_code==403
    assert n.delete(f'{path}/{id}',headers=headers()).status_code==200
    assert n.get(f'{path}/{id}',headers=headers()).status_code==404

def test_playbook_order_history_and_permissions(clients):
    _,_,p,_=clients
    path=PREFIX+'/playbooks'
    body={'name':'Malware','description':'Contain malware','incident_category':'Malware','severity':'High'}
    assert p.post(path,json=body,headers=headers('analyst')).status_code==403
    id=p.post(path,json=body,headers=headers()).json()['id']
    ids=[]
    for step in (1,2):
        response=p.post(f'{path}/{id}/actions',json={'description':f'Step {step}','step_number':step,'assigned_user_id':2},headers=headers('analyst'))
        assert response.status_code==201
        ids.append(response.json()['id'])
    assert p.post(f'{path}/{id}/actions',json={'description':'Duplicate','step_number':1},headers=headers()).status_code==409
    assert p.put(PREFIX+f'/actions/{ids[1]}/status',json={'status':'In Progress'},headers=headers('analyst')).status_code==409
    for action in ids:
        for status in ('In Progress','Completed'):
            result=p.put(PREFIX+f'/actions/{action}/status',json={'status':status},headers=headers('analyst'))
            assert result.status_code==200
        assert result.json()['completion_date']
    assert [a['step_number'] for a in p.get(f'{path}/{id}',headers=headers('auditor')).json()['actions']]==[1,2]
    assert p.get(path,headers=headers('employee')).status_code==403
    assert p.delete(f'{path}/{id}',headers=headers('analyst')).status_code==403
    assert p.delete(f'{path}/{id}',headers=headers()).status_code==200
    with db.connect() as conn:
        assert conn.execute('SELECT COUNT(*) FROM actions').fetchone()[0]==0
        assert conn.execute('SELECT COUNT(*) FROM action_history').fetchone()[0]==6

def test_login_and_inactive_tokens(clients):
    v,n,p,auth=clients
    path=PREFIX+'/auth/login'
    assert auth.post(path,json={'username':'admin','password':'wrong'}).status_code==401
    result=auth.post(path,json={'username':'admin','password':'TestPassword123!'})
    assert result.status_code==200
    token=result.json()['access_token']
    assert v.get(PREFIX+'/vulnerabilities',headers=headers(token)).status_code==200
    with db.connect() as conn:
        conn.execute("UPDATE users SET account_status='Suspended' WHERE id=1")
    assert v.get(PREFIX+'/vulnerabilities',headers=headers(token)).status_code==401
    assert auth.post(path,json={'username':'admin','password':'TestPassword123!'}).status_code==401

@pytest.mark.parametrize('role',['admin','analyst','employee','auditor'])
def test_read_role_matrix(clients,role):
    v,n,p,_=clients
    expected=403 if role=='employee' else 200
    assert v.get(PREFIX+'/vulnerabilities',headers=headers(role)).status_code==expected
    assert p.get(PREFIX+'/playbooks',headers=headers(role)).status_code==expected
    assert n.get(PREFIX+f'/notifications/user/{ {"admin":1,"analyst":2,"employee":3,"auditor":4}[role]}',headers=headers(role)).status_code==200

def test_all_endpoint_permission_denials(clients):
    v,n,p,_=clients
    cases=[
        (v,'post','/vulnerabilities',{'admin'}),
        (v,'get','/vulnerabilities',{'admin','analyst','auditor'}),
        (v,'get','/vulnerabilities/search',{'admin','analyst','auditor'}),
        (v,'get','/vulnerabilities/1',{'admin','analyst','auditor'}),
        (v,'put','/vulnerabilities/1',{'admin','analyst'}),
        (v,'delete','/vulnerabilities/1',{'admin'}),
        (n,'post','/notifications',{'admin'}),
        (n,'get','/notifications/search',{'admin','analyst','auditor'}),
        (n,'put','/notifications/1/read',{'admin','analyst','employee'}),
        (n,'delete','/notifications/1',{'admin'}),
        (p,'post','/playbooks',{'admin'}),
        (p,'get','/playbooks',{'admin','analyst','auditor'}),
        (p,'get','/playbooks/1',{'admin','analyst','auditor'}),
        (p,'post','/playbooks/1/actions',{'admin','analyst'}),
        (p,'put','/actions/1/status',{'admin','analyst'}),
        (p,'delete','/playbooks/1',{'admin'}),
    ]
    for client,method,path,roles in cases:
        for role in {'admin','analyst','employee','auditor'}-roles:
            response=client.request(method,PREFIX+path,headers=headers(role),json={})
            assert response.status_code==403,(method,path,role,response.text)
