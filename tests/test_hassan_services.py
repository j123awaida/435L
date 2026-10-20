"""Behavioral and integration coverage for Hassan Nasrallah's Services 1–3."""
import hashlib
import json
import sqlite3
import time
from contextlib import ExitStack
from pathlib import Path
import httpx
import pytest
from fastapi.testclient import TestClient
from app import db
from app.auth import hash_password, now, verify_password
from app.users import app as users_app
from app.assets import app as assets_app
from app.incidents import app as incidents_app
from app.notifications import app as notifications_app
from app.vulnerabilities import app as vulnerabilities_app
from app.integration import NotificationDelivery
from app.sprint123_models import PREFIX as P

PASSWORD = 'CorrectPassword123!'

def headers(role='admin'):
    return {'Authorization': 'Bearer ' + role}

@pytest.fixture(scope='module')
def encoded_password():
    return hash_password(PASSWORD)

@pytest.fixture
def clients(tmp_path, monkeypatch, encoded_password):
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'services.sqlite3'))
    db.initialize()
    with db.connect() as conn:
        for id, username, role in [(1,'admin','admin'), (2,'analyst','analyst'), (3,'employee','employee'),
                                   (4,'auditor','auditor'), (5,'analyst2','analyst'), (6,'employee2','employee')]:
            conn.execute('INSERT INTO users(id,full_name,username,password_hash,role) VALUES(?,?,?,?,?)', (id, username, username, encoded_password, role))
            conn.execute('INSERT INTO user_profiles VALUES(?,?,?,?,?)', (id, username + '@example.test', 'Security', now(), None))
            conn.execute('INSERT INTO sessions VALUES(?,?,?)', (hashlib.sha256(username.encode()).hexdigest(), id, time.time() + 3600))
    with ExitStack() as stack:
        yield tuple(stack.enter_context(TestClient(app)) for app in (users_app, assets_app, incidents_app, notifications_app, vulnerabilities_app))

def registration(**changes):
    return {'full_name': 'Sample Employee', 'username': 'new.employee', 'email': 'new@example.test',
            'password': PASSWORD, 'department': 'IT', 'role': 'employee'} | changes

def asset(**changes):
    return {'name': 'Incident server', 'asset_type': 'Server', 'ip_address': '192.0.2.10',
            'department': 'IT', 'owner_id': 3, 'location': 'Lab', 'criticality': 'High'} | changes

def make_incident(clients, **changes):
    _, a, i, *_ = clients
    asset_id = a.post(P + '/assets', json=asset(), headers=headers()).json()['id']
    result = i.post(P + '/incidents', json={'title': 'Suspicious login', 'description': 'Review access logs',
                    'category': 'Unauthorized access', 'severity': 'High', 'reporter_id': 3, 'asset_id': asset_id} | changes, headers=headers('employee'))
    assert result.status_code == 201, result.text
    return result.json()

def test_registration_login_hash_email_and_duplicates(clients):
    u, *rest = clients
    response = u.post(P + '/users/register', json=registration())
    assert response.status_code == 201, response.text
    record = response.json()
    assert 'password' not in record and 'password_hash' not in record
    with db.connect() as conn:
        stored = conn.execute('SELECT password_hash FROM users WHERE id=?', (record['id'],)).fetchone()[0]
        assert stored != PASSWORD and verify_password(PASSWORD, stored)
    assert u.post(P + '/users/register', json=registration()).status_code == 409
    assert u.post(P + '/users/register', json=registration(username='different', email='NEW@EXAMPLE.TEST')).status_code == 409
    assert u.post(P + '/users/login', json={'username':'new@example.test', 'password':PASSWORD}).status_code == 200
    result = u.post(P + '/users/login', json={'username':'new.employee', 'password':PASSWORD})
    token = result.json()['access_token']
    assert u.get(P + '/users/session', headers=headers(token)).json()['last_login_at']
    assert u.post(P + '/users/login', json={'username':'new.employee', 'password':'wrong'}).status_code == 401
    assert u.post(P + '/users/logout', headers=headers(token)).status_code == 200
    assert u.get(P + '/users/session', headers=headers(token)).status_code == 401

@pytest.mark.parametrize('change', [{'email':'bad'}, {'full_name':' '}, {'password':'short'}, {'password':'abcdefghijkl'}, {'username':'bad/user'}, {'username':'session'}, {'extra':True}, {'role':'root'}])
def test_registration_validation(clients, change):
    u, *_ = clients
    assert u.post(P + '/users/register', json=registration(**change)).status_code == 422

def test_registration_privilege_and_user_ownership(clients):
    u, *_ = clients
    for role in ('admin', 'analyst', 'auditor'):
        assert u.post(P + '/users/register', json=registration(role=role)).status_code == 403
    assert u.post(P + '/users/register', json=registration(), headers=headers('analyst')).status_code == 403
    result = u.post(P + '/users/register', json=registration(role='analyst'), headers=headers())
    assert result.status_code == 201
    assert u.get(P + '/users/employee', headers=headers('employee')).status_code == 200
    assert u.get(P + '/users/admin', headers=headers('employee')).status_code == 403
    assert u.put(P + '/users/1', json={'full_name':'Changed'}, headers=headers('employee')).status_code == 403
    assert u.put(P + '/users/3', json={'email':'updated@example.test','department':'HR'}, headers=headers('employee')).status_code == 200
    assert u.put(P + '/users/3', json={'role':'admin'}, headers=headers('employee')).status_code == 422
    assert u.put(P + '/users/3', json={}, headers=headers()).status_code == 422
    assert u.get(P + '/users/missing', headers=headers()).status_code == 404
    assert u.get(P + '/users/3/roles', headers=headers('auditor')).json()['role'] == 'employee'

def test_account_status_role_and_deletion_preserve_audit(clients):
    u, *_ = clients
    assert u.put(P + '/users/1/account-status', json={'account_status':'Suspended'}, headers=headers()).status_code == 409
    assert u.put(P + '/users/1/role', json={'role':'employee'}, headers=headers()).status_code == 409
    for status in ('Inactive', 'Suspended'):
        assert u.put(P + '/users/3/account-status', json={'account_status':status}, headers=headers()).status_code == 200
        assert u.get(P + '/users/session', headers=headers('employee')).status_code == 401
        assert u.post(P + '/users/login', json={'username':'employee','password':PASSWORD}).status_code == 401
    assert u.put(P + '/users/3/account-status', json={'account_status':'Active'}, headers=headers()).status_code == 200
    login = u.post(P + '/users/login', json={'username':'employee','password':PASSWORD}).json()
    assert u.put(P + '/users/3/role', json={'role':'analyst'}, headers=headers()).status_code == 200
    assert u.get(P + '/users/session', headers=headers(login['access_token'])).status_code == 401
    assert u.delete(P + '/users/3/role', headers=headers()).json()['role'] == 'employee'
    assert u.delete(P + '/users/3', headers=headers()).status_code == 200
    assert u.get(P + '/users/employee', headers=headers()).status_code == 404
    assert all(record['id'] != 3 for record in u.get(P + '/users', headers=headers()).json())
    assert u.put(P + '/users/3/account-status', json={'account_status':'Active'}, headers=headers()).status_code == 404
    assert u.delete(P + '/users/3', headers=headers()).status_code == 404
    assert u.delete(P + '/users/1', headers=headers()).status_code == 409
    with db.connect() as conn:
        assert conn.execute('SELECT COUNT(*) FROM audit_logs WHERE user_id=3').fetchone()[0] > 0
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []

def test_assets_search_history_relationships_and_delete(clients):
    _, a, *_ = clients
    response = a.post(P + '/assets', json=asset(), headers=headers())
    assert response.status_code == 201, response.text
    id = response.json()['id']
    assert a.get(P + '/assets/search?name=server&department=IT&criticality=High&asset_type=Server&ip_address=192.0.2.10', headers=headers('analyst')).json()[0]['id'] == id
    assert a.get(P + '/assets/search?name=%27%20OR%201=1--', headers=headers()).json() == []
    assert a.get(P + '/assets/search?ip_address=bad', headers=headers()).status_code == 422
    assert a.get(P + f'/assets/{id}', headers=headers('analyst')).status_code == 403
    assert a.get(P + f'/assets/{id}', headers=headers('auditor')).json()['incident_ids'] == []
    assert a.put(P + f'/assets/{id}', json={'status':'Under Maintenance','criticality':'Critical'}, headers=headers()).status_code == 200
    history = a.get(P + f'/assets/{id}/history', headers=headers()).json()
    assert len(history) == 3 and history[-1]['snapshot']['status'] == 'Under Maintenance'
    with db.connect() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE asset_history SET action='edited'")
    assert a.delete(P + f'/assets/{id}', headers=headers()).status_code == 200
    assert a.get(P + f'/assets/{id}', headers=headers()).status_code == 404
    assert a.get(P + f'/assets/{id}/history', headers=headers()).json()[-1]['action'] == 'Deleted'
    replacement = a.post(P + '/assets', json=asset(), headers=headers()).json()
    assert replacement['id'] != id
    assert len(a.get(P + f'/assets/{replacement["id"]}/history', headers=headers()).json()) == 1

@pytest.mark.parametrize('change', [{'ip_address':'300.1.1.1'}, {'criticality':'Extreme'}, {'asset_type':'Unknown'}, {'status':'Broken'}, {'name':' '}, {'owner_id':True}, {'owner_id':999}])
def test_asset_validation(clients, change):
    _, a, *_ = clients
    assert a.post(P + '/assets', json=asset(**change), headers=headers()).status_code == (404 if change == {'owner_id':999} else 422)

def test_incident_lifecycle_ownership_assignment_and_notifications(clients):
    u, a, i, n, v = clients
    incident = make_incident(clients)
    id = incident['id']
    path = P + f'/incidents/{id}'
    assert i.get(path, headers=headers('employee2')).status_code == 403
    assert i.get(path, headers=headers('analyst')).status_code == 403
    assert i.get(P + '/incidents', headers=headers('analyst')).json() == []
    assert len(i.get(P + '/incidents', headers=headers('employee')).json()) == 1
    assert i.put(path + '/assign', json={'analyst_id':3}, headers=headers()).status_code == 422
    assert i.put(path + '/assign', json={'analyst_id':2}, headers=headers('analyst')).status_code == 403
    assert i.put(path + '/assign', json={'analyst_id':2}, headers=headers()).status_code == 200
    assert i.put(path + '/assign', json={'analyst_id':2}, headers=headers()).status_code == 200
    assert len(i.get(P + '/incidents', headers=headers('analyst')).json()) == 1
    assert a.get(P + f'/assets/{incident["asset_id"]}', headers=headers('analyst')).json()['incident_ids'] == [id]
    assert u.put(P + '/users/2/role', json={'role':'employee'}, headers=headers()).status_code == 409
    assert u.delete(P + '/users/2', headers=headers()).status_code == 409
    assert i.put(path + '/status', json={'status':'Closed'}, headers=headers('analyst')).status_code == 409
    assert i.put(path + '/status', json={'status':'Under Investigation'}, headers=headers('analyst2')).status_code == 403
    assert i.post(path + '/notes', json={'content':'Private evidence'}, headers=headers('analyst')).status_code == 201
    assert i.get(path, headers=headers('employee')).json()['investigation_notes'] == []
    assert i.get(path, headers=headers('auditor')).json()['investigation_notes'][0]['analyst_id'] == 2
    resolution = None
    for status in ('Under Investigation','Mitigated','Resolved','Closed'):
        response = i.put(path + '/status', json={'status':status}, headers=headers('analyst'))
        assert response.status_code == 200, response.text
        if status == 'Resolved':
            resolution = response.json()['resolution_date']
        if status == 'Closed':
            assert response.json()['resolution_date'] == resolution
    assert i.put(path + '/status', json={'status':'Open'}, headers=headers()).status_code == 409
    assert i.post(path + '/notes', json={'content':'Late'}, headers=headers()).status_code == 409
    assert a.delete(P + f'/assets/{incident["asset_id"]}', headers=headers()).status_code == 409
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action='Incident assigned'").fetchone()[0] == 1
        assert conn.execute('SELECT COUNT(*) FROM notification_outbox').fetchone()[0] == 1
    def deliver(request):
        response = n.post('/Joseph-Awaida/notifications', json=json.loads(request.content), headers=dict(request.headers))
        return httpx.Response(response.status_code, json=response.json())
    with httpx.Client(transport=httpx.MockTransport(deliver)) as client:
        delivery = NotificationDelivery(client=client)
        assert delivery.deliver('admin') == 1
        with db.connect() as conn:
            conn.execute("UPDATE notification_outbox SET status='Pending'")
        assert delivery.deliver('admin') == 1
    notices = n.get('/Joseph-Awaida/notifications/user/2', headers=headers('analyst')).json()
    assert len(notices) == 1 and notices[0]['notification_type'] == 'Incident Assignment'
    # A Service 1 issued token authenticates Joseph's unmodified Service 7.
    token = u.post(P + '/users/login', json={'username':'admin', 'password':PASSWORD}).json()['access_token']
    assert v.get('/Joseph-Awaida/vulnerabilities', headers=headers(token)).status_code == 200

def test_incident_input_and_nonexistent_records(clients):
    _, a, i, *_ = clients
    incident = make_incident(clients)
    body = {'title':'Report','description':'Review','category':'Malware','severity':'High','reporter_id':3,'asset_id':incident['asset_id']}
    for changes in ({'severity':'Extreme'}, {'title':' '}, {'assigned_analyst_id':2}, {'status':'Closed'}):
        assert i.post(P + '/incidents', json=body | changes, headers=headers('employee')).status_code == 422
    assert i.post(P + '/incidents', json=body | {'reporter_id':6}, headers=headers('employee')).status_code == 403
    assert i.post(P + '/incidents', json=body | {'asset_id':999}, headers=headers('employee')).status_code == 404
    assert i.get(P + '/incidents/999', headers=headers()).status_code == 404
    assert a.get(P + '/assets/999', headers=headers()).status_code == 404
    assert i.post(P + f'/incidents/{incident["id"]}/notes', json={'content':' '}, headers=headers()).status_code == 422

@pytest.mark.parametrize('role', ['admin','analyst','employee','auditor'])
def test_role_matrix_and_denials_are_audited(clients, role):
    u, a, i, *_ = clients
    cases = [(u,'get','/users', {'admin','auditor'}), (u,'put','/users/3/role', {'admin'}),
             (u,'delete','/users/3', {'admin'}), (a,'post','/assets', {'admin'}),
             (a,'get','/assets', {'admin','auditor'}), (a,'get','/assets/search', {'admin','analyst','auditor'}),
             (a,'put','/assets/999', {'admin'}), (a,'delete','/assets/999', {'admin'}),
             (i,'post','/incidents', {'admin','employee'}), (i,'put','/incidents/999/assign', {'admin'}),
             (i,'put','/incidents/999/status', {'admin','analyst'}), (i,'post','/incidents/999/notes', {'admin','analyst'})]
    expected = 0
    for client, method, path, roles in cases:
        response = client.request(method, P + path, headers=headers(role), json={})
        if role not in roles:
            expected += 1
            assert response.status_code == 403, (role, method, path, response.text)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action='Permission denied'").fetchone()[0] == expected
    assert u.get(P + '/users').status_code == 401
    assert a.get(P + '/assets', headers=headers('invalid')).status_code == 401
    with db.connect() as conn:
        conn.execute('UPDATE sessions SET expires_at=0')
    assert u.get(P + '/users/session', headers=headers()).status_code == 401

def test_legacy_database_remains_compatible_and_initialization_idempotent(clients):
    u, a, *_ = clients
    with db.connect() as conn:
        conn.execute("INSERT INTO assets VALUES(20,'Legacy reference server',1)")
    db.initialize()
    assert a.get(P + '/assets/20', headers=headers()).json()['asset_type'] is None
    assert a.put(P + '/assets/20', json={'name':'New name'}, headers=headers()).status_code == 422
    assert a.put(P + '/assets/20', json=asset(), headers=headers()).status_code == 200
    assert a.get(P + '/assets/20', headers=headers()).json()['criticality'] == 'High'

def test_password_whitespace_is_preserved(clients):
    u, *_ = clients
    password = ' ' + PASSWORD + ' '
    assert u.post(P + '/users/register', json=registration(password=password)).status_code == 201
    assert u.post(P + '/users/login', json={'username':'new.employee','password':password}).status_code == 200
    assert u.post(P + '/users/login', json={'username':'new.employee','password':password.strip()}).status_code == 401

def test_seed_preserves_credentials_and_handles_deleted_demo_identity(clients, tmp_path, monkeypatch):
    from scripts.seed_hassan import main
    u, *_ = clients
    monkeypatch.chdir(tmp_path)
    Path('data').mkdir()
    Path('data/demo-credentials.json').write_text(json.dumps({'admin':PASSWORD}))
    assert u.delete(P + '/users/3', headers=headers()).status_code == 200
    main()
    main()
    credentials = json.loads(Path('data/demo-credentials.json').read_text())
    assert credentials['admin'] == PASSWORD
    login = u.post(P + '/users/login', json={'username':'employee','password':credentials['employee']})
    assert login.status_code == 200 and login.json()['user_id'] != 3
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE username='employee'").fetchone()[0] == 1
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
