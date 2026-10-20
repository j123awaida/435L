"""Record real HTTP integration of Services 1–3 with Joseph's Services 7 and 8.

Run scripts.run_hassan --with-joseph first. Retains actual demonstration records;
never writes credentials, Authorization headers, or login tokens to evidence.
"""
import json
from pathlib import Path
import httpx
from app.auth import now
from app.db import connect
from app.integration import NotificationDelivery
from app.sprint123_models import PREFIX

def main():
    passwords = json.loads(Path('data/demo-credentials.json').read_text())
    identity = 'http://127.0.0.1:8000' + PREFIX
    assets = 'http://127.0.0.1:8002' + PREFIX
    incidents = 'http://127.0.0.1:8003' + PREFIX
    notifications = 'http://127.0.0.1:8008/Joseph-Awaida/notifications'
    checks = []
    with httpx.Client(timeout=15) as client:
        def login(role):
            response = client.post(identity + '/users/login', json={'username':role, 'password':passwords[role]})
            response.raise_for_status()
            return response.json()
        admin, employee, analyst = (login(role) for role in ('admin','employee','analyst'))
        admin_headers = {'Authorization':'Bearer ' + admin['access_token']}
        employee_headers = {'Authorization':'Bearer ' + employee['access_token']}
        analyst_headers = {'Authorization':'Bearer ' + analyst['access_token']}
        response = client.post(assets + '/assets', headers=admin_headers, json={
            'name':'HTTP integration host', 'asset_type':'Server','ip_address':'192.0.2.77',
            'department':'IT','owner_id':employee['user_id'],'location':'Lab','criticality':'High'})
        assert response.status_code == 201, response.text
        asset = response.json()
        response = client.post(incidents + '/incidents', headers=employee_headers, json={
            'title':'HTTP assignment integration','description':'Verify actual incident assignment alert delivery',
            'category':'Unauthorized access','severity':'High','reporter_id':employee['user_id'],'asset_id':asset['id']})
        assert response.status_code == 201, response.text
        incident = response.json()
        response = client.put(incidents + f'/incidents/{incident["id"]}/assign', headers=admin_headers, json={'analyst_id':analyst['user_id']})
        assert response.status_code == 200, response.text
        incident = response.json()
        checks.append('Real HTTP asset creation, employee report and administrator assignment')
        with connect() as db:
            events = [dict(row) for row in db.execute('SELECT * FROM notification_outbox')]
        event = next(row for row in events if json.loads(row['payload_json'])['message'].startswith(f'Investigate incident {incident["id"]}:'))
        delivery = NotificationDelivery(endpoint=notifications)
        try:
            delivery.deliver(admin['access_token'])
        finally:
            delivery.close()
        payload = json.loads(event['payload_json'])
        hdr = admin_headers | {'Idempotency-Key':event['event_id']}
        first = client.post(notifications, headers=hdr, json=payload)
        second = client.post(notifications, headers=hdr, json=payload)
        assert first.status_code == second.status_code == 201
        assert first.json()['id'] == second.json()['id']
        response = client.get(notifications + f'/user/{analyst["user_id"]}', headers=analyst_headers)
        assert response.status_code == 200
        assert sum(row['id'] == first.json()['id'] for row in response.json()) == 1
        checks.append('Real Service 3 → Service 8 HTTP notification delivery and idempotent retry')
        response = client.get('http://127.0.0.1:8007/Joseph-Awaida/vulnerabilities', headers=admin_headers)
        assert response.status_code == 200
        checks.append('Service 1 bearer token accepted by unmodified Service 7')
        with connect() as db:
            state = db.execute('SELECT status FROM notification_outbox WHERE event_id=?', (event['event_id'],)).fetchone()[0]
            assert state == 'Delivered'
            assert db.execute('PRAGMA foreign_key_check').fetchall() == []
        checks.append('Durable delivered event and valid database foreign keys')
    target = Path('evidence/hassan')
    target.mkdir(parents=True, exist_ok=True)
    (target / 'http-integration.json').write_text(json.dumps({
        'captured_at':now(),'student':'Hassan Nasrallah','source':'Real HTTP calls to independently running local services',
        'passed':True,'checks':checks,'asset':asset,'incident':incident,
        'notification':first.json(),'duplicate_status':second.status_code,
        'duplicate_notification_id':second.json()['id'],'outbox_status':state,
    }, indent=2), encoding='utf-8')
    print('Real Services 1–3 / 7–8 HTTP integration passed; sanitized evidence saved.')

if __name__ == '__main__':
    main()
