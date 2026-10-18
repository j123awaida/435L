"""Verify real HTTP delivery and idempotency against running local services."""
import json
from pathlib import Path
import httpx
from app.integration import NotificationDelivery
from app.db import connect
from app.auth import now


def verify():
    passwords=json.loads(Path('data/demo-credentials.json').read_text())
    prefix='/Joseph-Awaida'
    with httpx.Client(timeout=10) as client:
        login=client.post('http://127.0.0.1:8000'+prefix+'/auth/login',json={'username':'admin','password':passwords['admin']})
        login.raise_for_status()
        token=login.json()['access_token']
        headers={'Authorization':'Bearer '+token}
        created=client.post('http://127.0.0.1:8007'+prefix+'/vulnerabilities',headers=headers,json={
            'title':'HTTP integration verification','description':'Verify actual Service 7 to Service 8 communication.',
            'cve_identifier':'CVE-2026-34567','cvss_score':8.5,'severity':'High','asset_id':1,'discovery_source':'Local verification'})
        assert created.status_code==201,created.text
        vulnerability=created.json()
        with connect() as db:
            events=[dict(x) for x in db.execute('SELECT * FROM notification_outbox ORDER BY created_at DESC')]
            event=next(e for e in events if f"{vulnerability['cve_identifier']} affects asset" in json.loads(e['payload_json'])['message'] and json.loads(e['payload_json'])['title']=='Vulnerability discovered: HTTP integration verification')
        delivery=NotificationDelivery()
        try:
            delivery.deliver(token)
        finally:
            delivery.close()
        body=json.loads(event['payload_json'])
        hdr=headers|{'Idempotency-Key':event['event_id']}
        first=client.post('http://127.0.0.1:8008'+prefix+'/notifications',headers=hdr,json=body)
        second=client.post('http://127.0.0.1:8008'+prefix+'/notifications',headers=hdr,json=body)
        assert first.status_code==second.status_code==201
        assert first.json()['id']==second.json()['id']
        result=client.get('http://127.0.0.1:8008'+prefix+'/notifications/user/1',headers=headers)
        assert result.status_code==200
        assert len([x for x in result.json() if x['id']==first.json()['id']])==1
        with connect() as db:
            saved=dict(db.execute('SELECT * FROM notification_outbox WHERE event_id=?',(event['event_id'],)).fetchone())
        assert saved['status']=='Delivered'
    output={'captured_at':now(),'source':'Real HTTP calls to independently running Services 7 and 8',
            'vulnerability':vulnerability,'outbox_event':saved,'notification':first.json(),
            'duplicate_http_status':second.status_code,'duplicate_notification_id':second.json()['id'],
            'passed':True}
    Path('evidence/http-integration.json').write_text(json.dumps(output,indent=2))
    print('Real Service 7 -> Service 8 HTTP alert delivery and duplicate protection passed.')

if __name__=='__main__':
    verify()
