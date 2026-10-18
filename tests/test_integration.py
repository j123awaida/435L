import json
import httpx
from app.db import connect
from app.integration import NotificationDelivery
from app.common import PREFIX
from tests.test_services import clients, headers


def test_vulnerability_to_notification_http_retry(clients):
    v, n, _, _ = clients
    body={'title':'Server flaw','description':'Review','cve_identifier':'CVE-2026-12345','cvss_score':9.2,'severity':'Critical','asset_id':1,'discovery_source':'Scanner'}
    result=v.post(PREFIX+'/vulnerabilities',json=body,headers=headers())
    assert result.status_code==201
    with connect() as db:
        assert db.execute('SELECT COUNT(*) FROM notification_outbox').fetchone()[0]==1
    # First HTTP delivery fails. The event must remain pending without losing the vulnerability.
    failing=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(503)))
    delivery=NotificationDelivery(client=failing,endpoint='http://service8'+PREFIX+'/notifications')
    assert delivery.deliver('admin')==0
    with connect() as db:
        event=dict(db.execute('SELECT * FROM notification_outbox').fetchone())
        assert event['status']=='Pending' and event['last_error']=='HTTP 503'
    def route(request):
        response=n.post(PREFIX+'/notifications',json=json.loads(request.content),headers=dict(request.headers))
        return httpx.Response(response.status_code,json=response.json())
    with httpx.Client(transport=httpx.MockTransport(route)) as client:
        delivery=NotificationDelivery(client=client,endpoint='http://service8'+PREFIX+'/notifications')
        assert delivery.deliver('admin')==1
        # Simulate a crash after the remote notification committed but before local acknowledgement.
        with connect() as db:
            db.execute("UPDATE notification_outbox SET status='Pending'")
        assert delivery.deliver('admin')==1
    records=n.get(PREFIX+'/notifications/user/1',headers=headers()).json()
    assert len(records)==1
    assert records[0]['notification_type']=='Vulnerability Alert'
    assert records[0]['severity']=='Critical'
    assert delivery.deliver('admin')==0  # Delivered events do not use the closed HTTP client.


def test_idempotency_key_conflict_and_audit(clients):
    _, n, _, _=clients
    body={'user_id':3,'title':'Alert','message':'Review','notification_type':'Security Alert','severity':'High'}
    hdr=headers()|{'Idempotency-Key':'test-event'}
    first=n.post(PREFIX+'/notifications',json=body,headers=hdr)
    duplicate=n.post(PREFIX+'/notifications',json=body,headers=hdr)
    assert first.status_code==duplicate.status_code==201
    assert first.json()['id']==duplicate.json()['id']
    assert n.post(PREFIX+'/notifications',json=body|{'title':'Different'},headers=hdr).status_code==409
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM audit_logs WHERE action='Data modification'").fetchone()[0]==2


def test_history_retrieval_and_no_inserting_before_started_step(clients):
    _,_,p,_=clients
    playbook=p.post(PREFIX+'/playbooks',json={'name':'Contain','description':'Respond','incident_category':'Malware','severity':'High'},headers=headers()).json()
    path=PREFIX+f'/playbooks/{playbook["id"]}'
    action=p.post(path+'/actions',json={'description':'Isolate','step_number':2,'assigned_user_id':2},headers=headers()).json()
    assert p.put(PREFIX+f'/actions/{action["id"]}/status',json={'status':'In Progress'},headers=headers('analyst')).status_code==200
    assert p.post(path+'/actions',json={'description':'Earlier','step_number':1},headers=headers()).status_code==409
    record=p.get(path,headers=headers('auditor')).json()
    assert len(record['execution_history'])==2
    assert record['execution_history'][-1]['new_status']=='In Progress'
