"""Capture real SQLite-Web and GitHub pages with headless Chrome; no image editing."""
import base64
import json
import os
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import httpx

CHROME=os.getenv('CHROME_PATH','/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
ROOT=Path('evidence/screenshots')


def capture():
    ROOT.mkdir(parents=True,exist_ok=True)
    records=[]
    def shot(name,url,caption):
        output=(ROOT/(name+'.png')).resolve()
        subprocess.run([CHROME,'--headless','--disable-gpu','--no-first-run','--no-default-browser-check',
                        '--user-data-dir=/private/tmp/joseph-assignment-evidence-chrome','--window-size=1800,1400',
                        '--timeout=15000','--screenshot='+str(output),url],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        records.append({'file':str(output.relative_to(Path.cwd())),'url':url,'caption':'Joseph Awaida — '+caption,
                        'captured_at':datetime.now(timezone.utc).isoformat(),'source':'Actual browser rendering, unedited'})
        print('Captured '+name,flush=True)
    def rowurl(table,id):
        key=base64.b64encode(json.dumps([id],separators=(',',':')).encode()).decode()
        return f'http://127.0.0.1:8010/{table}/row/{key}/'
    with httpx.Client(timeout=10) as client:
        assert client.get('http://127.0.0.1:8010/').status_code==200
        shot('database-tables','http://127.0.0.1:8010/','Database tables: the implemented local relational schema.')
        for table in ('vulnerabilities','notifications','playbooks','actions','action_history'):
            shot(table+'-structure',f'http://127.0.0.1:8010/{table}/',table+' structure: actual fields, keys and constraints.')
        passwords=json.loads(Path('data/demo-credentials.json').read_text())
        login=client.post('http://127.0.0.1:8000/Joseph-Awaida/auth/login',json={'username':'admin','password':passwords['admin']})
        login.raise_for_status(); headers={'Authorization':'Bearer '+login.json()['access_token']}
        vbase='http://127.0.0.1:8007/Joseph-Awaida/vulnerabilities'
        created=client.post(vbase,headers=headers,json={'title':'Database screenshot verification','description':'Before remediation review.','cve_identifier':'CVE-2026-45678','cvss_score':7.5,'severity':'High','asset_id':1,'discovery_source':'Local evidence capture'})
        created.raise_for_status(); vid=created.json()['id']
        shot('vulnerability-before',rowurl('vulnerabilities',vid),'Vulnerability before update: Open with no resolution date.')
        for state in ('Under Investigation','In Progress','Resolved'):
            changed=client.put(f'{vbase}/{vid}',headers=headers,json={'status':state,'description':'Remediation progression captured from the running system.'});changed.raise_for_status()
        shot('vulnerability-after',rowurl('vulnerabilities',vid),'Vulnerability after valid lifecycle progression: Resolved with server-recorded resolution date.')
        nbase='http://127.0.0.1:8008/Joseph-Awaida/notifications'
        created=client.post(nbase,headers=headers,json={'user_id':3,'title':'Read-tracking screenshot','message':'Actual before/after evidence.','notification_type':'System Notification','severity':'Low'})
        created.raise_for_status(); nid=created.json()['id']
        shot('notification-before',rowurl('notifications',nid),'Notification before read: Unread with no read date.')
        changed=client.put(f'{nbase}/{nid}/read',headers=headers);changed.raise_for_status()
        shot('notification-after',rowurl('notifications',nid),'Notification after mark-read: Read with its original read timestamp.')
        pbase='http://127.0.0.1:8009/Joseph-Awaida'
        created=client.post(pbase+'/playbooks',headers=headers,json={'name':'Screenshot response workflow','description':'Actual stored response procedure.','incident_category':'Malware','severity':'High'})
        created.raise_for_status(); pid=created.json()['id']
        actions=[]
        for step in (1,2):
            response=client.post(f'{pbase}/playbooks/{pid}/actions',headers=headers,json={'description':['Isolate affected asset','Investigate artifacts'][step-1],'step_number':step,'assigned_user_id':2})
            response.raise_for_status(); actions.append(response.json()['id'])
        shot('playbook-record',rowurl('playbooks',pid),'Stored playbook: category, severity, creator and creation timestamp.')
        shot('action-before',rowurl('actions',actions[0]),'Response action before execution: Pending and assigned to analyst 2.')
        for id in actions:
            for state in ('In Progress','Completed'):
                response=client.put(f'{pbase}/actions/{id}/status',headers=headers,json={'status':state});response.raise_for_status()
        shot('action-after',rowurl('actions',actions[0]),'Response action after ordered execution: Completed with server completion time.')
        from app.db import connect
        with connect() as db:
            hid=db.execute('SELECT MAX(id) FROM action_history WHERE playbook_id=?',(pid,)).fetchone()[0]
        shot('action-history-record',rowurl('action_history',hid),'Execution history: an actual immutable response-action transition and its actor.')
        for table in ('vulnerabilities','notifications','playbooks'):
            shot(table+'-records',f'http://127.0.0.1:8010/{table}/content/',table+' records: actual stored rows from the implementation.')
        shot('github-history','https://github.com/j123awaida/435L/commits/main/','GitHub commit history: genuine contributions in the supplied repository.')
    ROOT.joinpath('browser-manifest.json').write_text(json.dumps(records,indent=2))
    print(f'Captured {len(records)} genuine database/GitHub screenshots.')

if __name__=='__main__':
    capture()
