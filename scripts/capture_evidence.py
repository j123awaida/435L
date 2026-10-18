"""Capture real HTTP execution without storing credentials or bearer tokens."""
import json
import re
from pathlib import Path
from datetime import datetime, timezone
import httpx
from app.db import connect

ROOT=Path('evidence')

def capture():
    collection=json.loads(Path('postman/Services-7-8-9.postman_collection.json').read_text())
    passwords=json.loads(Path('data/demo-credentials.json').read_text())
    variables={'base'+str(p):'http://127.0.0.1:'+str(p) for p in (8000,8007,8008,8009)}
    variables.update({role+'_password':password for role,password in passwords.items()})
    def substitute(value):
        return re.sub(r'\{\{([^}]+)\}\}',lambda m:str(variables[m[1]]),value)
    results=[]
    transitions=[]
    def snapshot(table):
        with connect() as db:
            return [dict(x) for x in db.execute('SELECT * FROM '+table+' ORDER BY id')]

    with httpx.Client(timeout=15) as client:
        for folder in collection['item']:
            for item in folder['item']:
                req=item['request']; url=substitute(req['url'])
                headers={h['key']:substitute(h['value']) for h in req['header']}
                body=json.loads(substitute(req['body']['raw'])) if 'body' in req else None
                table = next((table for resource,table in [('vulnerabilities','vulnerabilities'),('notifications','notifications'),('playbooks','playbooks'),('actions','actions')] if '/'+resource in url), None)
                if '/actions' in url:
                    table = 'actions'
                before = snapshot(table) if table and req['method'] in ('POST','PUT','DELETE') else None
                response=client.request(req['method'],url,headers=headers,json=body)
                if before is not None:
                    transitions.append({'operation':item['name'],'table':table,'http_status':response.status_code,'before':before,'after':snapshot(table)})
                data=response.json()
                script='\n'.join(item['event'][0]['script']['exec'])
                expected=int(re.search(r'to.have.status\((\d+)\)',script)[1])
                for variable,key in re.findall(r'pm.environment.set\("([^"]+)", pm.response.json\(\).(\w+)\)',script):
                    variables[variable]=data[key]
                public_data={k:('[REDACTED]' if k=='access_token' else v) for k,v in data.items()} if isinstance(data,dict) else data
                public_body={k:('[REDACTED]' if k=='password' else v) for k,v in body.items()} if body else None
                results.append({'name':item['name'],'method':req['method'],'url':url,'request_body':public_body,'expected_status':expected,'actual_status':response.status_code,'passed':response.status_code==expected,'response':public_data})
    ROOT.mkdir(exist_ok=True)
    ROOT.joinpath('http-execution.json').write_text(json.dumps({'captured_at':datetime.now(timezone.utc).isoformat(),'source':'Real HTTP calls to local Uvicorn processes; not Postman screenshots','results':results},indent=2))
    with connect() as db:
        snapshot={table:[dict(x) for x in db.execute('SELECT * FROM '+table)] for table in ('assets','vulnerabilities','notifications','playbooks','actions','action_history','audit_logs','notification_outbox','notification_receipts')}
    ROOT.joinpath('database-records.json').write_text(json.dumps(snapshot,indent=2))
    ROOT.joinpath('database-transitions.json').write_text(json.dumps(transitions,indent=2))
    with connect() as db:
        schema = []
        for row in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
            schema.append({'table':row['name'],'create_sql':row['sql'],
                           'columns':[dict(x) for x in db.execute('PRAGMA table_info('+row['name']+')')],
                           'foreign_keys':[dict(x) for x in db.execute('PRAGMA foreign_key_list('+row['name']+')')]})
    ROOT.joinpath('database-schema.json').write_text(json.dumps(schema,indent=2))

    failures=[r['name'] for r in results if not r['passed']]
    ROOT.joinpath('SUMMARY.md').write_text('# Actual local execution (Joseph Awaida)\n\n'+f'{len(results)-len(failures)}/{len(results)} HTTP status checks passed.\n\nExecuted against four real local server processes. Request/response and database records are attached as JSON. Passwords and tokens were redacted. These are API execution records, not Postman screenshots.\n')
    print(f'{len(results)-len(failures)}/{len(results)} real HTTP requests passed.')
    if failures:
        raise SystemExit(str(failures))

if __name__=='__main__':
    capture()
