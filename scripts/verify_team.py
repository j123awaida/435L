"""Capture actual integrated reports, schema, and sanitized Newman execution records."""
import argparse
import json
import sqlite3
from pathlib import Path
from collections import Counter
from datetime import datetime,timezone
import xml.etree.ElementTree as ET
from urllib.parse import urlencode
import httpx

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'evidence/team'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,default=ROOT/'data/team-runtime')
    parser.add_argument('--base-port',type=int,default=18000)
    args=parser.parse_args(); OUT.mkdir(exist_ok=True,parents=True)
    runtime=args.runtime; base=args.base_port
    db=sqlite3.connect(runtime/'data/security.sqlite3');db.row_factory=sqlite3.Row
    passwords=json.loads((runtime/'data/demo-credentials.json').read_text())
    with httpx.Client(timeout=15) as client:
        login=client.post(f'http://127.0.0.1:{base}/Hassan-Nasrallah/users/login',json={'username':'admin','password':passwords['admin']})
        login.raise_for_status();headers={'Authorization':'Bearer '+login.json()['access_token']}
        reports={}
        for kind in ('summary','incidents','assets','threats','vulnerabilities','activity'):
            response=client.get(f'http://127.0.0.1:{base+6}/Mohammad-Nasrallah/reports/{kind}',headers=headers)
            response.raise_for_status();record=response.json()
            assert all(s['origin']=='api' for s in record['sources']),record['sources']
            reports[kind]=record
        counts={table:db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in ('users','assets','incidents','threats','vulnerabilities','audit_logs')}
        assert reports['incidents']['total_incidents']==counts['incidents']
        assert reports['assets']['total_assets']==counts['assets']
        assert reports['threats']['total_threats']==counts['threats']
        assert reports['vulnerabilities']['total_vulnerabilities']==counts['vulnerabilities']
        assert reports['activity']['total_activities']==counts['audit_logs']
        visible_users=db.execute('SELECT COUNT(*) FROM users WHERE id NOT IN (SELECT user_id FROM deleted_users)').fetchone()[0]
        assert reports['summary']['users']==visible_users
        assert reports['summary']['assets']==counts['assets']
        expected_open=db.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('Open','Under Investigation','Mitigated')").fetchone()[0]
        assert reports['summary']['open_incidents']==expected_open
        assert reports['summary']['critical_threats']==db.execute("SELECT COUNT(*) FROM threats WHERE severity='Critical'").fetchone()[0]
        # Prove a real, explicit Service 5 HTTP event is ingested once across retries.
        payload={'user_id':1,'action':'Merged team integration verified','description':'Actual HTTP verification of nine merged services.','severity':'Information','related_service':'Team integration'}
        key='team-verification-'+datetime.now(timezone.utc).isoformat()
        endpoint=f'http://127.0.0.1:{base+5}/Mohammad-Nasrallah/logs'
        first=client.post(endpoint,headers=headers|{'Idempotency-Key':key},json=payload)
        second=client.post(endpoint,headers=headers|{'Idempotency-Key':key},json=payload)
        assert first.status_code==201 and second.status_code==200
        assert first.json()['id']==second.json()['id']
        ingestion={'first_status':first.status_code,'replay_status':second.status_code,'same_log_id':first.json()['id']}
    assert db.execute('PRAGMA foreign_key_check').fetchall()==[]
    schema=[];safe_records={}
    for table in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall():
        name=table['name']
        schema.append({'name':name,'sql':table['sql'],'columns':[dict(x) for x in db.execute('PRAGMA table_info('+name+')')],
                       'foreign_keys':[dict(x) for x in db.execute('PRAGMA foreign_key_list('+name+')')]})
        if name not in ('users','sessions'):
            safe_records[name]=[dict(row) for row in db.execute('SELECT * FROM '+name)]
    safe_records['users']=[dict(row) for row in db.execute('SELECT id,full_name,username,role,account_status FROM users')]
    (OUT/'database-schema.json').write_text(json.dumps(schema,indent=2))
    (OUT/'database-records.json').write_text(json.dumps(safe_records,indent=2))
    (OUT/'http-integration.json').write_text(json.dumps({'captured_at':datetime.now(timezone.utc).isoformat(),'source':'Actual HTTP calls to all nine independent local service processes','validation_port_base':base,'passed':True,'reports':reports,'audit_ingestion':ingestion,'foreign_keys_valid':True},indent=2))
    private=json.loads((runtime/'data/newman-private-report.json').read_text())
    executions=[]
    def clean(value):
        if isinstance(value,dict):
            return {key:('[REDACTED]' if key.lower() in ('password','password_hash','access_token','token_hash','authorization') else clean(v)) for key,v in value.items()}
        if isinstance(value,list):
            return [clean(x) for x in value]
        return value
    for execution in private['run']['executions']:
        response=execution.get('response') or {}
        stream=response.get('stream',{})
        raw=bytes(stream.get('data',[])).decode(errors='replace') if isinstance(stream,dict) else ''
        try: body=clean(json.loads(raw))
        except ValueError: body=raw
        req=execution.get('request',{});url=req.get('url',{})
        if isinstance(url,dict):
            address=(url.get('protocol','http')+'://'+'.'.join(url.get('host',[]))+(':'+str(url['port']) if url.get('port') else '')+'/'+ '/'.join(url.get('path',[])))
            query=[(q['key'],q.get('value','')) for q in url.get('query',[]) if not q.get('disabled')]
            if query:address+='?'+urlencode(query)
        else:address=url
        executions.append({'name':execution['item']['name'],'method':req.get('method'),'url':address,
                           'status':response.get('code'),'response':body,
                           'assertions':[{'name':a.get('assertion'),'passed':not bool(a.get('error'))} for a in execution.get('assertions',[])]})
    (OUT/'http-execution.json').write_text(json.dumps(executions,indent=2))
    stats=private['run']['stats'];suites=ET.parse(OUT/'pytest-results.xml').getroot().findall('testsuite')
    summary={'captured_at':datetime.now(timezone.utc).isoformat(),
             'pytest':{key:sum(int(s.attrib.get(key,0)) for s in suites) for key in ('tests','failures','errors','skipped')},
             'newman':{key:stats[key] for key in ('requests','assertions')},
             'http_integration_passed':True,'report_sources_all_http':True,'foreign_keys_valid':True}
    (OUT/'validation-summary.json').write_text(json.dumps(summary,indent=2))
    assert summary['pytest']['failures']==summary['pytest']['errors']==stats['requests']['failed']==stats['assertions']['failed']==0
    print('Integrated reports match the database; all sources used HTTP. Audit retry and foreign keys passed.')
    print(f'{summary["pytest"]["tests"]} tests; {stats["requests"]["total"]} Newman requests; {stats["assertions"]["total"]} assertions passed.')

if __name__=='__main__':
    main()
