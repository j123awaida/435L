"""Generate Hassan's OpenAPI reference and executable, documented Postman scenarios."""
import json
from pathlib import Path
from app.users import app as users
from app.assets import app as assets
from app.incidents import app as incidents
from app.sprint123_models import PREFIX

def build():
    output = Path('docs/hassan')
    output.mkdir(parents=True, exist_ok=True)
    for number, app in ((1, users), (2, assets), (3, incidents)):
        (output / f'service-{number}.openapi.json').write_text(json.dumps(app.openapi(), indent=2), encoding='utf-8')
    folders = []
    def folder(name):
        items = []
        folders.append({'name': name, 'item': items})
        return items
    def request(items, name, service, method, path, status=200, body=None, role='admin', save=None, checks=()):
        raw = '{{' + service + '_url}}' + PREFIX + path
        headers = [{'key':'Content-Type','value':'application/json'}]
        if role:
            headers.append({'key':'Authorization','value':'Bearer {{' + role + '_token}}'})
        script = [f'pm.test("HTTP {status}", () => pm.response.to.have.status({status}));']
        if save:
            for key, field in save.items():
                script.append(f'if (pm.response.code === {status}) pm.environment.set({json.dumps(key)}, pm.response.json()[{json.dumps(field)}]);')
        script.extend(checks)
        req = {'method': method, 'header': headers, 'url': raw,
               'description': f'Hassan Nasrallah — {name}. Expected HTTP {status}. '
                              + ('Authenticate using the named role token. ' if role else 'Public endpoint. ')
                              + 'Run folders in order against the local development database. Full request/response schemas and errors are documented in docs/hassan/*.openapi.json and /docs on each service.'}
        if body is not None:
            req['body'] = {'mode':'raw','raw':json.dumps(body, indent=2),'options':{'raw':{'language':'json'}}}
        items.append({'name': name, 'request': req, 'event':[{'listen':'test','script':{'type':'text/javascript','exec':script}}]})

    items = folder('1 — Authenticate the four roles')
    for role in ('admin','analyst','employee','auditor'):
        request(items, 'Login ' + role, 'identity', 'POST', '/users/login', body={'username':role,'password':'{{' + role + '_password}}'}, role=None,
                save={role + '_token':'access_token', role + '_id':'user_id'})
    request(items, 'Reject wrong password', 'identity', 'POST', '/users/login', 401, {'username':'admin','password':'wrong'}, role=None)
    request(items, 'Verify session', 'identity', 'GET', '/users/session')

    items = folder('2 — Users and identity management')
    new = {'full_name':'Postman Demo Employee','username':'employee_{{run_id}}','email':'employee_{{run_id}}@example.test','password':'{{demo_password}}','department':'IT','role':'employee'}
    request(items, 'Register employee', 'identity','POST','/users/register',201,new,role=None,save={'new_user_id':'id'})
    request(items, 'Reject duplicate username', 'identity','POST','/users/register',409,new,role=None)
    request(items, 'Reject privileged public registration', 'identity','POST','/users/register',403,new | {'role':'admin'},role=None)
    request(items, 'Reject invalid email', 'identity','POST','/users/register',422,new | {'email':'bad'},role=None)
    request(items, 'Login newly registered employee', 'identity','POST','/users/login',body={'username':'employee_{{run_id}}','password':'{{demo_password}}'},role=None,save={'new_token':'access_token'})
    request(items, 'Update own profile', 'identity','PUT','/users/{{new_user_id}}',body={'full_name':'Updated Employee','department':'Finance'},role='new')
    request(items, 'List users as auditor', 'identity','GET','/users',role='auditor')
    request(items, 'Retrieve own username', 'identity','GET','/users/employee_{{run_id}}',role='new')
    request(items, 'Missing username', 'identity','GET','/users/does-not-exist-{{run_id}}',404)
    request(items, 'Reject analyst user management', 'identity','GET','/users',403,role='analyst')
    request(items, 'Reject unauthorized user deletion', 'identity','DELETE','/users/{{new_user_id}}',403,role='employee')
    request(items, 'View roles and permissions', 'identity','GET','/users/{{new_user_id}}/roles',role='auditor')
    request(items, 'Assign analyst role', 'identity','PUT','/users/{{new_user_id}}/role',body={'role':'analyst'})
    request(items, 'Role change revokes old session', 'identity','GET','/users/session',401,role='new')
    request(items, 'Remove analyst role', 'identity','DELETE','/users/{{new_user_id}}/role')
    request(items, 'Suspend account', 'identity','PUT','/users/{{new_user_id}}/account-status',body={'account_status':'Suspended'})
    request(items, 'Reject suspended login', 'identity','POST','/users/login',401,{'username':'employee_{{run_id}}','password':'{{demo_password}}'},role=None)
    request(items, 'Delete account', 'identity','DELETE','/users/{{new_user_id}}')
    request(items, 'Deleted account is absent', 'identity','GET','/users/employee_{{run_id}}',404)

    items = folder('3 — Asset management')
    asset = {'name':'Server {{run_id}}','asset_type':'Server','ip_address':'192.0.2.50','department':'IT',
             'owner_id':'{{employee_id}}','location':'Lab','criticality':'Critical','status':'Active'}
    request(items,'Create incident asset','assets','POST','/assets',201,asset,save={'asset_id':'id'})
    request(items,'Create temporary workstation','assets','POST','/assets',201,asset | {'name':'Temporary {{run_id}}','asset_type':'Workstation','ip_address':'2001:db8::1','criticality':'Low'},save={'temporary_asset_id':'id'})
    request(items,'Reject invalid IP','assets','POST','/assets',422,asset | {'ip_address':'999.0.0.1'})
    request(items,'Update asset','assets','PUT','/assets/{{asset_id}}',body={'status':'Under Maintenance','criticality':'High'})
    request(items,'List assets','assets','GET','/assets',role='auditor')
    request(items,'Retrieve asset','assets','GET','/assets/{{asset_id}}')
    request(items,'Missing asset','assets','GET','/assets/2147483647',404)
    for query in ('name=Server','asset_type=Server','ip_address=192.0.2.50','department=IT&criticality=High'):
        request(items,'Search ' + query,'assets','GET','/assets/search?' + query,role='analyst')
    request(items,'View asset history','assets','GET','/assets/{{asset_id}}/history',role='auditor')
    request(items,'Reject employee asset access','assets','GET','/assets',403,role='employee')
    request(items,'Reject analyst asset deletion','assets','DELETE','/assets/{{temporary_asset_id}}',403,role='analyst')
    request(items,'Delete unused asset','assets','DELETE','/assets/{{temporary_asset_id}}')

    items = folder('4 — Incident lifecycle and ownership')
    incident = {'title':'Suspicious login {{run_id}}','description':'Review access logs','category':'Unauthorized access',
                'severity':'High','reporter_id':'{{employee_id}}','asset_id':'{{asset_id}}'}
    request(items,'Report incident','incidents','POST','/incidents',201,incident,role='employee',save={'incident_id':'id'})
    request(items,'Reject invalid severity','incidents','POST','/incidents',422,incident | {'severity':'Extreme'},role='employee')
    request(items,'List all incidents','incidents','GET','/incidents',role='auditor')
    request(items,'Track submitted incident','incidents','GET','/incidents/{{incident_id}}',role='employee')
    request(items,'Missing incident','incidents','GET','/incidents/2147483647',404)
    request(items,'Reject unassigned analyst access','incidents','GET','/incidents/{{incident_id}}',403,role='analyst')
    request(items,'Reject employee assignment','incidents','PUT','/incidents/{{incident_id}}/assign',403,{'analyst_id':'{{analyst_id}}'},role='employee')
    request(items,'Reject non-analyst assignee','incidents','PUT','/incidents/{{incident_id}}/assign',422,{'analyst_id':'{{employee_id}}'})
    request(items,'Assign incident','incidents','PUT','/incidents/{{incident_id}}/assign',body={'analyst_id':'{{analyst_id}}'})
    request(items,'List assigned incidents','incidents','GET','/incidents',role='analyst')
    request(items,'Retrieve related asset as analyst','assets','GET','/assets/{{asset_id}}',role='analyst')
    request(items,'Reject skipped lifecycle','incidents','PUT','/incidents/{{incident_id}}/status',409,{'status':'Closed'},role='analyst')
    request(items,'Add investigation note','incidents','POST','/incidents/{{incident_id}}/notes',201,{'content':'Reviewed authentication logs; isolated affected host.'},role='analyst')
    request(items,'Read investigation notes','incidents','GET','/incidents/{{incident_id}}',role='analyst',checks=['pm.test("Investigation note persisted", () => pm.expect(pm.response.json().investigation_notes.length).to.be.above(0));'])
    for status in ('Under Investigation','Mitigated','Resolved','Closed'):
        request(items,'Advance to ' + status,'incidents','PUT','/incidents/{{incident_id}}/status',body={'status':status},role='analyst')
    request(items,'Reject backward transition','incidents','PUT','/incidents/{{incident_id}}/status',409,{'status':'Open'},role='analyst')
    request(items,'Preserve asset referenced by incident','assets','DELETE','/assets/{{asset_id}}',409)
    request(items,'Logout administrator','identity','POST','/users/logout')
    request(items,'Reject revoked token','identity','GET','/users/session',401)

    # Strict integer fields require numeric JSON after Postman substitutes ID variables.
    for f in folders:
        for item in f['item']:
            raw = item['request'].get('body', {}).get('raw')
            if raw:
                for key in ('employee_id','analyst_id','asset_id'):
                    raw = raw.replace('"{{' + key + '}}"', '{{' + key + '}}')
                item['request']['body']['raw'] = raw
    collection = {'info':{'name':'Hassan Nasrallah — Services 1–3','schema':'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
                          'description':'Run folders in order after scripts.seed_hassan and scripts.run_hassan. Requests execute real APIs and retain demonstration incidents/assets. See docs/HASSAN-SPRINT1.md.'},
                  'event':[{'listen':'prerequest','script':{'type':'text/javascript','exec':[
                      'if (pm.info.requestName === "Login admin") pm.environment.set("run_id", Date.now().toString());']}}], 'item':folders}
    values = {'identity_url':'http://127.0.0.1:8000','assets_url':'http://127.0.0.1:8002','incidents_url':'http://127.0.0.1:8003',
              'demo_password':'PostmanDemo123!'} | {role + '_password':'' for role in ('admin','analyst','employee','auditor')}
    environment = {'name':'Hassan Nasrallah — Local (fill passwords from data/demo-credentials.json)',
                   'values':[{'key':k,'value':v,'enabled':True,'type':'secret' if 'password' in k else 'default'} for k,v in values.items()], '_postman_variable_scope':'environment'}
    postman = Path('postman')
    (postman / 'Hassan-Services-1-2-3.postman_collection.json').write_text(json.dumps(collection, indent=2), encoding='utf-8')
    (postman / 'Hassan-Local.postman_environment.json').write_text(json.dumps(environment, indent=2), encoding='utf-8')
    return environment

if __name__ == '__main__':
    build()
