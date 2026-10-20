"""Compose teammates' original scenarios without variable collisions."""
import copy
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MEMBERS=[('h','Hassan Nasrallah','Hassan-Services-1-2-3','Hassan-Local'),
         ('m','Mohammad Nasrallah','Mohammad-Services-4-5-6','Mohammad-Local'),
         ('j','Joseph Awaida','Services-7-8-9','Local')]


def namespace(value,prefix):
    if isinstance(value,dict):
        return {k:namespace(v,prefix) for k,v in value.items()}
    if isinstance(value,list):
        return [namespace(v,prefix) for v in value]
    if isinstance(value,str):
        value=re.sub(r'\{\{([A-Za-z_][\w]*)\}\}',lambda m:'{{'+prefix+'_'+m[1]+'}}',value)
        value=re.sub(r'(pm\.(?:environment|collectionVariables)\.(?:set|get|unset|has)\(\s*)([\'"])([A-Za-z_][\w]*)([\'"])',
                     lambda m:m[1]+m[2]+prefix+'_'+m[3]+m[4],value)
    return value


def build():
    folders=[]; values=[]
    for prefix,student,collection_name,environment_name in MEMBERS:
        original=json.loads((ROOT/'postman'/f'{collection_name}.postman_collection.json').read_text())
        collection=namespace(copy.deepcopy(original),prefix)
        environment=json.loads((ROOT/'postman'/f'{environment_name}.postman_environment.json').read_text())
        for value in environment['values']:
            values.append(value|{'key':prefix+'_'+value['key']})
        for variable in original.get('variable',[]):
            if variable.get('value'):
                values.append({'key':prefix+'_'+variable['key'],'value':variable['value'],'enabled':True})
        for folder in collection['item']:
            for item in folder['item']:
                item['name']=student+' — '+item['name']
                if prefix=='j':
                    item['request']['url']=item['request']['url'].replace('/Joseph-Awaida/auth/login','/Hassan-Nasrallah/users/login')
                if prefix=='m':
                    body=item['request'].get('body',{}).get('raw')
                    if body:
                        body=body.replace('198.51.100.24','198.51.100.{{m_ip_octet}}').replace('malicious-update.test','run-{{m_run_id}}.malicious-update.test').replace('d41d8cd98f00b204e9800998ecf8427e','{{m_sample_hash}}')
                        item['request']['body']['raw']=body
                    for header in item['request'].get('header',[]):
                        if header['key'].lower()=='idempotency-key':
                            header['value']+='-{{m_run_id}}'
        group={'name':student+' — Services '+{'h':'1–3','m':'4–6','j':'7–9'}[prefix],
               'description':'Original teammate scenarios composed for the integrated identity service; runtime variables are isolated per contributor.',
               'item':collection['item']}
        if prefix=='h':
            group['event']=[{'listen':'prerequest','script':{'type':'text/javascript','exec':[
                'if (pm.info.requestName === "Hassan Nasrallah — Login admin") pm.environment.set("h_run_id", Date.now().toString());']}}]
        elif prefix=='m':
            group['event']=[{'listen':'prerequest','script':{'type':'text/javascript','exec':[
                'pm.collectionVariables.set("m_today", new Date().toISOString().slice(0,10));',
                'if (pm.info.requestName === "Mohammad Nasrallah — Login as admin") { const id=Date.now(); pm.environment.set("m_run_id", id.toString()); pm.environment.set("m_ip_octet", (25+id%225).toString()); pm.environment.set("m_sample_hash", id.toString(16).padStart(32,"0")); }']}}]
        folders.append(group)
    document={'info':{'name':'Hassan Nasrallah - Mohammad Nasrallah - Joseph Awaida — All 9 Services',
                     'schema':'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
                     'description':'Run all three member groups in order with scripts.run_team. Includes every member’s original cases, isolated runtime variables, and the real Hassan identity endpoint.'},'item':folders}
    environment={'name':'Team — All 9 Services (enter local demo passwords)','values':values,'_postman_variable_scope':'environment'}
    (ROOT/'postman/Team-All-Services.postman_collection.json').write_text(json.dumps(document,indent=2))
    (ROOT/'postman/Team-Local.postman_environment.json').write_text(json.dumps(environment,indent=2))
    count=sum(len(f['item']) for group in folders for f in group['item'])
    print(f'Combined team collection: {count} real request scenarios.')
    return environment

if __name__=='__main__':
    build()
