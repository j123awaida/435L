import json
from pathlib import Path

environment=json.loads(Path('postman/Local.postman_environment.json').read_text())
passwords=json.loads(Path('data/demo-credentials.json').read_text())
for entry in environment['values']:
    if entry['key'].endswith('_password'):
        entry['value']=passwords[entry['key'].removesuffix('_password')]
path=Path('data/newman-local.postman_environment.json')
path.write_text(json.dumps(environment))
path.chmod(0o600)
print('Prepared ignored local Newman environment; credentials were not printed.')
