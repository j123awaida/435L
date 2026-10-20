"""Create an ignored Newman environment with local demo credentials; never print them."""
import json
from pathlib import Path
from scripts.artifacts_hassan import build

def main():
    environment = build()
    credentials = json.loads(Path('data/demo-credentials.json').read_text())
    for value in environment['values']:
        if value['key'].endswith('_password') and value['key'] != 'demo_password':
            value['value'] = credentials[value['key'].removesuffix('_password')]
    target = Path('data/hassan-newman-local.postman_environment.json')
    target.write_text(json.dumps(environment, indent=2))
    target.chmod(0o600)
    print('Private local Newman environment written under ignored data/.')

if __name__ == '__main__':
    main()
