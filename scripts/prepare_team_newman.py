"""Prepare a private integrated environment without publishing credentials."""
import argparse
import json
import re
from pathlib import Path
from scripts.team_collection import build, ROOT


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,default=ROOT)
    parser.add_argument('--base-port',type=int,default=8000)
    args=parser.parse_args()
    environment=build()
    passwords=json.loads((args.runtime/'data/demo-credentials.json').read_text())
    for value in environment['values']:
        key=value['key']
        if key.endswith('_password') and not key.endswith('demo_password'):
            value['value']=passwords[key[2:].removesuffix('_password')]
        if isinstance(value.get('value'),str):
            value['value']=re.sub(r'127\.0\.0\.1:800([0-9])',lambda m:'127.0.0.1:'+str(args.base_port+int(m[1])),value['value'])
    target=args.runtime/'data/team-newman-private.environment.json'
    target.write_text(json.dumps(environment,indent=2));target.chmod(0o600)
    print('Private team environment prepared under ignored data/.')

if __name__=='__main__':
    main()
