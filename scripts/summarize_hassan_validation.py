"""Summarize actual pytest/Newman results without copying their private payloads."""
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from app.auth import now

def main():
    suites = ET.parse('data/hassan-pytest-results.xml').getroot().findall('testsuite')
    newman = json.loads(Path('data/hassan-newman-result.json').read_text())
    integration = json.loads(Path('evidence/hassan/http-integration.json').read_text())
    stats = newman['run']['stats']
    result = {'captured_at':now(),'student':'Hassan Nasrallah',
              'pytest':{key:sum(int(s.get(key,0)) for s in suites) for key in ('tests','failures','errors','skipped')},
              'newman':{key:{'total':stats[key]['total'],'failed':stats[key]['failed']} for key in ('requests','assertions')},
              'http_integration_passed':integration['passed'],
              'commands':[
                  'python -m pytest -q --junitxml=data/hassan-pytest-results.xml',
                  'npx --yes newman run postman/Hassan-Services-1-2-3.postman_collection.json -e data/hassan-newman-local.postman_environment.json --reporters cli,json --reporter-json-export data/hassan-newman-result.json',
                  'python -m scripts.verify_hassan_http'],
              'note':'Actual local execution results. Raw Newman results contain secrets and stay in ignored data/. These results do not replace required Postman desktop screenshots.'}
    assert result['pytest']['failures'] == result['pytest']['errors'] == 0
    assert not newman['run']['failures']
    assert integration['passed']
    Path('evidence/hassan/validation-summary.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
