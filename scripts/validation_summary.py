"""Summarize actual test runner artifacts without publishing Newman secrets."""
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def summarize():
    newman = json.loads(Path('data/newman-private-report.json').read_text())
    stats = newman['run']['stats']
    suites = ET.parse('evidence/pytest-results.xml').getroot().findall('testsuite')
    summary = {
        'pytest': {key:sum(int(s.attrib.get(key,0)) for s in suites) for key in ('tests','failures','errors','skipped')},
        'newman': {key:{'total':stats[key]['total'],'failed':stats[key]['failed']} for key in ('requests','assertions')},
        'http_scenarios': len(json.loads(Path('evidence/http-execution.json').read_text())['results']),
    }
    Path('evidence/validation-summary.json').write_text(json.dumps(summary,indent=2))
    Path('evidence/SUMMARY.md').write_text(
        '# Actual execution — Joseph Awaida\n\n'
        f'Pytest: {summary["pytest"]["tests"]} tests, {summary["pytest"]["failures"]} failures, {summary["pytest"]["errors"]} errors.\n\n'
        f'Postman Newman: {stats["requests"]["total"]} requests, {stats["assertions"]["total"]} assertions, '
        f'{stats["assertions"]["failed"]} failed assertions.\n\n'
        'All execution records come from the local implementation. Database structure, before/after records, HTTP request/response records, JUnit results, and actual Newman CLI output are included. Passwords and access tokens are excluded. These artifacts are not Postman desktop screenshots.\n')
    print(json.dumps(summary,indent=2))
    if summary['pytest']['failures'] or summary['pytest']['errors'] or stats['requests']['failed'] or stats['assertions']['failed']:
        raise SystemExit('Validation failed')

if __name__ == '__main__':
    summarize()
