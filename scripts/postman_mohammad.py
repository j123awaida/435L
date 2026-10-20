"""Generate Mohammad Nasrallah's Postman collection and environment template for Services 4–6.

Every request carries a description and assertions, and the collection captures real runtime
tokens and record identifiers so a run exercises the live system rather than fixed values.

    python -m scripts.postman_mohammad
"""
import json
from pathlib import Path
from app.sprint123_models import PREFIX as HASSAN
from app.sprint456_models import PREFIX as MINE

COLLECTION = Path('postman/Mohammad-Services-4-5-6.postman_collection.json')
ENVIRONMENT = Path('postman/Mohammad-Local.postman_environment.json')

ROLES = ['admin', 'analyst', 'employee', 'auditor']


def script(*lines):
    return {'listen': 'test', 'script': {'type': 'text/javascript', 'exec': list(lines)}}


def request(name, method, url, description, body=None, token='admin_token', tests=(), headers=None, auth=True):
    header = list(headers or [])
    if auth:
        header.append({'key': 'Authorization', 'value': '{{' + token + '}}'})
    if body is not None:
        header.append({'key': 'Content-Type', 'value': 'application/json'})
    item = {
        'name': name,
        'request': {
            'method': method,
            'header': header,
            'url': url,
            'description': description,
        },
    }
    if body is not None:
        item['request']['body'] = {'mode': 'raw', 'raw': json.dumps(body, indent=2),
                                   'options': {'raw': {'language': 'json'}}}
    if tests:
        item['event'] = [script(*tests)]
    return item


def expect(code, *extra):
    return [f'pm.test("status {code}", () => pm.response.to.have.status({code}));', *extra]


def login_folder():
    items = []
    for role in ROLES:
        items.append(request(
            f'Login as {role}', 'POST', '{{identity_url}}/users/login',
            f'Authenticate the {role} account against Hassan Nasrallah\'s Service 1 and store the bearer token '
            f'for later requests. Never include the token response in submitted evidence.',
            body={'username': role, 'password': '{{' + role + '_password}}'},
            auth=False,
            tests=expect(200,
                         'const body = pm.response.json();',
                         f'pm.collectionVariables.set("{role}_token", "Bearer " + body.access_token);',
                         f'pm.collectionVariables.set("{role}_id", body.user_id);',
                         f'pm.test("role is {role}", () => pm.expect(body.role).to.eql("{role}"));')))
    items.append(request(
        'Login with an incorrect password (rejected)', 'POST', '{{identity_url}}/users/login',
        'Demonstrates failed authentication. The attempt is recorded as a "Login failed" audit record, which the '
        'activity report then counts.',
        body={'username': 'admin', 'password': 'WrongPassword123!'}, auth=False,
        tests=expect(401)))
    return {'name': '0. Authentication (Mohammad Nasrallah)', 'item': items,
            'description': 'Obtain bearer tokens for all four roles. Run this folder first.'}


def threats_folder():
    indicators = [
        ('IP address indicator', {'threat_type': 'IP Address', 'threat_value': '198.51.100.24',
                                  'description': 'Command-and-control host observed in outbound beaconing',
                                  'severity': 'Critical', 'source': 'Internal detection'},
         'Adds a critical malicious IP indicator. The value is validated as an IP address and stored canonically.'),
        ('Domain indicator', {'threat_type': 'Domain', 'threat_value': 'malicious-update.test',
                              'description': 'Phishing domain impersonating the update portal',
                              'severity': 'High', 'source': 'Threat feed'},
         'Adds a high-severity suspicious domain. Domain format is validated and lowercased.'),
        ('File hash indicator', {'threat_type': 'File Hash', 'threat_value': 'd41d8cd98f00b204e9800998ecf8427e',
                                 'description': 'Dropper sample recovered from an email attachment',
                                 'severity': 'Medium', 'source': 'Malware analysis'},
         'Adds a medium-severity malware hash. The digest length identifies MD5, SHA-1, SHA-256 or SHA-512.'),
    ]
    items = []
    for index, (name, body, description) in enumerate(indicators):
        items.append(request(f'Add threat indicator — {name}', 'POST', '{{threats_url}}/threats', description,
                             body=body, tests=expect(201,
                                                     'const body = pm.response.json();',
                                                     f'pm.collectionVariables.set("threat_id_{index}", body.id);',
                                                     'pm.test("stored fields returned", () => pm.expect(body).to.have.property("created_at"));')))
    items += [
        request('Add duplicate indicator (rejected)', 'POST', '{{threats_url}}/threats',
                'The same threat type and value cannot be stored twice. A database uniqueness constraint rejects the '
                'duplicate, so concurrent requests cannot both succeed.',
                body=indicators[0][1], tests=expect(409)),
        request('Add indicator with an invalid IP (rejected)', 'POST', '{{threats_url}}/threats',
                'Validation rejects a malformed IP address for an IP-type indicator and names the offending field.',
                body={'threat_type': 'IP Address', 'threat_value': '999.1.1.1', 'description': 'Invalid address',
                      'severity': 'High', 'source': 'Manual entry'},
                tests=expect(422, 'pm.test("names the field", () => pm.expect(pm.response.json().errors).to.be.an("array").that.is.not.empty);')),
        request('Add indicator with an invalid hash (rejected)', 'POST', '{{threats_url}}/threats',
                'A file hash must be a hexadecimal digest of a supported length.',
                body={'threat_type': 'File Hash', 'threat_value': 'not-a-hash', 'description': 'Invalid digest',
                      'severity': 'Low', 'source': 'Manual entry'}, tests=expect(422)),
        request('Add indicator with an invalid severity (rejected)', 'POST', '{{threats_url}}/threats',
                'Severity must be Low, Medium, High or Critical.',
                body={'threat_type': 'Other', 'threat_value': 'Unusual process tree', 'description': 'Indicator',
                      'severity': 'Catastrophic', 'source': 'Analyst review'}, tests=expect(422)),
        request('Add indicator as analyst (forbidden)', 'POST', '{{threats_url}}/threats',
                'Only administrators may add threat intelligence. The denial is itself recorded as a '
                '"Permission denied" audit record.',
                body=indicators[1][1], token='analyst_token', tests=expect(403)),
        request('Add indicator without a token (unauthenticated)', 'POST', '{{threats_url}}/threats',
                'Protected operations require a bearer token.', body=indicators[1][1], auth=False,
                tests=expect(401)),
        request('Retrieve all indicators', 'GET', '{{threats_url}}/threats?limit=100&offset=0',
                'Returns stored indicators with their severity, source and date added, using limit/offset pagination.',
                tests=expect(200, 'pm.test("array returned", () => pm.expect(pm.response.json()).to.be.an("array"));')),
        request('Retrieve all indicators as auditor', 'GET', '{{threats_url}}/threats',
                'Auditors hold read access to threat intelligence.', token='auditor_token', tests=expect(200)),
        request('Retrieve all indicators as employee (forbidden)', 'GET', '{{threats_url}}/threats',
                'Regular employees have no access to threat intelligence APIs.', token='employee_token',
                tests=expect(403)),
        request('Retrieve a specific indicator', 'GET', '{{threats_url}}/threats/{{threat_id_0}}',
                'Returns the complete record for one indicator.',
                tests=expect(200, 'pm.test("same record", () => pm.expect(pm.response.json().id).to.eql(Number(pm.collectionVariables.get("threat_id_0"))));')),
        request('Retrieve a non-existing indicator', 'GET', '{{threats_url}}/threats/999999',
                'An unknown identifier returns 404 with the shared error shape.',
                tests=expect(404, 'pm.test("error shape", () => pm.expect(pm.response.json().status).to.eql("error"));')),
        request('Search by threat type', 'GET', '{{threats_url}}/threats/search?threat_type=IP Address',
                'Filters indicators by type. Filters combine with AND.', tests=expect(200)),
        request('Search by severity', 'GET', '{{threats_url}}/threats/search?severity=Critical',
                'Filters indicators by severity level.', tests=expect(200)),
        request('Search by partial value', 'GET', '{{threats_url}}/threats/search?threat_value=198.51.100',
                'Value matching is a literal case-insensitive substring, so a partial indicator matches.',
                tests=expect(200, 'pm.test("at least one match", () => pm.expect(pm.response.json().length).to.be.above(0));')),
        request('Search by source and type combined', 'GET',
                '{{threats_url}}/threats/search?threat_type=Domain&source=Threat feed',
                'Several filters narrow the result set together.', tests=expect(200)),
        request('Search with no matches', 'GET', '{{threats_url}}/threats/search?severity=Low&threat_type=File Hash',
                'A search with no results returns an empty array rather than an error.',
                tests=expect(200, 'pm.test("empty array", () => pm.expect(pm.response.json()).to.eql([]));')),
        request('Search as analyst', 'GET', '{{threats_url}}/threats/search?severity=Critical',
                'Analysts may search threat intelligence during investigations.', token='analyst_token',
                tests=expect(200)),
        request('Update indicator severity and source', 'PUT', '{{threats_url}}/threats/{{threat_id_1}}',
                'Administrators may revise the description, severity and source. Capture the record before and after '
                'this request to show the change.',
                body={'severity': 'Critical', 'source': 'Confirmed by analyst review'},
                tests=expect(200, 'pm.test("severity updated", () => pm.expect(pm.response.json().severity).to.eql("Critical"));')),
        request('Update threat value (rejected)', 'PUT', '{{threats_url}}/threats/{{threat_id_1}}',
                'Threat type and value are immutable: editing them would bypass the duplicate-indicator constraint.',
                body={'threat_value': '203.0.113.9'}, tests=expect(422)),
        request('Update with an empty body (rejected)', 'PUT', '{{threats_url}}/threats/{{threat_id_1}}',
                'An update must contain at least one non-null field.', body={}, tests=expect(422)),
        request('Delete indicator as auditor (forbidden)', 'DELETE', '{{threats_url}}/threats/{{threat_id_2}}',
                'Auditors hold read-only permissions and cannot delete threat records.', token='auditor_token',
                tests=expect(403)),
        request('Delete indicator as administrator', 'DELETE', '{{threats_url}}/threats/{{threat_id_2}}',
                'Administrators may remove a threat record.',
                tests=expect(200, 'pm.test("confirmation returned", () => pm.expect(pm.response.json().message).to.be.a("string"));')),
    ]
    return {'name': '1. Service 4 — Threat Intelligence (Mohammad Nasrallah)', 'item': items,
            'description': 'Create, list, retrieve, search, update and delete threat indicators, including validation '
                           'and authorization failures.'}


def logs_folder():
    payload = {'user_id': '{{analyst_id}}', 'action': 'Threat indicator reviewed',
               'description': 'Analyst reviewed a critical threat indicator during triage',
               'severity': 'Information', 'related_service': 'Service 4: Threat Intelligence'}
    items = [
        request('Create log record', 'POST', '{{logs_url}}/logs',
                'Records a security activity. Integrating services call this endpoint with an administrator service '
                'token and the acting user in user_id.',
                body=payload, tests=expect(201,
                                           'const body = pm.response.json();',
                                           'pm.collectionVariables.set("log_id", body.id);',
                                           'pm.test("timestamp generated", () => pm.expect(body.created_at).to.be.a("string"));')),
        request('Create log record with an Idempotency-Key', 'POST', '{{logs_url}}/logs',
                'Integration contract for Services 1–3 and 7–9: supplying an Idempotency-Key makes delivery retries '
                'safe. The first call creates the record.',
                body=payload | {'action': 'Incident assigned', 'related_service': 'Service 3: Incident Management'},
                headers=[{'key': 'Idempotency-Key', 'value': 'incident-assignment-demo-1'}],
                tests=expect(201, 'pm.collectionVariables.set("idempotent_log_id", pm.response.json().id);')),
        request('Replay the same Idempotency-Key (no duplicate)', 'POST', '{{logs_url}}/logs',
                'Replaying a key returns the original record with HTTP 200 instead of creating a second row, so a '
                'teammate retry cannot duplicate the event.',
                body=payload | {'action': 'Incident assigned', 'related_service': 'Service 3: Incident Management'},
                headers=[{'key': 'Idempotency-Key', 'value': 'incident-assignment-demo-1'}],
                tests=expect(200, 'pm.test("same record returned", () => pm.expect(pm.response.json().id).to.eql(Number(pm.collectionVariables.get("idempotent_log_id"))));')),
        request('Reuse the key with a different payload (rejected)', 'POST', '{{logs_url}}/logs',
                'Reusing a key for a different event is a client error rather than a silent overwrite.',
                body=payload | {'action': 'Incident closed', 'related_service': 'Service 3: Incident Management'},
                headers=[{'key': 'Idempotency-Key', 'value': 'incident-assignment-demo-1'}],
                tests=expect(409)),
        request('Create log with an invalid severity (rejected)', 'POST', '{{logs_url}}/logs',
                'Log severity must be Information, Warning, Error or Critical.',
                body=payload | {'severity': 'Fatal'}, tests=expect(422)),
        request('Create log for an unknown user (rejected)', 'POST', '{{logs_url}}/logs',
                'A referenced user must exist.', body=payload | {'user_id': 999999}, tests=expect(422)),
        request('Create log as analyst (forbidden)', 'POST', '{{logs_url}}/logs',
                'Only administrators and integrating service accounts may write audit records.',
                body=payload, token='analyst_token', tests=expect(403)),
        request('Retrieve all logs', 'GET', '{{logs_url}}/logs?limit=100&offset=0',
                'Administrators list audit records newest first. Records are produced automatically by login attempts, '
                'permission denials and data modifications across all services.',
                tests=expect(200, 'pm.test("array returned", () => pm.expect(pm.response.json()).to.be.an("array"));')),
        request('Retrieve all logs as auditor', 'GET', '{{logs_url}}/logs',
                'Auditors hold full read access to audit records.', token='auditor_token', tests=expect(200)),
        request('Retrieve all logs as analyst (forbidden)', 'GET', '{{logs_url}}/logs',
                "Service 5's authorization table does not grant analysts the full log listing.",
                token='analyst_token', tests=expect(403)),
        request('Retrieve all logs as employee (forbidden)', 'GET', '{{logs_url}}/logs',
                'Regular employees have no access to audit log APIs.', token='employee_token', tests=expect(403)),
        request('Retrieve a specific log', 'GET', '{{logs_url}}/logs/{{log_id}}',
                'Returns one audit record in full.', tests=expect(200)),
        request('Retrieve a specific log as analyst', 'GET', '{{logs_url}}/logs/{{log_id}}',
                'Analysts may read an individual audit record.', token='analyst_token', tests=expect(200)),
        request('Retrieve an invalid log id', 'GET', '{{logs_url}}/logs/999999',
                'An unknown identifier returns 404.', tests=expect(404)),
        request('Search logs by severity', 'GET', '{{logs_url}}/logs/search?severity=Warning',
                'Filters audit records by severity. Failed logins and permission denials are recorded as Warning.',
                tests=expect(200)),
        request('Search logs by action', 'GET', '{{logs_url}}/logs/search?action=Login',
                'Action matching is a literal case-insensitive substring, so this returns both successful and failed '
                'logins.', tests=expect(200)),
        request('Search logs by user and date', 'GET',
                '{{logs_url}}/logs/search?user_id={{admin_id}}&date_from={{today}}&date_to={{today}}',
                'Filters combine with AND. The date range is inclusive and interpreted in UTC.', tests=expect(200)),
        request('Search logs by related service', 'GET',
                '{{logs_url}}/logs/search?related_service=Service 4: Threat Intelligence',
                'Identifies which service produced each activity.', tests=expect(200)),
        request('Search logs with no matches', 'GET', '{{logs_url}}/logs/search?date_from=2099-01-01',
                'A search with no results returns an empty array.',
                tests=expect(200, 'pm.test("empty array", () => pm.expect(pm.response.json()).to.eql([]));')),
        request('Retrieve logs by user', 'GET', '{{logs_url}}/logs/user/{{analyst_id}}',
                'Returns every activity recorded for one user, filtered on the user identifier.',
                tests=expect(200, 'pm.test("all records belong to the user", () => pm.response.json().forEach(r => pm.expect(r.user_id).to.eql(Number(pm.collectionVariables.get("analyst_id")))));')),
        request('Retrieve logs for a user with no activity', 'GET', '{{logs_url}}/logs/user/{{employee_id}}',
                'A real user with no recorded activity returns an empty array rather than an error. Run this before '
                'generating employee activity.',
                tests=expect(200, 'pm.test("array returned", () => pm.expect(pm.response.json()).to.be.an("array"));')),
        request('Retrieve logs for an unknown user', 'GET', '{{logs_url}}/logs/user/999999',
                'An unknown user identifier returns 404.', tests=expect(404)),
        request('Delete log as analyst (forbidden)', 'DELETE', '{{logs_url}}/logs/{{log_id}}',
                'Analysts, auditors and employees must not delete audit records.', token='analyst_token',
                tests=expect(403)),
        request('Delete log as auditor (forbidden)', 'DELETE', '{{logs_url}}/logs/{{log_id}}',
                'Auditors hold read-only permissions.', token='auditor_token', tests=expect(403)),
        request('Delete log as administrator', 'DELETE', '{{logs_url}}/logs/{{log_id}}',
                'Only administrators may remove audit records. The deleted identifier, the administrator and the time '
                'are retained in an immutable deletion record.',
                tests=expect(200)),
    ]
    return {'name': '2. Service 5 — Security Audit Logging (Mohammad Nasrallah)', 'item': items,
            'description': 'Create, list, retrieve, search and delete audit records, retrieve logs by user, and '
                           'demonstrate the idempotent ingestion contract used by teammate services.'}


def reports_folder():
    reports = [
        ('summary', 'Generate security summary report',
         'Overall platform status: user, asset, open incident and critical threat totals. Compare these figures with '
         'the database records to verify them.'),
        ('incidents', 'Generate incident report',
         'Total incidents with distribution by severity and by lifecycle status.'),
        ('assets', 'Generate asset report',
         'Total assets, count of critical assets and distribution by asset type.'),
        ('threats', 'Generate threat report',
         'Threat totals grouped by severity and type, plus the most recently added indicators.'),
        ('vulnerabilities', 'Generate vulnerability report',
         'Vulnerability totals grouped by severity and status, plus the count of critical vulnerabilities.'),
        ('activity', 'Generate activity report',
         'Total activities, login attempts, failed login attempts and the most performed actions, derived from audit '
         'records.'),
    ]
    items = []
    for path, name, description in reports:
        items.append(request(name, 'GET', '{{reports_url}}/reports/' + path,
                             description + ' The response includes a sources block naming each source service and '
                                           'whether the figures were collected over its API or read from the shared '
                                           'database.',
                             tests=expect(200,
                                          'const body = pm.response.json();',
                                          'pm.test("sources declared", () => pm.expect(body.sources).to.be.an("array").that.is.not.empty);')))
    items.append(request('Generate summary report as auditor', 'GET', '{{reports_url}}/reports/summary',
                         'Auditors may generate every security report.', token='auditor_token', tests=expect(200)))
    items.append(request('Generate summary report as analyst (forbidden)', 'GET', '{{reports_url}}/reports/summary',
                         'Analysts have no report generation access unless explicitly authorized.',
                         token='analyst_token', tests=expect(403)))
    items.append(request('Generate summary report as employee (forbidden)', 'GET', '{{reports_url}}/reports/summary',
                         'Regular employees have no access to report APIs.', token='employee_token',
                         tests=expect(403)))
    items.append(request('Generate summary report without a token', 'GET', '{{reports_url}}/reports/summary',
                         'Report generation requires authentication.', auth=False, tests=expect(401)))
    return {'name': '3. Service 6 — Security Reports (Mohammad Nasrallah)', 'item': items,
            'description': 'Generate all six security reports from live system data and demonstrate report access '
                           'control. Run the Service 4 and 5 folders first so the reports contain data.'}


def main():
    collection = {
        'info': {
            'name': 'Mohammad Nasrallah — Services 4, 5, 6 (Sprint I)',
            'description':
                'Security Incident Detection and Response Management System — Threat Intelligence (Service 4, port '
                '8004), Security Audit Logging (Service 5, port 8005) and Security Reports (Service 6, port 8006), '
                'implemented by Mohammad Nasrallah. Every business route is prefixed with ' + MINE + '.\n\n'
                'Run the folders in order: authentication first, then Service 4, Service 5 and Service 6. '
                'Authentication uses Hassan Nasrallah\'s Service 1 on port 8000. Fill the four role passwords in the '
                'environment before running, and do not include tokens or passwords in submitted screenshots.',
            'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
        },
        'item': [login_folder(), threats_folder(), logs_folder(), reports_folder()],
        'event': [{'listen': 'prerequest', 'script': {'type': 'text/javascript', 'exec': [
            '// Supply today\'s UTC date for the audit log date-range search.',
            'pm.collectionVariables.set("today", new Date().toISOString().slice(0, 10));',
        ]}}],
        'variable': [
            {'key': 'identity_url', 'value': 'http://127.0.0.1:8000' + HASSAN,
             'description': "Hassan Nasrallah's Service 1 (authentication)"},
            {'key': 'threats_url', 'value': 'http://127.0.0.1:8004' + MINE, 'description': 'Service 4'},
            {'key': 'logs_url', 'value': 'http://127.0.0.1:8005' + MINE, 'description': 'Service 5'},
            {'key': 'reports_url', 'value': 'http://127.0.0.1:8006' + MINE, 'description': 'Service 6'},
        ] + [{'key': f'{role}_token', 'value': ''} for role in ROLES]
          + [{'key': f'{role}_id', 'value': ''} for role in ROLES]
          + [{'key': key, 'value': ''} for key in ('threat_id_0', 'threat_id_1', 'threat_id_2', 'log_id',
                                                   'idempotent_log_id', 'today')],
    }
    environment = {
        'name': 'Mohammad Local (Services 4–6)',
        'values': [{'key': f'{role}_password', 'value': '', 'type': 'secret', 'enabled': True} for role in ROLES],
        '_postman_variable_scope': 'environment',
    }
    for path, document in [(COLLECTION, collection), (ENVIRONMENT, environment)]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2) + '\n', encoding='utf8')
        print(f'Wrote {path}')
    total = sum(len(folder['item']) for folder in collection['item'])
    print(f'{len(collection["item"])} folders, {total} documented requests.')
    print('Passwords are intentionally blank in the committed environment; fill them locally before running.')


if __name__ == '__main__':
    main()
