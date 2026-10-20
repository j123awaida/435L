"""Behavioral coverage for Mohammad Nasrallah's Services 4–6.

Report figures are asserted against direct database counts, and the cross-service
collection path runs against Hassan's and Joseph's applications mounted in-process so
pagination and token forwarding are exercised without starting servers.
"""
import hashlib
import sqlite3
import time
from contextlib import ExitStack
import httpx
import pytest
from fastapi.testclient import TestClient
from app import db, reporting
from app.auth import hash_password, now
from app.assets import app as assets_app
from app.incidents import app as incidents_app
from app.logs import app as logs_app
from app.reports import app as reports_app
from app.threats import app as threats_app
from app.users import app as users_app
from app.vulnerabilities import app as vulnerabilities_app
from app.sprint123_models import PREFIX as H
from app.sprint456_models import PREFIX as P

PASSWORD = 'CorrectPassword123!'
ROLES = [(1, 'admin', 'admin'), (2, 'analyst', 'analyst'), (3, 'employee', 'employee'), (4, 'auditor', 'auditor')]


def headers(role='admin'):
    return {'Authorization': 'Bearer ' + role}


@pytest.fixture(scope='module')
def encoded_password():
    return hash_password(PASSWORD)


@pytest.fixture
def clients(tmp_path, monkeypatch, encoded_password):
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'services.sqlite3'))
    db.initialize()
    with db.connect() as conn:
        for id, username, role in ROLES:
            conn.execute('INSERT INTO users(id,full_name,username,password_hash,role) VALUES(?,?,?,?,?)',
                         (id, username, username, encoded_password, role))
            conn.execute('INSERT INTO user_profiles VALUES(?,?,?,?,?)',
                         (id, username + '@example.test', 'Security', now(), None))
            conn.execute('INSERT INTO sessions VALUES(?,?,?)',
                         (hashlib.sha256(username.encode()).hexdigest(), id, time.time() + 3600))
    with ExitStack() as stack:
        apps = (threats_app, logs_app, reports_app, users_app, assets_app, incidents_app, vulnerabilities_app)
        yield tuple(stack.enter_context(TestClient(app)) for app in apps)


DROPPED_HEADERS = {'host', 'content-length', 'transfer-encoding', 'connection'}


class InProcessTransport(httpx.BaseTransport):
    """Serves the collector's real HTTP requests from an in-process application.

    httpx.ASGITransport is async-only in this release, so it cannot back the synchronous
    client the collector uses. Delegating to Starlette's TestClient keeps the collector's
    URL building, pagination and header forwarding under test unchanged.
    """

    def __init__(self, client):
        self.client = client

    def handle_request(self, request):
        response = self.client.request(
            request.method,
            request.url.raw_path.decode(),
            headers=[(k.decode(), v.decode()) for k, v in request.headers.raw
                     if k.decode().lower() not in DROPPED_HEADERS],
            content=request.read(),
        )
        headers = [(k, v) for k, v in response.headers.items() if k.lower() not in DROPPED_HEADERS]
        return httpx.Response(response.status_code, headers=headers, content=response.content)


@pytest.fixture
def over_http(monkeypatch, clients):
    """Route the collector's configured base URLs at the in-process applications."""
    t, l, _, u, a, i, v = clients
    mounts = {f'http://127.0.0.1:{port}': InProcessTransport(client)
              for port, client in [(8000, u), (8002, a), (8003, i), (8004, t), (8005, l), (8007, v)]}
    monkeypatch.setattr(reporting, 'http_client', lambda: httpx.Client(mounts=mounts, timeout=5.0))


def threat(**changes):
    return {'threat_type': 'IP Address', 'threat_value': '198.51.100.24',
            'description': 'Command-and-control host', 'severity': 'High',
            'source': 'Internal detection'} | changes


def make_threat(t, **changes):
    response = t.post(P + '/threats', json=threat(**changes), headers=headers())
    assert response.status_code == 201, response.text
    return response.json()


def log(**changes):
    return {'user_id': 2, 'action': 'Threat reviewed', 'description': 'Analyst reviewed an indicator',
            'severity': 'Information', 'related_service': 'Service 4: Threat Intelligence'} | changes


# --------------------------------------------------------------------------- Service 4

def test_threat_creation_canonicalizes_and_stores(clients):
    t, *_ = clients
    record = make_threat(t, threat_value='2001:0DB8:0000:0000:0000:0000:0000:F00D')
    assert record['threat_value'] == '2001:db8::f00d', 'IPv6 must be compressed and lowercased before storage'
    with db.connect() as conn:
        stored = conn.execute('SELECT * FROM threats WHERE id=?', (record['id'],)).fetchone()
    assert stored['threat_value'] == '2001:db8::f00d' and stored['severity'] == 'High'
    assert make_threat(t, threat_type='Domain', threat_value='Malicious-Update.TEST.')['threat_value'] == 'malicious-update.test'
    assert make_threat(t, threat_type='File Hash', threat_value='D41D8CD98F00B204E9800998ECF8427E')['threat_value'] == 'd41d8cd98f00b204e9800998ecf8427e'
    assert make_threat(t, threat_type='Other', threat_value='  Encoded PowerShell  ')['threat_value'] == 'Encoded PowerShell'


def test_leading_zero_ipv4_is_rejected(clients):
    """Leading-zero octets are ambiguous (octal) and a known filter-bypass vector."""
    t, *_ = clients
    assert t.post(P + '/threats', json=threat(threat_value='192.000.002.001'), headers=headers()).status_code == 422
    assert t.post(P + '/threats', json=threat(threat_value='010.0.0.1'), headers=headers()).status_code == 422


def test_duplicate_threat_indicator_rejected(clients):
    t, *_ = clients
    make_threat(t)
    duplicate = t.post(P + '/threats', json=threat(), headers=headers())
    assert duplicate.status_code == 409 and duplicate.json()['status'] == 'error'
    # Canonicalization means an equivalent indicator is also a duplicate.
    make_threat(t, threat_type='Domain', threat_value='example.test')
    assert t.post(P + '/threats', json=threat(threat_type='Domain', threat_value='EXAMPLE.TEST.'),
                  headers=headers()).status_code == 409
    # The same value under a different type is a distinct indicator.
    assert t.post(P + '/threats', json=threat(threat_type='Other'), headers=headers()).status_code == 201
    with db.connect() as conn:
        assert conn.execute('SELECT COUNT(*) FROM threats').fetchone()[0] == 3


@pytest.mark.parametrize('threat_type,value', [
    ('IP Address', '999.1.1.1'), ('IP Address', 'not-an-ip'), ('IP Address', '192.0.2.1/24'),
    ('Domain', 'no-dot'), ('Domain', 'https://example.test'), ('Domain', 'example.test/path'),
    ('Domain', '-bad.example.test'), ('Domain', '192.0.2.1'),
    ('File Hash', 'xyz'), ('File Hash', 'd41d8cd98f00b204e9800998ecf8427'), ('File Hash', 'z' * 32),
])
def test_threat_value_validation_rejects_bad_formats(clients, threat_type, value):
    t, *_ = clients
    response = t.post(P + '/threats', json=threat(threat_type=threat_type, threat_value=value), headers=headers())
    assert response.status_code == 422, f'{threat_type} {value!r} should be rejected'
    assert response.json()['status'] == 'error' and response.json()['errors']


def test_threat_rejects_bad_enums_blanks_and_unknown_keys(clients):
    t, *_ = clients
    assert t.post(P + '/threats', json=threat(severity='Catastrophic'), headers=headers()).status_code == 422
    assert t.post(P + '/threats', json=threat(threat_type='Rumour'), headers=headers()).status_code == 422
    assert t.post(P + '/threats', json=threat(description='   '), headers=headers()).status_code == 422
    assert t.post(P + '/threats', json=threat(extra='x'), headers=headers()).status_code == 422
    assert t.post(P + '/threats', json={}, headers=headers()).status_code == 422


def test_threat_role_permissions(clients):
    t, *_ = clients
    record = make_threat(t)
    for role in ('analyst', 'auditor', 'employee'):
        assert t.post(P + '/threats', json=threat(threat_value='203.0.113.5'), headers=headers(role)).status_code == 403
    for role in ('admin', 'analyst', 'auditor'):
        assert t.get(P + '/threats', headers=headers(role)).status_code == 200
        assert t.get(f'{P}/threats/{record["id"]}', headers=headers(role)).status_code == 200
    assert t.get(P + '/threats', headers=headers('employee')).status_code == 403
    assert t.get(f'{P}/threats/{record["id"]}', headers=headers('employee')).status_code == 403
    # Service 4's authorization table grants search to administrators and analysts only.
    assert t.get(P + '/threats/search', params={'severity': 'High'}, headers=headers('analyst')).status_code == 200
    assert t.get(P + '/threats/search', params={'severity': 'High'}, headers=headers('auditor')).status_code == 403
    for role in ('analyst', 'auditor', 'employee'):
        assert t.delete(f'{P}/threats/{record["id"]}', headers=headers(role)).status_code == 403
    assert t.put(f'{P}/threats/{record["id"]}', json={'severity': 'Low'}, headers=headers('analyst')).status_code == 403


def test_threat_requires_authentication(clients):
    t, *_ = clients
    assert t.get(P + '/threats').status_code == 401
    assert t.get(P + '/threats', headers={'Authorization': 'Bearer wrong'}).status_code == 401


def test_threat_search_filters_combine(clients):
    t, *_ = clients
    make_threat(t, threat_value='198.51.100.24', severity='Critical', source='Internal detection')
    make_threat(t, threat_value='203.0.113.9', severity='High', source='Firewall logs')
    make_threat(t, threat_type='Domain', threat_value='malicious-update.test', severity='Critical', source='Threat feed')

    def search(**params):
        response = t.get(P + '/threats/search', params=params, headers=headers())
        assert response.status_code == 200, response.text
        return response.json()

    assert len(search(threat_type='IP Address')) == 2
    assert len(search(severity='Critical')) == 2
    assert len(search(source='Threat feed')) == 1
    assert len(search(threat_type='IP Address', severity='Critical')) == 1
    assert len(search(threat_value='203.0.113')) == 1, 'partial value should match as a substring'
    assert len(search(threat_value='MALICIOUS-UPDATE.TEST')) == 1, 'value search is case-insensitive'
    assert search(severity='Low') == [], 'no matches must return an empty array'
    assert search(threat_type='IP Address', severity='Low') == []
    assert len(search()) == 3


def test_threat_search_treats_wildcards_literally(clients):
    t, *_ = clients
    make_threat(t, threat_type='Other', threat_value='100% confirmed indicator')
    make_threat(t, threat_type='Malware Signature', threat_value='Trojan.Generic')
    response = t.get(P + '/threats/search', params={'threat_value': '%'}, headers=headers())
    assert [r['threat_value'] for r in response.json()] == ['100% confirmed indicator']


def test_threat_update_and_immutable_identity(clients):
    t, *_ = clients
    record = make_threat(t)
    updated = t.put(f'{P}/threats/{record["id"]}', json={'severity': 'Critical', 'source': 'Analyst review'}, headers=headers())
    assert updated.status_code == 200, updated.text
    assert updated.json()['severity'] == 'Critical' and updated.json()['source'] == 'Analyst review'
    assert updated.json()['threat_value'] == record['threat_value']
    # Type and value cannot be edited, so the uniqueness constraint cannot be bypassed.
    assert t.put(f'{P}/threats/{record["id"]}', json={'threat_value': '203.0.113.9'}, headers=headers()).status_code == 422
    assert t.put(f'{P}/threats/{record["id"]}', json={'threat_type': 'Domain'}, headers=headers()).status_code == 422
    assert t.put(f'{P}/threats/{record["id"]}', json={}, headers=headers()).status_code == 422
    assert t.put(f'{P}/threats/{record["id"]}', json={'severity': None}, headers=headers()).status_code == 422
    assert t.put(f'{P}/threats/999', json={'severity': 'Low'}, headers=headers()).status_code == 404


def test_threat_retrieve_and_delete_missing(clients):
    t, *_ = clients
    record = make_threat(t)
    assert t.get(f'{P}/threats/{record["id"]}', headers=headers()).json()['threat_value'] == '198.51.100.24'
    missing = t.get(P + '/threats/4242', headers=headers())
    assert missing.status_code == 404 and missing.json() == {'status': 'error', 'message': 'Threat not found'}
    assert t.delete(f'{P}/threats/{record["id"]}', headers=headers()).status_code == 200
    assert t.get(f'{P}/threats/{record["id"]}', headers=headers()).status_code == 404
    assert t.delete(f'{P}/threats/{record["id"]}', headers=headers()).status_code == 404


def test_threat_pagination(clients):
    t, *_ = clients
    for n in range(5):
        make_threat(t, threat_value=f'203.0.113.{n}')
    assert len(t.get(P + '/threats', params={'limit': 2}, headers=headers()).json()) == 2
    assert len(t.get(P + '/threats', params={'limit': 2, 'offset': 4}, headers=headers()).json()) == 1
    assert t.get(P + '/threats', params={'limit': 0}, headers=headers()).status_code == 422
    assert t.get(P + '/threats', params={'offset': -1}, headers=headers()).status_code == 422


# --------------------------------------------------------------------------- Service 5

def test_log_creation_records_exactly_one_row(clients):
    _, l, *_ = clients
    before = log_count()
    response = l.post(P + '/logs', json=log(), headers=headers())
    assert response.status_code == 201, response.text
    assert response.json()['action'] == 'Threat reviewed' and response.json()['user_id'] == 2
    # The shared modification middleware must not append a second row for an ingested log.
    assert log_count() == before + 1, 'ingesting one event must create exactly one audit row'


def log_count():
    with db.connect() as conn:
        return conn.execute('SELECT COUNT(*) FROM audit_logs').fetchone()[0]


def test_log_ingestion_is_idempotent(clients):
    _, l, *_ = clients
    key = {'Idempotency-Key': 'incident-assignment-17'} | headers()
    first = l.post(P + '/logs', json=log(), headers=key)
    assert first.status_code == 201
    before = log_count()
    replay = l.post(P + '/logs', json=log(), headers=key)
    assert replay.status_code == 200, 'a replayed key must not create a second record'
    assert replay.json() == first.json()
    assert log_count() == before, 'retrying a delivery must not duplicate the event'
    # The same key with a different payload is a client error, not a silent overwrite.
    conflict = l.post(P + '/logs', json=log(description='Different event'), headers=key)
    assert conflict.status_code == 409
    assert log_count() == before


def test_log_ingestion_without_key_allows_distinct_repeats(clients):
    _, l, *_ = clients
    before = log_count()
    assert l.post(P + '/logs', json=log(), headers=headers()).status_code == 201
    assert l.post(P + '/logs', json=log(), headers=headers()).status_code == 201
    assert log_count() == before + 2


def test_log_validation(clients):
    _, l, *_ = clients
    assert l.post(P + '/logs', json=log(severity='Fatal'), headers=headers()).status_code == 422
    assert l.post(P + '/logs', json=log(action=''), headers=headers()).status_code == 422
    assert l.post(P + '/logs', json=log(extra='x'), headers=headers()).status_code == 422
    assert l.post(P + '/logs', json={}, headers=headers()).status_code == 422
    assert l.post(P + '/logs', json=log(user_id=999), headers=headers()).status_code == 422
    # A system event with no responsible user is permitted, matching failed-login records.
    assert l.post(P + '/logs', json=log(user_id=None), headers=headers()).status_code == 201


def test_logs_are_immutable(clients):
    _, l, *_ = clients
    record = l.post(P + '/logs', json=log(), headers=headers()).json()
    assert l.put(f'{P}/logs/{record["id"]}', json={'description': 'tampered'}, headers=headers()).status_code == 405
    assert l.patch(f'{P}/logs/{record["id"]}', json={'description': 'tampered'}, headers=headers()).status_code == 405
    with pytest.raises(sqlite3.IntegrityError, match='immutable'):
        with db.connect() as conn:
            conn.execute('UPDATE audit_logs SET description=? WHERE id=?', ('tampered', record['id']))
    with db.connect() as conn:
        assert conn.execute('SELECT description FROM audit_logs WHERE id=?', (record['id'],)).fetchone()[0] == record['description']


def test_log_role_permissions(clients):
    _, l, *_ = clients
    record = l.post(P + '/logs', json=log(), headers=headers()).json()
    for role in ('analyst', 'auditor', 'employee'):
        assert l.post(P + '/logs', json=log(), headers=headers(role)).status_code == 403
    for role in ('admin', 'auditor'):
        assert l.get(P + '/logs', headers=headers(role)).status_code == 200
        assert l.get(P + '/logs/user/2', headers=headers(role)).status_code == 200
    for role in ('analyst', 'employee'):
        assert l.get(P + '/logs', headers=headers(role)).status_code == 403
        assert l.get(P + '/logs/user/2', headers=headers(role)).status_code == 403
    for role in ('admin', 'analyst', 'auditor'):
        assert l.get(f'{P}/logs/{record["id"]}', headers=headers(role)).status_code == 200
        assert l.get(P + '/logs/search', params={'severity': 'Information'}, headers=headers(role)).status_code == 200
    assert l.get(f'{P}/logs/{record["id"]}', headers=headers('employee')).status_code == 403
    for role in ('analyst', 'auditor', 'employee'):
        assert l.delete(f'{P}/logs/{record["id"]}', headers=headers(role)).status_code == 403


def test_permission_denial_is_itself_recorded(clients):
    _, l, *_ = clients
    before = log_count()
    assert l.get(P + '/logs', headers=headers('employee')).status_code == 403
    assert log_count() > before
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM audit_logs WHERE action='Permission denied' ORDER BY id DESC").fetchone()
    assert row['severity'] == 'Warning' and row['user_id'] == 3


def test_log_search_filters(clients):
    _, l, *_ = clients
    l.post(P + '/logs', json=log(action='Login failed', severity='Warning', user_id=1), headers=headers())
    l.post(P + '/logs', json=log(action='Login', severity='Information', user_id=2), headers=headers())
    l.post(P + '/logs', json=log(action='Asset modified', severity='Error', user_id=2,
                                 related_service='Service 2: Asset Management'), headers=headers())

    def search(**params):
        response = l.get(P + '/logs/search', params=params, headers=headers())
        assert response.status_code == 200, response.text
        return response.json()

    assert all(r['user_id'] == 2 for r in search(user_id=2)) and len(search(user_id=2)) >= 2
    assert len(search(severity='Error')) == 1
    assert len(search(related_service='Service 2: Asset Management')) == 1
    assert len(search(action='Login')) == 2, 'substring matching should find Login and Login failed'
    assert len(search(action='Login', severity='Warning')) == 1
    assert search(severity='Critical') == []
    today = now()[:10]
    assert len(search(date_from=today)) >= 3 and len(search(date_to=today)) >= 3
    assert search(date_from='2099-01-01') == []
    assert search(date_to='2000-01-01') == []
    assert l.get(P + '/logs/search', params={'date_from': 'yesterday'}, headers=headers()).status_code == 422


def test_logs_by_user(clients):
    _, l, *_ = clients
    l.post(P + '/logs', json=log(user_id=2), headers=headers())
    l.post(P + '/logs', json=log(user_id=2, action='Second review'), headers=headers())
    response = l.get(P + '/logs/user/2', headers=headers())
    assert response.status_code == 200 and len(response.json()) >= 2
    assert all(r['user_id'] == 2 for r in response.json())
    # A real user with no recorded activity returns an empty array, not 404.
    assert l.get(P + '/logs/user/4', headers=headers()).json() == []
    assert l.get(P + '/logs/user/999', headers=headers()).status_code == 404
    # The literal paths must not be captured by the /{id} route.
    assert l.get(P + '/logs/search', headers=headers()).status_code == 200


def test_log_deletion(clients):
    _, l, *_ = clients
    record = l.post(P + '/logs', json=log(), headers={'Idempotency-Key': 'delete-me'} | headers()).json()
    assert l.delete(f'{P}/logs/{record["id"]}', headers=headers()).status_code == 200
    with db.connect() as conn:
        # The record's content is gone and its ingestion receipt was cleared with it.
        assert conn.execute('SELECT COUNT(*) FROM audit_logs WHERE id=? AND description=?',
                            (record['id'], record['description'])).fetchone()[0] == 0
        assert conn.execute('SELECT COUNT(*) FROM log_receipts WHERE log_id=?', (record['id'],)).fetchone()[0] == 0
        # Deleting an audit record stays accountable.
        tombstone = conn.execute('SELECT * FROM log_tombstones WHERE log_id=?', (record['id'],)).fetchone()
    assert tombstone['deleted_by'] == 1 and tombstone['action'] == record['action']
    assert tombstone['recorded_at'] == record['created_at'] and tombstone['deleted_at']


def test_deleting_a_missing_log_is_rejected(clients):
    _, l, *_ = clients
    assert l.delete(P + '/logs/9999', headers=headers()).status_code == 404
    with db.connect() as conn:
        assert conn.execute('SELECT COUNT(*) FROM log_tombstones').fetchone()[0] == 0


def test_log_deletion_records_are_immutable(clients):
    _, l, *_ = clients
    record = l.post(P + '/logs', json=log(), headers=headers()).json()
    l.delete(f'{P}/logs/{record["id"]}', headers=headers())
    for statement, parameters in [('UPDATE log_tombstones SET deleted_by=2 WHERE log_id=?', (record['id'],)),
                                  ('DELETE FROM log_tombstones WHERE log_id=?', (record['id'],))]:
        with pytest.raises(sqlite3.IntegrityError, match='immutable'):
            with db.connect() as conn:
                conn.execute(statement, parameters)


# --------------------------------------------------------------------------- Service 6

def test_reports_role_permissions(clients):
    *_, = clients
    _, _, rp, *_ = clients
    for name in ('summary', 'incidents', 'assets', 'threats', 'vulnerabilities', 'activity'):
        for role in ('admin', 'auditor'):
            assert rp.get(f'{P}/reports/{name}', headers=headers(role)).status_code == 200, name
        for role in ('analyst', 'employee'):
            assert rp.get(f'{P}/reports/{name}', headers=headers(role)).status_code == 403, name
        assert rp.get(f'{P}/reports/{name}').status_code == 401, name


def seed_reportable_data(clients):
    """Create real records through the owning APIs and return the expected figures."""
    t, l, rp, u, a, i, v = clients
    for value, severity in [('198.51.100.24', 'Critical'), ('203.0.113.9', 'High'), ('203.0.113.10', 'Critical')]:
        make_threat(t, threat_value=value, severity=severity)
    make_threat(t, threat_type='Domain', threat_value='malicious-update.test', severity='Low')

    asset_ids = []
    for name, kind, criticality in [('App server', 'Server', 'Critical'), ('Analyst laptop', 'Workstation', 'Medium'),
                                    ('Billing database', 'Database', 'Critical')]:
        response = a.post(H + '/assets', json={'name': name, 'asset_type': kind, 'ip_address': f'192.0.2.{len(asset_ids) + 10}',
                                               'department': 'IT', 'owner_id': 3, 'location': 'Lab',
                                               'criticality': criticality}, headers=headers())
        assert response.status_code == 201, response.text
        asset_ids.append(response.json()['id'])

    for title, severity in [('Suspicious login', 'High'), ('Malware alert', 'Critical')]:
        response = i.post(H + '/incidents', json={'title': title, 'description': 'Investigate the activity',
                                                  'category': 'Unauthorized access', 'severity': severity,
                                                  'reporter_id': 3, 'asset_id': asset_ids[0]}, headers=headers('employee'))
        assert response.status_code == 201, response.text

    response = v.post(H.replace(H, '/Joseph-Awaida') + '/vulnerabilities',
                      json={'title': 'Outdated TLS', 'description': 'Legacy protocol enabled',
                            'cve_identifier': 'CVE-2024-12345', 'cvss_score': 7.5, 'severity': 'High',
                            'asset_id': asset_ids[0], 'discovery_source': 'Scanner'}, headers=headers())
    assert response.status_code == 201, response.text
    l.post(P + '/logs', json=log(action='Login failed', severity='Warning', user_id=None), headers=headers())
    l.post(P + '/logs', json=log(action='Login', severity='Information', user_id=1), headers=headers())


def database_figures():
    with db.connect() as conn:
        fetch = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
        return {
            'users': fetch('SELECT COUNT(*) FROM users WHERE id NOT IN (SELECT user_id FROM deleted_users)'),
            'assets': fetch('SELECT COUNT(*) FROM assets'),
            'open_incidents': fetch("SELECT COUNT(*) FROM incidents WHERE status IN ('Open','Under Investigation','Mitigated')"),
            'critical_threats': fetch("SELECT COUNT(*) FROM threats WHERE severity='Critical'"),
            'threats': fetch('SELECT COUNT(*) FROM threats'),
            'incidents': fetch('SELECT COUNT(*) FROM incidents'),
            'vulnerabilities': fetch('SELECT COUNT(*) FROM vulnerabilities'),
            'logs': fetch('SELECT COUNT(*) FROM audit_logs'),
            'failed_logins': fetch("SELECT COUNT(*) FROM audit_logs WHERE action='Login failed'"),
        }


@pytest.mark.parametrize('transport', ['database', 'api'])
def test_reports_match_database_records(clients, request, transport):
    """Every report figure must equal a direct database count, over both collection paths."""
    if transport == 'api':
        request.getfixturevalue('over_http')
    _, _, rp, *_ = clients
    seed_reportable_data(clients)
    expected = database_figures()

    summary = rp.get(P + '/reports/summary', headers=headers()).json()
    assert summary['users'] == expected['users']
    assert summary['assets'] == expected['assets']
    assert summary['open_incidents'] == expected['open_incidents']
    assert summary['critical_threats'] == expected['critical_threats']
    assert {s['origin'] for s in summary['sources']} == {transport}

    incidents = rp.get(P + '/reports/incidents', headers=headers()).json()
    assert incidents['total_incidents'] == expected['incidents'] == sum(incidents['incidents_by_severity'].values())
    assert sum(incidents['incidents_by_status'].values()) == expected['incidents']
    assert incidents['incidents_by_severity'] == {'Critical': 1, 'High': 1}

    assets = rp.get(P + '/reports/assets', headers=headers()).json()
    assert assets['total_assets'] == expected['assets'] == sum(assets['assets_by_type'].values())
    assert assets['critical_assets'] == 2
    assert assets['assets_by_type']['Server'] == 1 and assets['assets_by_type']['Database'] == 1

    threats = rp.get(P + '/reports/threats', headers=headers()).json()
    assert threats['total_threats'] == expected['threats'] == sum(threats['threats_by_severity'].values())
    assert threats['threats_by_severity'] == {'Critical': 2, 'High': 1, 'Low': 1}
    assert threats['threats_by_type'] == {'Domain': 1, 'IP Address': 3}
    assert len(threats['recent_threats']) == min(4, 5)

    vulnerabilities = rp.get(P + '/reports/vulnerabilities', headers=headers()).json()
    assert vulnerabilities['total_vulnerabilities'] == expected['vulnerabilities']
    assert vulnerabilities['vulnerabilities_by_severity'] == {'High': 1}
    assert vulnerabilities['vulnerabilities_by_status'] == {'Open': 1}
    assert vulnerabilities['critical_vulnerabilities'] == 0

    activity = rp.get(P + '/reports/activity', headers=headers()).json()
    assert activity['total_activities'] == expected['logs']
    assert activity['failed_login_attempts'] == expected['failed_logins'] == 1
    assert activity['login_attempts'] == 2
    assert sum(a['count'] for a in activity['most_performed_actions']) == expected['logs']
    assert activity['most_performed_actions'][0]['count'] >= activity['most_performed_actions'][-1]['count']


def test_reports_paginate_across_pages(clients, over_http, monkeypatch):
    """A page size smaller than the record count proves the collector follows pagination."""
    t, _, rp, *_ = clients
    monkeypatch.setattr(reporting, 'PAGE_SIZE', 2)
    for n in range(7):
        make_threat(t, threat_value=f'203.0.113.{n}', severity='Low')
    report = rp.get(P + '/reports/threats', headers=headers()).json()
    assert report['total_threats'] == 7, 'all pages must be collected, not just the first'
    assert report['threats_by_severity'] == {'Low': 7}
    assert [s['origin'] for s in report['sources']] == ['api']


def test_reports_fall_back_when_a_service_is_unreachable(clients, monkeypatch):
    """An unreachable source degrades to a database read and says so, rather than failing."""
    t, _, rp, *_ = clients
    make_threat(t, severity='Critical')
    monkeypatch.setenv('USERS_API_URL', 'http://127.0.0.1:9/unreachable')
    response = rp.get(P + '/reports/summary', headers=headers())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['critical_threats'] == 1
    assert body['users'] == database_figures()['users'], 'fallback must still produce the correct figure'
    users_source = next(s for s in body['sources'] if s['name'] == 'users')
    assert users_source['origin'] == 'database' and 'unavailable' in users_source['detail']


def test_reports_forward_caller_credentials(clients, over_http):
    """An auditor's own token must be what reaches the source services."""
    _, _, rp, *_ = clients
    seen = {}
    original = reporting.http_client

    def recording():
        client = original()
        client.event_hooks['request'] = [lambda request: seen.setdefault('auth', request.headers.get('authorization'))]
        return client

    reporting.http_client = recording
    try:
        assert rp.get(P + '/reports/summary', headers=headers('auditor')).status_code == 200
    finally:
        reporting.http_client = original
    assert seen['auth'] == 'Bearer auditor', 'the caller’s credentials, not a stored service account, must be used'


def test_summary_matches_brief_example_shape(clients):
    _, _, rp, *_ = clients
    body = rp.get(P + '/reports/summary', headers=headers()).json()
    assert set(body) == {'users', 'assets', 'open_incidents', 'critical_threats', 'sources'}
    assert all(isinstance(body[k], int) for k in ('users', 'assets', 'open_incidents', 'critical_threats'))


def test_health_endpoints_use_the_student_prefix(clients):
    t, l, rp, *_ = clients
    for client, title in [(t, 'Service 4: Threat Intelligence'), (l, 'Service 5: Security Audit Logging'),
                          (rp, 'Service 6: Security Reports')]:
        response = client.get(P + '/health')
        assert response.status_code == 200 and response.json() == {'status': 'ok', 'service': title}
