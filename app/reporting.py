"""Cross-service data collection for Service 6 (Mohammad Nasrallah).

Each source is read over HTTP from the owning service first, following its documented
``limit``/``offset`` pagination. If a service cannot be reached the collector falls back
to the shared database so a report is still produced, and records which path was used so
every response states where its figures came from.

The caller's own bearer token is forwarded rather than storing a service account: only
administrators and auditors can reach Service 6, and both roles already hold read
permission on every source.
"""
import os
from collections import Counter
import httpx
from .db import connect
from .sprint456_models import SourceStatus

PAGE_SIZE = 500
MAX_PAGES = 200  # Guards against a malformed upstream that never returns a short page.
TIMEOUT = 5.0

# Defaults match the documented local ports and route prefixes of each owning service.
SOURCES = {
    'users': ('USERS_API_URL', 'http://127.0.0.1:8000/Hassan-Nasrallah/users'),
    'assets': ('ASSETS_API_URL', 'http://127.0.0.1:8002/Hassan-Nasrallah/assets'),
    'incidents': ('INCIDENTS_API_URL', 'http://127.0.0.1:8003/Hassan-Nasrallah/incidents'),
    'threats': ('THREATS_API_URL', 'http://127.0.0.1:8004/Mohammad-Nasrallah/threats'),
    'logs': ('LOGS_API_URL', 'http://127.0.0.1:8005/Mohammad-Nasrallah/logs'),
    'vulnerabilities': ('VULNERABILITIES_API_URL', 'http://127.0.0.1:8007/Joseph-Awaida/vulnerabilities'),
}

# Fallback queries mirror the field names and visibility rules of the corresponding APIs.
# Deleted accounts are excluded because Hassan's user APIs no longer return them.
FALLBACKS = {
    'users': 'SELECT id, full_name, username, role, account_status FROM users'
             ' WHERE id NOT IN (SELECT user_id FROM deleted_users) ORDER BY id',
    'assets': 'SELECT a.id, a.name, p.asset_type, p.criticality FROM assets a'
              ' LEFT JOIN asset_profiles p ON p.asset_id = a.id ORDER BY a.id',
    'incidents': 'SELECT id, severity, status FROM incidents ORDER BY id',
    'threats': 'SELECT id, threat_type, threat_value, description, severity, source, created_at FROM threats ORDER BY id',
    'logs': 'SELECT id, user_id, action, description, severity, related_service, created_at FROM audit_logs ORDER BY id',
    'vulnerabilities': 'SELECT id, severity, status FROM vulnerabilities ORDER BY id',
}


def base_url(name):
    variable, default = SOURCES[name]
    return os.getenv(variable, default).rstrip('/')


def http_client():
    """Overridden in tests to route these base URLs at in-process ASGI applications."""
    return httpx.Client(timeout=TIMEOUT)


def from_database(name):
    with connect() as db:
        return [dict(row) for row in db.execute(FALLBACKS[name])]


def collect(name, authorization):
    """Return ``(records, SourceStatus)`` for one source."""
    url = base_url(name)
    headers = {'Authorization': authorization} if authorization else {}
    records = []
    client = http_client()
    try:
        for page in range(MAX_PAGES):
            response = client.get(url, params={'limit': PAGE_SIZE, 'offset': page * PAGE_SIZE}, headers=headers)
            if response.status_code != 200:
                raise RuntimeError(f'HTTP {response.status_code}')
            batch = response.json()
            if not isinstance(batch, list):
                raise RuntimeError('Expected a JSON array')
            records.extend(batch)
            if len(batch) < PAGE_SIZE:
                break
        else:
            raise RuntimeError('Pagination did not terminate')
    except (httpx.HTTPError, RuntimeError, ValueError) as error:
        reason = f'{type(error).__name__}: {error}'.strip(': ')
        return from_database(name), SourceStatus(name=name, origin='database',
                                                 detail=f'{url} unavailable ({reason}); read from the shared database')
    finally:
        client.close()
    return records, SourceStatus(name=name, origin='api', detail=url)


class Collection:
    """Lazily collects each requested source at most once per report request."""

    def __init__(self, authorization):
        self.authorization = authorization
        self.records = {}
        self.sources = {}

    def get(self, name):
        if name not in self.records:
            self.records[name], self.sources[name] = collect(name, self.authorization)
        return self.records[name]

    def status(self):
        return [self.sources[name] for name in sorted(self.sources)]


def tally(records, field, default='Unspecified'):
    """Count records by one field, returning a deterministic ordering."""
    counts = Counter(record.get(field) or default for record in records)
    return dict(sorted(counts.items()))
