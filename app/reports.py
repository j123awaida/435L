"""Service 6: Security Reports (Mohammad Nasrallah).

Reports are derived from live system data collected from the owning services, never from
stored summaries, so every figure reflects the database at request time.
"""
from collections import Counter
from fastapi import APIRouter, Depends, Header
from .auth import allowed
from .common import create_app
from .reporting import Collection, tally
from .sprint456_models import (PREFIX, ActivityReport, AssetReport, IncidentReport, SummaryReport,
                               ThreatReport, VulnerabilityReport)

app = create_app('Service 6: Security Reports', PREFIX)
r = APIRouter(prefix=PREFIX + '/reports', tags=['Security Reports'])

# Service 6 authorization table: administrators and auditors only.
# Analysts have no report generation access; employees have no access at all.
reporting_roles = allowed('admin', 'auditor')

OPEN_INCIDENT_STATES = ('Open', 'Under Investigation', 'Mitigated')
RECENT_THREATS = 5


def collection(authorization: str | None = Header(default=None, alias='Authorization'), user=Depends(reporting_roles)):
    """Forward the caller's own credentials to each source service."""
    return Collection(authorization)


@r.get('/summary', summary='Generate security summary report',
        description='Overall platform status: user, asset, open incident and critical threat totals.',
        response_model=SummaryReport)
def summary(data: Collection = Depends(collection)):
    incidents = data.get('incidents')
    threats = data.get('threats')
    return {'users': len(data.get('users')),
            'assets': len(data.get('assets')),
            'open_incidents': sum(1 for i in incidents if i.get('status') in OPEN_INCIDENT_STATES),
            'critical_threats': sum(1 for t in threats if t.get('severity') == 'Critical'),
            'sources': data.status()}


@r.get('/incidents', summary='Generate incident report',
        description='Incident statistics: total records and distribution by severity and lifecycle status.',
        response_model=IncidentReport)
def incidents(data: Collection = Depends(collection)):
    records = data.get('incidents')
    return {'total_incidents': len(records),
            'incidents_by_severity': tally(records, 'severity'),
            'incidents_by_status': tally(records, 'status'),
            'sources': data.status()}


@r.get('/assets', summary='Generate asset report',
        description='Asset statistics: total records, count of critical assets and distribution by asset type.',
        response_model=AssetReport)
def assets(data: Collection = Depends(collection)):
    records = data.get('assets')
    return {'total_assets': len(records),
            'critical_assets': sum(1 for a in records if a.get('criticality') == 'Critical'),
            'assets_by_type': tally(records, 'asset_type'),
            'sources': data.status()}


@r.get('/threats', summary='Generate threat report',
        description='Threat intelligence statistics: totals, distribution by severity and type, and the most '
                    'recently added indicators.',
        response_model=ThreatReport)
def threats(data: Collection = Depends(collection)):
    records = data.get('threats')
    recent = sorted(records, key=lambda t: (t.get('created_at') or '', t.get('id') or 0), reverse=True)
    return {'total_threats': len(records),
            'threats_by_severity': tally(records, 'severity'),
            'threats_by_type': tally(records, 'threat_type'),
            'recent_threats': recent[:RECENT_THREATS],
            'sources': data.status()}


@r.get('/vulnerabilities', summary='Generate vulnerability report',
        description='Vulnerability statistics: totals, distribution by severity and status, and the count of '
                    'critical vulnerabilities.',
        response_model=VulnerabilityReport)
def vulnerabilities(data: Collection = Depends(collection)):
    records = data.get('vulnerabilities')
    return {'total_vulnerabilities': len(records),
            'vulnerabilities_by_severity': tally(records, 'severity'),
            'vulnerabilities_by_status': tally(records, 'status'),
            'critical_vulnerabilities': sum(1 for v in records if v.get('severity') == 'Critical'),
            'sources': data.status()}


@r.get('/activity', summary='Generate activity report',
        description='Security activity statistics derived from audit records: total activities, total and failed '
                    'login attempts, and the most frequently performed actions.',
        response_model=ActivityReport)
def activity(data: Collection = Depends(collection)):
    records = data.get('logs')
    actions = Counter(record.get('action') or 'Unspecified' for record in records)
    ranked = sorted(actions.items(), key=lambda item: (-item[1], item[0]))
    return {'total_activities': len(records),
            'login_attempts': actions['Login'] + actions['Login failed'],
            'failed_login_attempts': actions['Login failed'],
            'most_performed_actions': [{'action': name, 'count': count} for name, count in ranked],
            'sources': data.status()}


app.include_router(r)
