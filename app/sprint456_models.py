"""Validated public contracts for Services 4–6 (Mohammad Nasrallah)."""
import re
from ipaddress import ip_address
from typing import Annotated, Literal
from pydantic import Field, StringConstraints, field_validator, model_validator
from .models import StrictModel, Text, Severity

PREFIX = '/Mohammad-Nasrallah'

ThreatType = Literal['IP Address', 'Domain', 'File Hash', 'Malware Signature', 'Other']
LogSeverity = Literal['Information', 'Warning', 'Error', 'Critical']
ThreatValue = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
Source = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]

# One hex digest length per supported algorithm: MD5, SHA-1, SHA-256, SHA-512.
HASH_LENGTHS = {32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512'}
DOMAIN_LABEL = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')


def validate_threat_value(threat_type, value):
    """Return the canonical indicator for a type, or raise ValueError.

    Canonicalizing here means the uniqueness constraint compares equivalent
    indicators: 192.0.2.1 and 192.000.002.001 cannot both be stored.
    """
    if threat_type == 'IP Address':
        try:
            return str(ip_address(value))
        except ValueError:
            raise ValueError('Provide a valid IPv4 or IPv6 address')
    if threat_type == 'Domain':
        candidate = value.rstrip('.').lower()
        if '/' in candidate or ':' in candidate or '@' in candidate:
            raise ValueError('Provide a bare domain name without scheme, port or path')
        labels = candidate.split('.')
        if len(candidate) > 253 or len(labels) < 2 or not all(DOMAIN_LABEL.fullmatch(l) for l in labels):
            raise ValueError('Provide a valid domain name such as example.test')
        if labels[-1].isdigit():
            raise ValueError('Provide a valid domain name such as example.test')
        return candidate
    if threat_type == 'File Hash':
        candidate = value.lower()
        if len(candidate) not in HASH_LENGTHS or not re.fullmatch(r'[0-9a-f]+', candidate):
            raise ValueError('Provide an MD5, SHA-1, SHA-256 or SHA-512 hexadecimal digest')
        return candidate
    return value


class ThreatFields(StrictModel):
    @model_validator(mode='after')
    def canonical_value(self):
        if getattr(self, 'threat_type', None) and getattr(self, 'threat_value', None):
            self.threat_value = validate_threat_value(self.threat_type, self.threat_value)
        return self


class ThreatCreate(ThreatFields):
    threat_type: ThreatType
    threat_value: ThreatValue
    description: Text
    severity: Severity
    source: Source


class ThreatUpdate(StrictModel):
    """Type and value are immutable: editing them would bypass the uniqueness constraint."""
    description: Text | None = None
    severity: Severity | None = None
    source: Source | None = None

    @model_validator(mode='after')
    def nonempty(self):
        if not self.model_fields_set or any(getattr(self, k) is None for k in self.model_fields_set):
            raise ValueError('Provide at least one non-null update field')
        return self


class ThreatRecord(StrictModel):
    id: int
    threat_type: ThreatType
    threat_value: str
    description: str
    severity: Severity
    source: str
    created_at: str


class LogCreate(StrictModel):
    """Accepted from administrators and from Services 1–3 and 7–9 during integration."""
    user_id: int | None = Field(default=None, gt=0)
    action: Text
    description: Text
    severity: LogSeverity
    related_service: Source


class LogRecord(StrictModel):
    id: int
    user_id: int | None
    action: str
    description: str
    severity: LogSeverity
    related_service: str
    created_at: str


class SourceStatus(StrictModel):
    """Records whether each report figure came from a teammate's API or the shared database."""
    name: str
    origin: Literal['api', 'database']
    detail: str | None = None


class SummaryReport(StrictModel):
    users: int
    assets: int
    open_incidents: int
    critical_threats: int
    sources: list[SourceStatus]


class IncidentReport(StrictModel):
    total_incidents: int
    incidents_by_severity: dict[str, int]
    incidents_by_status: dict[str, int]
    sources: list[SourceStatus]


class AssetReport(StrictModel):
    total_assets: int
    critical_assets: int
    assets_by_type: dict[str, int]
    sources: list[SourceStatus]


class ThreatReport(StrictModel):
    total_threats: int
    threats_by_severity: dict[str, int]
    threats_by_type: dict[str, int]
    recent_threats: list[ThreatRecord]
    sources: list[SourceStatus]


class VulnerabilityReport(StrictModel):
    total_vulnerabilities: int
    vulnerabilities_by_severity: dict[str, int]
    vulnerabilities_by_status: dict[str, int]
    critical_vulnerabilities: int
    sources: list[SourceStatus]


class ActivityReport(StrictModel):
    total_activities: int
    login_attempts: int
    failed_login_attempts: int
    most_performed_actions: list[dict[str, int | str]]
    sources: list[SourceStatus]
