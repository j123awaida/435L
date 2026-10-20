"""Validated public contracts for Services 1–3. Passwords never appear in records."""
import re
from ipaddress import ip_address
from typing import Annotated, Literal
from pydantic import Field, StringConstraints, field_validator, model_validator
from .models import StrictModel, Text, Severity

PREFIX = '/Hassan-Nasrallah'
Role = Literal['admin', 'analyst', 'employee', 'auditor']
AccountStatus = Literal['Active', 'Inactive', 'Suspended']
AssetType = Literal['Server', 'Workstation', 'Database', 'Application', 'Network Device', 'Cloud Resource']
AssetStatus = Literal['Active', 'Inactive', 'Under Maintenance']
IncidentStatus = Literal['Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed']
Username = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_.-]{3,64}$')]
Password = Annotated[str, StringConstraints(min_length=12, max_length=128)]
Email = Annotated[str, StringConstraints(strip_whitespace=True, max_length=254)]

class ProfileFields(StrictModel):
    @field_validator('email', check_fields=False)
    @classmethod
    def valid_email(cls, value):
        if value is not None and not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
            raise ValueError('Provide a valid email address')
        return value.lower() if value else value

class Register(ProfileFields):
    full_name: Text
    username: Username
    email: Email
    password: Password
    department: Text
    role: Role

    @field_validator('username')
    @classmethod
    def routable_username(cls, value):
        if value == 'session':
            raise ValueError('Username is reserved by the session endpoint')
        return value

    @field_validator('password')
    @classmethod
    def strong_password(cls, value):
        if not (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value) and any(not c.isalnum() for c in value)):
            raise ValueError('Password needs uppercase, lowercase, digit and symbol')
        return value

class UserUpdate(ProfileFields):
    full_name: Text | None = None
    email: Email | None = None
    department: Text | None = None

    @model_validator(mode='after')
    def nonempty(self):
        if not self.model_fields_set or any(getattr(self, k) is None for k in self.model_fields_set):
            raise ValueError('Provide at least one non-null update field')
        return self

class UserRecord(StrictModel):
    id: int
    full_name: str
    username: str
    email: str | None
    department: str | None
    role: Role
    account_status: AccountStatus
    created_at: str | None
    last_login_at: str | None

class RoleChange(StrictModel):
    role: Role

class AccountChange(StrictModel):
    account_status: AccountStatus

class TokenRecord(StrictModel):
    access_token: str
    token_type: str
    expires_in: int
    user_id: int
    role: Role

class UserLogin(StrictModel):
    username: Text
    # Preserve password whitespace exactly as supplied at registration.
    password: Annotated[str, StringConstraints(min_length=1, max_length=128)]

class AssetFields(StrictModel):
    @field_validator('ip_address', check_fields=False)
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value)) if value is not None else value

class AssetCreate(AssetFields):
    name: Text
    asset_type: AssetType
    ip_address: Text
    operating_system: Text | None = None
    department: Text
    owner_id: int = Field(gt=0, strict=True)
    location: Text
    criticality: Severity
    status: AssetStatus = 'Active'

class AssetUpdate(AssetFields):
    name: Text | None = None
    asset_type: AssetType | None = None
    ip_address: Text | None = None
    operating_system: Text | None = None
    department: Text | None = None
    owner_id: int | None = Field(default=None, gt=0, strict=True)
    location: Text | None = None
    criticality: Severity | None = None
    status: AssetStatus | None = None

    @model_validator(mode='after')
    def nonempty(self):
        if not self.model_fields_set or any(getattr(self, k) is None and k != 'operating_system' for k in self.model_fields_set):
            raise ValueError('Provide at least one non-null update field')
        return self

class AssetRecord(StrictModel):
    id: int
    name: str
    owner_id: int
    asset_type: AssetType | None
    ip_address: str | None
    operating_system: str | None
    department: str | None
    location: str | None
    criticality: Severity | None
    status: AssetStatus | None
    created_at: str | None

class AssetDetail(AssetRecord):
    incident_ids: list[int]
    vulnerability_ids: list[int]

class HistoryRecord(StrictModel):
    id: int
    asset_id: int
    actor_id: int
    action: str
    snapshot: AssetRecord
    created_at: str

class IncidentCreate(StrictModel):
    title: Text
    description: Text
    category: Text
    severity: Severity
    reporter_id: int = Field(gt=0, strict=True)
    asset_id: int = Field(gt=0, strict=True)

class Assignment(StrictModel):
    analyst_id: int = Field(gt=0, strict=True)

class StatusChange(StrictModel):
    status: IncidentStatus

class NoteCreate(StrictModel):
    content: Text

class NoteRecord(NoteCreate):
    id: int
    incident_id: int
    analyst_id: int
    created_at: str

class IncidentRecord(IncidentCreate):
    id: int
    assigned_analyst_id: int | None
    status: IncidentStatus
    created_at: str
    resolution_date: str | None

class IncidentDetail(IncidentRecord):
    investigation_notes: list[NoteRecord]
