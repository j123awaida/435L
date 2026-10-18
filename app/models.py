from enum import Enum
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
Severity = Literal['Low','Medium','High','Critical']
VStatus = Literal['Open','Under Investigation','In Progress','Resolved','Closed']
NType = Literal['Incident Assignment','Security Alert','System Notification','Threat Alert','Vulnerability Alert']
CVE = Annotated[str, StringConstraints(pattern=r'^CVE-\d{4}-\d{4,}$', max_length=40)]

class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Login(StrictModel):
    username: Text
    password: Text

class VulnerabilityCreate(StrictModel):
    title: Text
    description: Text
    cve_identifier: CVE
    cvss_score: float = Field(ge=0, le=10, allow_inf_nan=False)
    severity: Severity
    asset_id: int = Field(gt=0)
    discovery_source: Text

class VulnerabilityUpdate(StrictModel):
    description: Text | None = None
    severity: Severity | None = None
    status: VStatus | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10, allow_inf_nan=False)
    @model_validator(mode='after')
    def nonempty(self):
        if not self.model_fields_set or any(getattr(self,k) is None for k in self.model_fields_set):
            raise ValueError('Provide at least one non-null update field')
        return self

class NotificationCreate(StrictModel):
    user_id: int = Field(gt=0)
    title: Text
    message: Text
    notification_type: NType
    severity: Severity

class PlaybookCreate(StrictModel):
    name: Text
    description: Text
    incident_category: Text
    severity: Severity

class ActionCreate(StrictModel):
    description: Text
    step_number: int = Field(gt=0, strict=True)
    assigned_user_id: int | None = Field(default=None, gt=0)

class ActionUpdate(StrictModel):
    status: Literal['Pending','In Progress','Completed']
    assigned_user_id: int | None = Field(default=None, gt=0)

class VulnerabilityRecord(VulnerabilityCreate):
    id: int
    status: VStatus
    created_at: str
    resolution_date: str | None

class NotificationRecord(NotificationCreate):
    id: int
    status: Literal['Unread','Read']
    created_at: str
    read_date: str | None

class PlaybookRecord(PlaybookCreate):
    id: int
    created_by: int
    created_at: str

class ActionRecord(ActionCreate):
    id: int
    playbook_id: int
    status: Literal['Pending','In Progress','Completed']
    completion_date: str | None

class ActionHistory(StrictModel):
    id: int
    action_id: int
    playbook_id: int
    actor_id: int
    old_status: Literal['Pending','In Progress','Completed'] | None
    new_status: Literal['Pending','In Progress','Completed']
    assigned_user_id: int | None
    recorded_at: str

class PlaybookDetail(PlaybookRecord):
    actions: list[ActionRecord]
    execution_history: list[ActionHistory]

class Message(StrictModel):
    message: str
