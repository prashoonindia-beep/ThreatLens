from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict

IOCType = Literal["ip", "domain", "url", "hash", "email", "cve"]
Severity = Literal["low", "medium", "high", "critical"]
TLPLevel = Literal["clear", "green", "amber", "red"]
IOCStatus = Literal["active", "inactive", "expired", "false_positive"]

class IOCCreate(BaseModel):
    indicator: str = Field(min_length=1, max_length=500)
    indicator_type: IOCType
    severity: Severity = "medium"
    source: str = Field(default="manual", min_length=1, max_length=100)
    confidence: int = Field(default=50, ge=0, le=100)
    tlp: TLPLevel = "clear"
    status: IOCStatus = "active"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    tags: str = "[]"
    attack_techniques: str = "[]"
    analyst_notes: str | None = None

class IOCResponse(BaseModel):
    id: int
    indicator: str
    indicator_type: str
    severity: str
    threat_score: int
    source: str
    confidence: int
    tlp: str
    status: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    tags: str
    attack_techniques: str
    analyst_notes: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)
