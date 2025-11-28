from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Any
from app.models.security_event import ThreatLevel


class SecurityEventCreate(BaseModel):
    ip_address: str
    endpoint: str
    method: str
    threat_type: str
    threat_level: ThreatLevel
    payload: Optional[dict[str, Any]] = None
    user_agent: Optional[str] = None
    blocked: int = 1


class SecurityEventResponse(BaseModel):
    id: int
    ip_address: str
    endpoint: str
    method: str
    threat_type: str
    threat_level: ThreatLevel
    payload: Optional[dict[str, Any]]
    user_agent: Optional[str]
    blocked: int
    created_at: datetime

    class Config:
        from_attributes = True

