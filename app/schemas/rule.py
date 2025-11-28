from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Any


class RuleCreate(BaseModel):
    name: str
    enabled: bool = True
    pattern: Optional[str] = None
    threat_type: str
    sensitivity: str = "medium"
    custom_config: Optional[dict[str, Any]] = None


class RuleResponse(BaseModel):
    id: int
    name: str
    enabled: bool
    pattern: Optional[str]
    threat_type: str
    sensitivity: str
    custom_config: Optional[dict[str, Any]]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

