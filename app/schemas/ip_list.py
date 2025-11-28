from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models.ip_list import IPListType


class IPListCreate(BaseModel):
    ip_address: str
    list_type: IPListType
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None


class IPListResponse(BaseModel):
    id: int
    ip_address: str
    list_type: IPListType
    reason: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True

