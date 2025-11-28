from sqlalchemy import Column, Integer, String, DateTime, JSON, Enum
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class ThreatLevel(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    endpoint = Column(String, index=True)
    method = Column(String)
    threat_type = Column(String, index=True)
    threat_level = Column(Enum(ThreatLevel), index=True)
    payload = Column(JSON)
    user_agent = Column(String)
    blocked = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

