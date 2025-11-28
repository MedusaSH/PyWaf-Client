from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.sql import func
from app.core.database import Base


class TLSFingerprint(Base):
    __tablename__ = "tls_fingerprints"

    id = Column(Integer, primary_key=True, index=True)
    fingerprint = Column(String, unique=True, index=True, nullable=False)
    fingerprint_hash = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text)
    is_whitelisted = Column(Boolean, default=False, index=True)
    is_blacklisted = Column(Boolean, default=False, index=True)
    threat_level = Column(String, default="unknown")
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    request_count = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)
    fingerprint_metadata = Column(Text)

