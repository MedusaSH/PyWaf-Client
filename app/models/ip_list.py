from sqlalchemy import Column, Integer, String, DateTime, Enum
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class IPListType(enum.Enum):
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"


class IPList(Base):
    __tablename__ = "ip_lists"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    list_type = Column(Enum(IPListType), index=True)
    reason = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)

