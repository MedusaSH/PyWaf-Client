from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime
from app.models.ip_list import IPList, IPListType
from app.core.redis_client import get_redis
from app.core.logger import logger


class IPManager:
    def __init__(self):
        self.redis = get_redis()
        self.cache_ttl = 3600

    def is_whitelisted(self, ip_address: str, db: Session) -> bool:
        cache_key = f"ip:whitelist:{ip_address}"
        
        cached = self.redis.get(cache_key)
        if cached is not None:
            return cached == "1"
        
        ip_entry = db.query(IPList).filter(
            IPList.ip_address == ip_address,
            IPList.list_type == IPListType.WHITELIST
        ).first()
        
        if ip_entry:
            if ip_entry.expires_at and ip_entry.expires_at < datetime.utcnow():
                db.delete(ip_entry)
                db.commit()
                self.redis.setex(cache_key, self.cache_ttl, "0")
                return False
            
            self.redis.setex(cache_key, self.cache_ttl, "1")
            return True
        
        self.redis.setex(cache_key, self.cache_ttl, "0")
        return False

    def is_blacklisted(self, ip_address: str, db: Session) -> bool:
        cache_key = f"ip:blacklist:{ip_address}"
        
        cached = self.redis.get(cache_key)
        if cached is not None:
            return cached == "1"
        
        ip_entry = db.query(IPList).filter(
            IPList.ip_address == ip_address,
            IPList.list_type == IPListType.BLACKLIST
        ).first()
        
        if ip_entry:
            if ip_entry.expires_at and ip_entry.expires_at < datetime.utcnow():
                db.delete(ip_entry)
                db.commit()
                self.redis.setex(cache_key, self.cache_ttl, "0")
                return False
            
            self.redis.setex(cache_key, self.cache_ttl, "1")
            return True
        
        self.redis.setex(cache_key, self.cache_ttl, "0")
        return False

    def add_to_whitelist(
        self,
        ip_address: str,
        reason: Optional[str],
        expires_at: Optional[datetime],
        db: Session
    ) -> IPList:
        existing = db.query(IPList).filter(IPList.ip_address == ip_address).first()
        
        if existing:
            existing.list_type = IPListType.WHITELIST
            existing.reason = reason
            existing.expires_at = expires_at
        else:
            existing = IPList(
                ip_address=ip_address,
                list_type=IPListType.WHITELIST,
                reason=reason,
                expires_at=expires_at
            )
            db.add(existing)
        
        db.commit()
        db.refresh(existing)
        
        cache_key = f"ip:whitelist:{ip_address}"
        self.redis.setex(cache_key, self.cache_ttl, "1")
        
        return existing

    def add_to_blacklist(
        self,
        ip_address: str,
        reason: Optional[str],
        expires_at: Optional[datetime],
        db: Session
    ) -> IPList:
        existing = db.query(IPList).filter(IPList.ip_address == ip_address).first()
        
        if existing:
            existing.list_type = IPListType.BLACKLIST
            existing.reason = reason
            existing.expires_at = expires_at
        else:
            existing = IPList(
                ip_address=ip_address,
                list_type=IPListType.BLACKLIST,
                reason=reason,
                expires_at=expires_at
            )
            db.add(existing)
        
        db.commit()
        db.refresh(existing)
        
        cache_key = f"ip:blacklist:{ip_address}"
        self.redis.setex(cache_key, self.cache_ttl, "1")
        
        return existing

