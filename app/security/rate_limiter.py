import time
from typing import Optional
from app.core.redis_client import get_redis
from app.config import settings
from app.core.logger import logger


class RateLimiter:
    def __init__(self):
        self.redis = get_redis()
        self.requests_per_minute = settings.rate_limit_requests_per_minute
        self.burst_limit = settings.rate_limit_burst
        self.by_ip = settings.rate_limit_by_ip

    def check_limit(self, identifier: str, endpoint: str = "*") -> tuple[bool, Optional[int]]:
        if not settings.rate_limiting_enabled:
            return True, None
        
        key = f"rate_limit:{identifier}:{endpoint}"
        
        try:
            current = self.redis.get(key)
            
            if current is None:
                self.redis.setex(key, 60, 1)
                return True, None
            
            count = int(current)
            
            if count >= self.requests_per_minute:
                ttl = self.redis.ttl(key)
                logger.warning(
                    "rate_limit_exceeded",
                    identifier=identifier,
                    endpoint=endpoint,
                    count=count
                )
                return False, ttl
            
            self.redis.incr(key)
            return True, None
            
        except Exception as e:
            logger.error("rate_limit_error", error=str(e))
            return True, None

    def check_burst(self, identifier: str, endpoint: str = "*") -> bool:
        if not settings.rate_limiting_enabled:
            return True
        
        key = f"rate_limit_burst:{identifier}:{endpoint}"
        
        try:
            current = self.redis.get(key)
            
            if current is None:
                self.redis.setex(key, 1, 1)
                return True
            
            count = int(current)
            
            if count >= self.burst_limit:
                logger.warning(
                    "burst_limit_exceeded",
                    identifier=identifier,
                    endpoint=endpoint
                )
                return False
            
            self.redis.incr(key)
            return True
            
        except Exception as e:
            logger.error("rate_limit_burst_error", error=str(e))
            return True

