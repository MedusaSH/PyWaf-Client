import hashlib
import time
import secrets
from typing import Optional, Dict, Tuple
from fastapi import Request
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.config import settings


class SYNCookieProtection:
    def __init__(self):
        self.redis = get_redis()
        self.cookie_ttl = 60
        self.secret_key = settings.secret_key.encode()
        self.enabled = getattr(settings, 'syn_cookie_enabled', True)
        self.max_syn_requests_per_ip = getattr(settings, 'syn_cookie_max_requests_per_ip', 10)

    def generate_syn_cookie(
        self,
        source_ip: str,
        source_port: int,
        dest_ip: str,
        dest_port: int,
        sequence_number: Optional[int] = None
    ) -> int:
        if not sequence_number:
            sequence_number = int(time.time() * 1000) & 0xFFFFFFFF
        
        cookie_data = f"{source_ip}:{source_port}:{dest_ip}:{dest_port}:{sequence_number}"
        cookie_hash = hashlib.sha256(
            (cookie_data + self.secret_key.decode()).encode()
        ).hexdigest()
        
        cookie = int(cookie_hash[:8], 16) & 0x7FFFFFFF
        cookie |= (sequence_number & 0xFF) << 24
        
        return cookie

    def verify_syn_cookie(
        self,
        cookie: int,
        source_ip: str,
        source_port: int,
        dest_ip: str,
        dest_port: int
    ) -> Tuple[bool, Optional[int]]:
        sequence_number = (cookie >> 24) & 0xFF
        cookie_value = cookie & 0x7FFFFFFF
        
        expected_cookie = self.generate_syn_cookie(
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            sequence_number
        )
        
        expected_value = expected_cookie & 0x7FFFFFFF
        
        if cookie_value == expected_value:
            return True, sequence_number
        
        return False, None

    def track_syn_request(self, ip_address: str) -> Tuple[bool, int]:
        if not self.enabled:
            return True, 0
        
        key = f"syn_requests:{ip_address}"
        
        try:
            current_count = self.redis.get(key)
            if current_count is None:
                self.redis.setex(key, 60, 1)
                return True, 1
            
            count = int(current_count)
            if count >= self.max_syn_requests_per_ip:
                logger.warning(
                    "syn_flood_detected",
                    ip=ip_address,
                    count=count
                )
                return False, count
            
            self.redis.incr(key)
            return True, count + 1
            
        except Exception as e:
            logger.error("syn_cookie_tracking_error", error=str(e))
            return True, 0

    def should_apply_syn_cookie(self, ip_address: str) -> bool:
        if not self.enabled:
            return False
        
        allowed, count = self.track_syn_request(ip_address)
        return not allowed or count > (self.max_syn_requests_per_ip * 0.7)

    def get_syn_cookie_header(self, request: Request) -> Optional[str]:
        if not self.should_apply_syn_cookie(request.client.host if request.client else "unknown"):
            return None
        
        source_ip = request.client.host if request.client else "unknown"
        source_port = request.client.port if request.client else 0
        dest_ip = request.url.hostname or "localhost"
        dest_port = request.url.port or 80
        
        cookie = self.generate_syn_cookie(source_ip, source_port, dest_ip, dest_port)
        
        return f"X-SYN-Cookie: {cookie}"

    def verify_request_syn_cookie(self, request: Request) -> bool:
        if not self.enabled:
            return True
        
        syn_cookie_header = request.headers.get("X-SYN-Cookie")
        if not syn_cookie_header:
            return False
        
        try:
            cookie = int(syn_cookie_header)
        except ValueError:
            return False
        
        source_ip = request.client.host if request.client else "unknown"
        source_port = request.client.port if request.client else 0
        dest_ip = request.url.hostname or "localhost"
        dest_port = request.url.port or 80
        
        valid, _ = self.verify_syn_cookie(cookie, source_ip, source_port, dest_ip, dest_port)
        
        if not valid:
            logger.warning(
                "invalid_syn_cookie",
                ip=source_ip,
                cookie=syn_cookie_header
            )
        
        return valid

