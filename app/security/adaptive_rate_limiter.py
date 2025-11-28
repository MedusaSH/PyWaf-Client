import time
from typing import Optional, Dict
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.config import settings
from app.security.ip_reputation import IPReputationEngine
from app.security.behavioral_analyzer import BehavioralAnalyzer


class AdaptiveRateLimiter:
    def __init__(self):
        self.redis = get_redis()
        self.reputation_engine = IPReputationEngine()
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        self.base_requests_per_minute = settings.rate_limit_requests_per_minute
        self.base_burst_limit = settings.rate_limit_burst
        
        self.clean_multiplier = 1.5
        self.suspicious_multiplier = 0.5
        self.malicious_multiplier = 0.1

    def get_adaptive_limits(
        self,
        ip_address: str,
        reputation: Dict,
        behavioral_data: Dict,
        db
    ) -> Dict[str, int]:
        base_rpm = self.base_requests_per_minute
        base_burst = self.base_burst_limit
        
        reputation_status = reputation.get("status", "clean")
        reputation_score = reputation.get("total_score", 0.0)
        
        if reputation_status == "malicious":
            multiplier = self.malicious_multiplier
        elif reputation_status == "suspicious":
            multiplier = self.suspicious_multiplier
        else:
            multiplier = self.clean_multiplier
        
        if behavioral_data.get("is_automated", False):
            multiplier *= 0.5
        
        if behavioral_data.get("anomaly_score", 0.0) > 0.7:
            multiplier *= 0.3
        
        adaptive_rpm = max(int(base_rpm * multiplier), 1)
        adaptive_burst = max(int(base_burst * multiplier), 1)
        
        return {
            "requests_per_minute": adaptive_rpm,
            "burst_limit": adaptive_burst,
            "multiplier": multiplier,
            "reason": self._get_limit_reason(reputation_status, behavioral_data)
        }

    def _get_limit_reason(self, reputation_status: str, behavioral_data: Dict) -> str:
        reasons = []
        
        if reputation_status == "malicious":
            reasons.append("malicious_reputation")
        elif reputation_status == "suspicious":
            reasons.append("suspicious_reputation")
        
        if behavioral_data.get("is_automated"):
            reasons.append("automated_behavior")
        
        if behavioral_data.get("anomaly_score", 0.0) > 0.7:
            reasons.append("anomalous_activity")
        
        return ", ".join(reasons) if reasons else "normal"

    def check_adaptive_limit(
        self,
        identifier: str,
        endpoint: str,
        reputation: Dict,
        behavioral_data: Dict,
        db
    ) -> tuple[bool, Optional[int], Dict]:
        limits = self.get_adaptive_limits(identifier, reputation, behavioral_data, db)
        
        rpm = limits["requests_per_minute"]
        burst = limits["burst_limit"]
        
        burst_key = f"rate_limit_burst:{identifier}:{endpoint}"
        rpm_key = f"rate_limit:{identifier}:{endpoint}"
        
        try:
            burst_current = self.redis.get(burst_key)
            if burst_current is None:
                self.redis.setex(burst_key, 1, 1)
            else:
                burst_count = int(burst_current)
                if burst_count >= burst:
                    logger.warning(
                        "adaptive_burst_limit_exceeded",
                        identifier=identifier,
                        endpoint=endpoint,
                        limit=burst,
                        reason=limits["reason"]
                    )
                    return False, None, limits
                self.redis.incr(burst_key)
            
            rpm_current = self.redis.get(rpm_key)
            if rpm_current is None:
                self.redis.setex(rpm_key, 60, 1)
                return True, None, limits
            
            rpm_count = int(rpm_current)
            if rpm_count >= rpm:
                ttl = self.redis.ttl(rpm_key)
                logger.warning(
                    "adaptive_rate_limit_exceeded",
                    identifier=identifier,
                    endpoint=endpoint,
                    limit=rpm,
                    reason=limits["reason"]
                )
                return False, ttl, limits
            
            self.redis.incr(rpm_key)
            return True, None, limits
            
        except Exception as e:
            logger.error("adaptive_rate_limit_error", error=str(e))
            return True, None, limits

