import time
from typing import Optional, Dict, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.models.security_event import SecurityEvent
from app.config import settings


class IPReputationEngine:
    def __init__(self):
        self.redis = get_redis()
        self.cache_ttl = 300
        self.reputation_ttl = 3600
        
        self.threat_intelligence_weight = 0.3
        self.behavioral_weight = 0.4
        self.temporal_weight = 0.2
        self.network_weight = 0.1
        
        self.malicious_threshold = 70.0
        self.suspicious_threshold = 40.0

    def calculate_reputation_score(
        self,
        ip_address: str,
        db: Session,
        current_request_data: Optional[Dict] = None
    ) -> Dict[str, float]:
        cache_key = f"ip:reputation:{ip_address}"
        
        cached = self.redis.get(cache_key)
        if cached:
            try:
                return eval(cached)
            except:
                pass
        
        threat_score = self._calculate_threat_intelligence_score(ip_address, db)
        behavioral_score = self._calculate_behavioral_score(ip_address, db)
        temporal_score = self._calculate_temporal_score(ip_address, db)
        network_score = self._calculate_network_score(ip_address, db)
        
        total_score = (
            threat_score * self.threat_intelligence_weight +
            behavioral_score * self.behavioral_weight +
            temporal_score * self.temporal_weight +
            network_score * self.network_weight
        )
        
        reputation = {
            "total_score": round(total_score, 2),
            "threat_intelligence": round(threat_score, 2),
            "behavioral": round(behavioral_score, 2),
            "temporal": round(temporal_score, 2),
            "network": round(network_score, 2),
            "status": self._get_status(total_score),
            "timestamp": time.time()
        }
        
        self.redis.setex(cache_key, self.reputation_ttl, str(reputation))
        return reputation

    def _calculate_threat_intelligence_score(self, ip_address: str, db: Session) -> float:
        since = datetime.utcnow() - timedelta(hours=24)
        
        blocked_count = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since,
            SecurityEvent.blocked == 1
        ).scalar() or 0
        
        total_count = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since
        ).scalar() or 0
        
        if total_count == 0:
            return 0.0
        
        block_ratio = (blocked_count / total_count) * 100
        
        threat_types = db.query(
            SecurityEvent.threat_type,
            func.count(SecurityEvent.id).label("count")
        ).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since,
            SecurityEvent.blocked == 1
        ).group_by(SecurityEvent.threat_type).all()
        
        severity_multiplier = 1.0
        for threat_type, count in threat_types:
            if threat_type in ["sql_injection", "command_injection"]:
                severity_multiplier += 0.3
            elif threat_type in ["xss", "path_traversal"]:
                severity_multiplier += 0.2
        
        score = min(block_ratio * severity_multiplier, 100.0)
        return score

    def _calculate_behavioral_score(self, ip_address: str, db: Session) -> float:
        since = datetime.utcnow() - timedelta(hours=1)
        
        events = db.query(SecurityEvent).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since
        ).order_by(desc(SecurityEvent.created_at)).limit(100).all()
        
        if not events:
            return 0.0
        
        unique_endpoints = len(set(e.endpoint for e in events))
        unique_user_agents = len(set(e.user_agent for e in events if e.user_agent))
        request_rate = len(events) / 60.0
        
        endpoint_diversity_score = min((unique_endpoints / len(events)) * 100, 50.0)
        user_agent_score = 100.0 if unique_user_agents == 1 else max(0, 100 - (unique_user_agents * 10))
        rate_score = min(request_rate * 2, 100.0)
        
        behavioral_score = (
            endpoint_diversity_score * 0.3 +
            user_agent_score * 0.2 +
            rate_score * 0.5
        )
        
        return min(behavioral_score, 100.0)

    def _calculate_temporal_score(self, ip_address: str, db: Session) -> float:
        now = datetime.utcnow()
        hour = now.hour
        
        events_last_hour = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= now - timedelta(hours=1)
        ).scalar() or 0
        
        events_same_hour_yesterday = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= now - timedelta(days=1, hours=1),
            SecurityEvent.created_at < now - timedelta(days=1),
            func.extract('hour', SecurityEvent.created_at) == hour
        ).scalar() or 0
        
        if events_same_hour_yesterday == 0:
            return 0.0 if events_last_hour < 10 else min(events_last_hour / 10, 100.0)
        
        ratio = events_last_hour / events_same_hour_yesterday if events_same_hour_yesterday > 0 else 0
        
        if ratio > 5.0:
            return 100.0
        elif ratio > 2.0:
            return 50.0
        else:
            return 0.0

    def _calculate_network_score(self, ip_address: str, db: Session) -> float:
        since = datetime.utcnow() - timedelta(hours=24)
        
        connection_attempts = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since
        ).scalar() or 0
        
        failed_connections = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since,
            SecurityEvent.blocked == 1
        ).scalar() or 0
        
        if connection_attempts == 0:
            return 0.0
        
        failure_rate = (failed_connections / connection_attempts) * 100
        
        if connection_attempts > 1000:
            volume_penalty = min((connection_attempts - 1000) / 100, 50.0)
            return min(failure_rate + volume_penalty, 100.0)
        
        return failure_rate

    def _get_status(self, score: float) -> str:
        if score >= self.malicious_threshold:
            return "malicious"
        elif score >= self.suspicious_threshold:
            return "suspicious"
        else:
            return "clean"

    def is_malicious(self, ip_address: str, db: Session) -> bool:
        reputation = self.calculate_reputation_score(ip_address, db)
        return reputation["status"] == "malicious"

    def is_suspicious(self, ip_address: str, db: Session) -> bool:
        reputation = self.calculate_reputation_score(ip_address, db)
        return reputation["status"] in ["malicious", "suspicious"]

    def get_reputation(self, ip_address: str, db: Session) -> Dict[str, float]:
        return self.calculate_reputation_score(ip_address, db)

    def update_reputation(self, ip_address: str, db: Session, event_data: Dict):
        cache_key = f"ip:reputation:{ip_address}"
        self.redis.delete(cache_key)
        
        self.calculate_reputation_score(ip_address, db, event_data)

