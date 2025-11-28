import time
import hashlib
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.models.security_event import SecurityEvent


class BehavioralAnalyzer:
    def __init__(self):
        self.redis = get_redis()
        self.fingerprint_ttl = 3600
        self.session_ttl = 1800

    def generate_fingerprint(self, request_data: Dict) -> str:
        components = [
            request_data.get("user_agent", ""),
            request_data.get("accept_language", ""),
            request_data.get("accept_encoding", ""),
            str(request_data.get("headers", {}).get("sec-ch-ua", "")),
        ]
        
        fingerprint_string = "|".join(components)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]

    def analyze_request_pattern(
        self,
        ip_address: str,
        endpoint: str,
        fingerprint: str,
        db: Session
    ) -> Dict[str, any]:
        since = datetime.utcnow() - timedelta(minutes=5)
        
        recent_requests = db.query(SecurityEvent).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since
        ).order_by(SecurityEvent.created_at.desc()).limit(50).all()
        
        if not recent_requests:
            return {
                "is_bot": False,
                "is_scraper": False,
                "is_automated": False,
                "confidence": 0.0,
                "patterns": []
            }
        
        patterns = []
        confidence = 0.0
        
        endpoint_diversity = len(set(r.endpoint for r in recent_requests))
        total_requests = len(recent_requests)
        
        if endpoint_diversity / total_requests > 0.8 and total_requests > 20:
            patterns.append("high_endpoint_diversity")
            confidence += 0.3
        
        time_intervals = []
        for i in range(1, len(recent_requests)):
            delta = (recent_requests[i-1].created_at - recent_requests[i].created_at).total_seconds()
            time_intervals.append(delta)
        
        if time_intervals:
            avg_interval = sum(time_intervals) / len(time_intervals)
            interval_variance = sum((x - avg_interval) ** 2 for x in time_intervals) / len(time_intervals)
            
            if interval_variance < 0.1 and avg_interval < 2.0:
                patterns.append("regular_timing")
                confidence += 0.4
        
        user_agents = [r.user_agent for r in recent_requests if r.user_agent]
        if user_agents:
            unique_ua = len(set(user_agents))
            if unique_ua == 1 and total_requests > 10:
                patterns.append("single_user_agent")
                confidence += 0.2
        
        methods = [r.method for r in recent_requests]
        if methods.count("GET") / len(methods) > 0.95:
            patterns.append("mostly_get_requests")
            confidence += 0.1
        
        is_bot = confidence >= 0.5
        is_scraper = "high_endpoint_diversity" in patterns and "regular_timing" in patterns
        is_automated = is_bot or is_scraper
        
        return {
            "is_bot": is_bot,
            "is_scraper": is_scraper,
            "is_automated": is_automated,
            "confidence": min(confidence, 1.0),
            "patterns": patterns,
            "endpoint_diversity": endpoint_diversity,
            "total_requests": total_requests
        }

    def track_session(self, ip_address: str, fingerprint: str, endpoint: str):
        session_key = f"session:{ip_address}:{fingerprint}"
        endpoint_key = f"{session_key}:endpoints"
        
        self.redis.sadd(endpoint_key, endpoint)
        self.redis.expire(endpoint_key, self.session_ttl)
        
        self.redis.incr(session_key)
        self.redis.expire(session_key, self.session_ttl)

    def get_session_stats(self, ip_address: str, fingerprint: str) -> Dict:
        session_key = f"session:{ip_address}:{fingerprint}"
        endpoint_key = f"{session_key}:endpoints"
        
        request_count = int(self.redis.get(session_key) or 0)
        endpoints = self.redis.smembers(endpoint_key) or set()
        
        return {
            "request_count": request_count,
            "unique_endpoints": len(endpoints),
            "endpoints": list(endpoints)
        }

    def detect_anomalous_behavior(
        self,
        ip_address: str,
        current_request: Dict,
        db: Session
    ) -> Dict[str, any]:
        fingerprint = self.generate_fingerprint(current_request)
        
        pattern_analysis = self.analyze_request_pattern(
            ip_address,
            current_request.get("endpoint", ""),
            fingerprint,
            db
        )
        
        self.track_session(ip_address, fingerprint, current_request.get("endpoint", ""))
        
        session_stats = self.get_session_stats(ip_address, fingerprint)
        
        anomaly_score = 0.0
        anomalies = []
        
        if pattern_analysis["is_automated"]:
            anomaly_score += 0.4
            anomalies.append("automated_behavior")
        
        if session_stats["request_count"] > 100:
            anomaly_score += 0.3
            anomalies.append("high_request_volume")
        
        if session_stats["unique_endpoints"] > 50:
            anomaly_score += 0.3
            anomalies.append("excessive_endpoint_diversity")
        
        return {
            "is_anomalous": anomaly_score >= 0.5,
            "anomaly_score": min(anomaly_score, 1.0),
            "anomalies": anomalies,
            "pattern_analysis": pattern_analysis,
            "session_stats": session_stats,
            "fingerprint": fingerprint
        }

