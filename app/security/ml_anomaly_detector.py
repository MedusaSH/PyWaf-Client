import numpy as np
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.models.security_event import SecurityEvent


class MLAnomalyDetector:
    def __init__(self):
        self.redis = get_redis()
        self.feature_cache_ttl = 300
        
        self.entropy_threshold = 2.0
        self.distribution_threshold = 0.3

    def extract_features(
        self,
        ip_address: str,
        current_request: Dict,
        db: Session
    ) -> Dict[str, float]:
        cache_key = f"ml:features:{ip_address}"
        
        cached = self.redis.get(cache_key)
        if cached:
            try:
                return eval(cached)
            except:
                pass
        
        since = datetime.utcnow() - timedelta(minutes=10)
        
        recent_events = db.query(SecurityEvent).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since
        ).all()
        
        if not recent_events:
            return self._default_features()
        
        endpoints = [e.endpoint for e in recent_events]
        methods = [e.method for e in recent_events]
        timestamps = [e.created_at.timestamp() for e in recent_events]
        
        endpoint_entropy = self._calculate_entropy(endpoints)
        method_entropy = self._calculate_entropy(methods)
        
        time_intervals = []
        for i in range(1, len(timestamps)):
            time_intervals.append(timestamps[i-1] - timestamps[i])
        
        avg_interval = np.mean(time_intervals) if time_intervals else 0.0
        interval_std = np.std(time_intervals) if len(time_intervals) > 1 else 0.0
        
        request_rate = len(recent_events) / 600.0
        
        unique_endpoints = len(set(endpoints))
        endpoint_diversity = unique_endpoints / len(endpoints) if endpoints else 0.0
        
        blocked_ratio = sum(1 for e in recent_events if e.blocked == 1) / len(recent_events)
        
        features = {
            "endpoint_entropy": endpoint_entropy,
            "method_entropy": method_entropy,
            "avg_interval": avg_interval,
            "interval_std": interval_std,
            "request_rate": request_rate,
            "endpoint_diversity": endpoint_diversity,
            "blocked_ratio": blocked_ratio,
            "total_requests": len(recent_events)
        }
        
        self.redis.setex(cache_key, self.feature_cache_ttl, str(features))
        return features

    def _calculate_entropy(self, items: List[str]) -> float:
        if not items:
            return 0.0
        
        counts = {}
        for item in items:
            counts[item] = counts.get(item, 0) + 1
        
        total = len(items)
        entropy = 0.0
        
        for count in counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy

    def _default_features(self) -> Dict[str, float]:
        return {
            "endpoint_entropy": 0.0,
            "method_entropy": 0.0,
            "avg_interval": 0.0,
            "interval_std": 0.0,
            "request_rate": 0.0,
            "endpoint_diversity": 0.0,
            "blocked_ratio": 0.0,
            "total_requests": 0
        }

    def detect_anomaly(self, features: Dict[str, float]) -> Dict[str, any]:
        anomaly_score = 0.0
        anomalies = []
        
        if features["endpoint_entropy"] > self.entropy_threshold:
            anomaly_score += 0.2
            anomalies.append("high_endpoint_entropy")
        
        if features["request_rate"] > 10.0:
            anomaly_score += 0.3
            anomalies.append("high_request_rate")
        
        if features["interval_std"] < 0.5 and features["request_rate"] > 5.0:
            anomaly_score += 0.2
            anomalies.append("regular_timing_pattern")
        
        if features["endpoint_diversity"] > 0.8 and features["total_requests"] > 20:
            anomaly_score += 0.2
            anomalies.append("excessive_endpoint_diversity")
        
        if features["blocked_ratio"] > 0.5:
            anomaly_score += 0.1
            anomalies.append("high_block_ratio")
        
        is_anomalous = anomaly_score >= 0.5
        
        return {
            "is_anomalous": is_anomalous,
            "anomaly_score": min(anomaly_score, 1.0),
            "anomalies": anomalies,
            "features": features
        }

    def analyze_request(
        self,
        ip_address: str,
        current_request: Dict,
        db: Session
    ) -> Dict[str, any]:
        features = self.extract_features(ip_address, current_request, db)
        anomaly_result = self.detect_anomaly(features)
        
        return {
            **anomaly_result,
            "ml_confidence": anomaly_result["anomaly_score"]
        }

