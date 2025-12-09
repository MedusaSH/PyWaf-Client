import time
import statistics
from typing import Dict, Optional, List, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.models.security_event import SecurityEvent


class ConnectionMetricsAnalyzer:
    def __init__(self):
        self.redis = get_redis()
        from app.config import settings
        self.metrics_ttl = 3600
        self.window_minutes = getattr(settings, 'connection_metrics_window_minutes', 5)
        self.low_and_slow_threshold_bytes_per_sec = getattr(settings, 'low_and_slow_threshold_bytes_per_sec', 10.0)
        self.low_and_slow_min_duration_seconds = getattr(settings, 'low_and_slow_min_duration_seconds', 60)

    def track_request_metrics(
        self,
        ip_address: str,
        status_code: int,
        response_size_bytes: int,
        request_timestamp: Optional[float] = None
    ):
        if request_timestamp is None:
            request_timestamp = time.time()
        
        metrics_key = f"conn_metrics:{ip_address}"
        
        try:
            import json
            metrics_data = self.redis.get(metrics_key)
            
            if metrics_data:
                metrics = json.loads(metrics_data)
            else:
                metrics = {
                    "requests": [],
                    "errors": [],
                    "total_bytes": 0,
                    "first_request_time": request_timestamp,
                    "last_request_time": request_timestamp
                }
            
            metrics["requests"].append({
                "timestamp": request_timestamp,
                "status_code": status_code,
                "response_size": response_size_bytes
            })
            
            if status_code >= 400:
                metrics["errors"].append({
                    "timestamp": request_timestamp,
                    "status_code": status_code
                })
            
            metrics["total_bytes"] += response_size_bytes
            metrics["last_request_time"] = request_timestamp
            
            if not metrics.get("first_request_time"):
                metrics["first_request_time"] = request_timestamp
            
            self.redis.setex(metrics_key, self.metrics_ttl, json.dumps(metrics))
            
        except Exception as e:
            logger.error("track_request_metrics_error", error=str(e))

    def get_connection_metrics(
        self,
        ip_address: str,
        window_minutes: Optional[int] = None
    ) -> Dict[str, any]:
        if window_minutes is None:
            window_minutes = self.window_minutes
        
        metrics_key = f"conn_metrics:{ip_address}"
        
        try:
            import json
            metrics_data = self.redis.get(metrics_key)
            
            if not metrics_data:
                return {
                    "error_rate": 0.0,
                    "bytes_per_second": 0.0,
                    "avg_inter_request_delay": 0.0,
                    "inter_request_delay_variance": 0.0,
                    "is_low_and_slow": False,
                    "total_requests": 0,
                    "total_errors": 0,
                    "total_bytes": 0,
                    "connection_duration": 0.0
                }
            
            metrics = json.loads(metrics_data)
            cutoff_time = time.time() - (window_minutes * 60)
            
            recent_requests = [
                r for r in metrics.get("requests", [])
                if r["timestamp"] >= cutoff_time
            ]
            
            recent_errors = [
                e for e in metrics.get("errors", [])
                if e["timestamp"] >= cutoff_time
            ]
            
            if not recent_requests:
                return {
                    "error_rate": 0.0,
                    "bytes_per_second": 0.0,
                    "avg_inter_request_delay": 0.0,
                    "inter_request_delay_variance": 0.0,
                    "is_low_and_slow": False,
                    "total_requests": 0,
                    "total_errors": 0,
                    "total_bytes": 0,
                    "connection_duration": 0.0
                }
            
            total_requests = len(recent_requests)
            total_errors = len(recent_errors)
            error_rate = total_errors / total_requests if total_requests > 0 else 0.0
            
            total_bytes = sum(r["response_size"] for r in recent_requests)
            first_time = min(r["timestamp"] for r in recent_requests)
            last_time = max(r["timestamp"] for r in recent_requests)
            connection_duration = last_time - first_time if last_time > first_time else 0.0
            
            bytes_per_second = total_bytes / connection_duration if connection_duration > 0 else 0.0
            
            inter_request_delays = []
            sorted_requests = sorted(recent_requests, key=lambda x: x["timestamp"])
            for i in range(1, len(sorted_requests)):
                delay = sorted_requests[i]["timestamp"] - sorted_requests[i-1]["timestamp"]
                inter_request_delays.append(delay)
            
            avg_inter_request_delay = statistics.mean(inter_request_delays) if inter_request_delays else 0.0
            inter_request_delay_variance = statistics.variance(inter_request_delays) if len(inter_request_delays) > 1 else 0.0
            
            is_low_and_slow = (
                bytes_per_second < self.low_and_slow_threshold_bytes_per_sec and
                connection_duration > self.low_and_slow_min_duration_seconds and
                total_requests > 5
            )
            
            return {
                "error_rate": error_rate,
                "bytes_per_second": bytes_per_second,
                "avg_inter_request_delay": avg_inter_request_delay,
                "inter_request_delay_variance": inter_request_delay_variance,
                "is_low_and_slow": is_low_and_slow,
                "total_requests": total_requests,
                "total_errors": total_errors,
                "total_bytes": total_bytes,
                "connection_duration": connection_duration,
                "regular_timing_detected": inter_request_delay_variance < 0.1 and avg_inter_request_delay > 0
            }
            
        except Exception as e:
            logger.error("get_connection_metrics_error", error=str(e))
            return {
                "error_rate": 0.0,
                "bytes_per_second": 0.0,
                "avg_inter_request_delay": 0.0,
                "inter_request_delay_variance": 0.0,
                "is_low_and_slow": False,
                "total_requests": 0,
                "total_errors": 0,
                "total_bytes": 0,
                "connection_duration": 0.0
            }

    def analyze_http_error_patterns(
        self,
        ip_address: str,
        db: Session,
        window_minutes: Optional[int] = None
    ) -> Dict[str, any]:
        if window_minutes is None:
            window_minutes = self.window_minutes
        
        since = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        try:
            recent_events = db.query(SecurityEvent).filter(
                SecurityEvent.ip_address == ip_address,
                SecurityEvent.created_at >= since
            ).all()
            
            if not recent_events:
                return {
                    "error_rate": 0.0,
                    "error_patterns": {},
                    "suspicious_error_rate": False
                }
            
            total_requests = len(recent_events)
            error_4xx = sum(1 for e in recent_events if hasattr(e, 'status_code') and 400 <= getattr(e, 'status_code', 0) < 500)
            error_5xx = sum(1 for e in recent_events if hasattr(e, 'status_code') and 500 <= getattr(e, 'status_code', 0) < 600)
            total_errors = error_4xx + error_5xx
            
            error_rate = total_errors / total_requests if total_requests > 0 else 0.0
            
            suspicious_error_rate = error_rate > 0.3 and total_requests > 10
            
            error_patterns = {
                "4xx_errors": error_4xx,
                "5xx_errors": error_5xx,
                "total_errors": total_errors,
                "error_rate": error_rate
            }
            
            return {
                "error_rate": error_rate,
                "error_patterns": error_patterns,
                "suspicious_error_rate": suspicious_error_rate,
                "total_requests": total_requests
            }
            
        except Exception as e:
            logger.error("analyze_http_error_patterns_error", error=str(e))
            return {
                "error_rate": 0.0,
                "error_patterns": {},
                "suspicious_error_rate": False
            }

    def get_comprehensive_metrics(
        self,
        ip_address: str,
        db: Session,
        window_minutes: Optional[int] = None
    ) -> Dict[str, any]:
        connection_metrics = self.get_connection_metrics(ip_address, window_minutes)
        error_patterns = self.analyze_http_error_patterns(ip_address, db, window_minutes)
        
        return {
            **connection_metrics,
            **error_patterns,
            "metrics_quality": "high" if connection_metrics["total_requests"] > 5 else "low"
        }

