import time
import psutil
from typing import Dict, Optional, Tuple
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.config import settings


class ConnectionStateProtection:
    def __init__(self):
        self.redis = get_redis()
        self.enabled = getattr(settings, 'connection_state_protection_enabled', True)
        self.max_half_open_connections = getattr(settings, 'max_half_open_connections', 1000)
        self.max_total_connections = getattr(settings, 'max_total_connections', 5000)
        self.connection_threshold_warning = getattr(settings, 'connection_threshold_warning', 0.7)
        self.connection_threshold_critical = getattr(settings, 'connection_threshold_critical', 0.9)
        self.monitoring_interval = 5
        self.last_check = 0
        self._cached_stats = None

    def get_connection_stats(self) -> Dict[str, int]:
        current_time = time.time()
        
        if self._cached_stats and (current_time - self.last_check) < self.monitoring_interval:
            return self._cached_stats
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            total_connections = len(connections)
            established = sum(1 for conn in connections if conn.status == 'ESTABLISHED')
            time_wait = sum(1 for conn in connections if conn.status == 'TIME_WAIT')
            close_wait = sum(1 for conn in connections if conn.status == 'CLOSE_WAIT')
            syn_sent = sum(1 for conn in connections if conn.status == 'SYN_SENT')
            syn_recv = sum(1 for conn in connections if conn.status == 'SYN_RECV')
            listen = sum(1 for conn in connections if conn.status == 'LISTEN')
            
            half_open = syn_sent + syn_recv
            
            stats = {
                "total": total_connections,
                "established": established,
                "time_wait": time_wait,
                "close_wait": close_wait,
                "half_open": half_open,
                "syn_sent": syn_sent,
                "syn_recv": syn_recv,
                "listen": listen
            }
            
            self._cached_stats = stats
            self.last_check = current_time
            
            return stats
            
        except Exception as e:
            logger.error("connection_stats_error", error=str(e))
            return {
                "total": 0,
                "established": 0,
                "time_wait": 0,
                "close_wait": 0,
                "half_open": 0,
                "syn_sent": 0,
                "syn_recv": 0,
                "listen": 0
            }

    def check_connection_state(self) -> Tuple[bool, str, Dict[str, int]]:
        if not self.enabled:
            return True, "disabled", {}
        
        stats = self.get_connection_stats()
        
        half_open = stats.get("half_open", 0)
        total = stats.get("total", 0)
        
        half_open_ratio = half_open / self.max_half_open_connections if self.max_half_open_connections > 0 else 0
        total_ratio = total / self.max_total_connections if self.max_total_connections > 0 else 0
        
        if half_open >= self.max_half_open_connections or total >= self.max_total_connections:
            logger.critical(
                "connection_state_exhaustion",
                half_open=half_open,
                total=total,
                max_half_open=self.max_half_open_connections,
                max_total=self.max_total_connections
            )
            return False, "exhausted", stats
        
        if half_open_ratio >= self.connection_threshold_critical or total_ratio >= self.connection_threshold_critical:
            logger.warning(
                "connection_state_critical",
                half_open=half_open,
                total=total,
                half_open_ratio=half_open_ratio,
                total_ratio=total_ratio
            )
            return False, "critical", stats
        
        if half_open_ratio >= self.connection_threshold_warning or total_ratio >= self.connection_threshold_warning:
            logger.warning(
                "connection_state_warning",
                half_open=half_open,
                total=total,
                half_open_ratio=half_open_ratio,
                total_ratio=total_ratio
            )
            return True, "warning", stats
        
        return True, "normal", stats

    def track_connection_attempt(self, ip_address: str) -> Tuple[bool, int]:
        if not self.enabled:
            return True, 0
        
        key = f"conn_attempts:{ip_address}"
        
        try:
            current_count = self.redis.get(key)
            if current_count is None:
                self.redis.setex(key, 60, 1)
                return True, 1
            
            count = int(current_count)
            max_attempts = 20
            
            if count >= max_attempts:
                logger.warning(
                    "connection_attempt_flood",
                    ip=ip_address,
                    count=count
                )
                return False, count
            
            self.redis.incr(key)
            return True, count + 1
            
        except Exception as e:
            logger.error("connection_tracking_error", error=str(e))
            return True, 0

    def should_accept_connection(self, ip_address: str) -> Tuple[bool, str]:
        if not self.enabled:
            return True, "disabled"
        
        allowed, reason, stats = self.check_connection_state()
        
        if not allowed:
            return False, reason
        
        conn_allowed, count = self.track_connection_attempt(ip_address)
        
        if not conn_allowed:
            return False, "too_many_attempts"
        
        return True, "allowed"

    def get_protection_status(self) -> Dict[str, any]:
        allowed, reason, stats = self.check_connection_state()
        
        return {
            "enabled": self.enabled,
            "allowed": allowed,
            "reason": reason,
            "stats": stats,
            "limits": {
                "max_half_open": self.max_half_open_connections,
                "max_total": self.max_total_connections,
                "threshold_warning": self.connection_threshold_warning,
                "threshold_critical": self.connection_threshold_critical
            },
            "utilization": {
                "half_open_ratio": stats.get("half_open", 0) / self.max_half_open_connections if self.max_half_open_connections > 0 else 0,
                "total_ratio": stats.get("total", 0) / self.max_total_connections if self.max_total_connections > 0 else 0
            }
        }

