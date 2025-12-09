import ipaddress
import time
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.config import settings
from app.models.security_event import SecurityEvent


class GeoFiltering:
    def __init__(self):
        self.redis = get_redis()
        self.enabled = getattr(settings, 'geo_filtering_enabled', False)
        self.blocked_regions_ttl = 3600
        self.attack_threshold = getattr(settings, 'geo_attack_threshold', 100)
        self.analysis_window_minutes = getattr(settings, 'geo_analysis_window_minutes', 5)
        
        self.country_ranges = self._load_country_ranges()

    def _load_country_ranges(self) -> Dict[str, List[str]]:
        return {
            "US": ["1.0.0.0/8", "2.0.0.0/8", "3.0.0.0/8"],
            "CN": ["1.12.0.0/14", "1.24.0.0/13"],
            "RU": ["5.8.0.0/13", "5.101.0.0/16"],
        }

    def get_country_from_ip(self, ip_address: str) -> Optional[str]:
        try:
            ip = ipaddress.ip_address(ip_address)
            
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return "LOCAL"
            
            for country, ranges in self.country_ranges.items():
                for range_str in ranges:
                    if ip in ipaddress.ip_network(range_str, strict=False):
                        return country
            
            return "UNKNOWN"
        except Exception:
            return "UNKNOWN"

    def analyze_attack_by_region(
        self,
        db: Session,
        time_window_minutes: Optional[int] = None
    ) -> Dict[str, Dict[str, any]]:
        if not time_window_minutes:
            time_window_minutes = self.analysis_window_minutes
        
        since = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        try:
            recent_events = db.query(SecurityEvent).filter(
                SecurityEvent.created_at >= since,
                SecurityEvent.threat_level.in_(["HIGH", "CRITICAL"])
            ).all()
            
            region_stats = {}
            
            for event in recent_events:
                country = self.get_country_from_ip(event.ip_address)
                
                if country not in region_stats:
                    region_stats[country] = {
                        "count": 0,
                        "ips": set(),
                        "threat_types": {}
                    }
                
                region_stats[country]["count"] += 1
                region_stats[country]["ips"].add(event.ip_address)
                
                threat_type = event.threat_type or "unknown"
                if threat_type not in region_stats[country]["threat_types"]:
                    region_stats[country]["threat_types"][threat_type] = 0
                region_stats[country]["threat_types"][threat_type] += 1
            
            for country in region_stats:
                region_stats[country]["ips"] = list(region_stats[country]["ips"])
                region_stats[country]["unique_ips"] = len(region_stats[country]["ips"])
                region_stats[country]["is_attack"] = region_stats[country]["count"] >= self.attack_threshold
            
            return region_stats
            
        except Exception as e:
            logger.error("geo_analysis_error", error=str(e))
            return {}

    def block_region(
        self,
        country_code: str,
        duration_seconds: int = 3600,
        reason: str = "DDoS attack detected"
    ) -> bool:
        if not self.enabled:
            return False
        
        key = f"geo_blocked:{country_code}"
        
        try:
            block_data = {
                "country": country_code,
                "blocked_at": time.time(),
                "expires_at": time.time() + duration_seconds,
                "reason": reason
            }
            
            import json
            self.redis.setex(key, duration_seconds, json.dumps(block_data))
            
            logger.warning(
                "region_blocked",
                country=country_code,
                duration=duration_seconds,
                reason=reason
            )
            
            return True
            
        except Exception as e:
            logger.error("geo_block_error", error=str(e))
            return False

    def unblock_region(self, country_code: str) -> bool:
        key = f"geo_blocked:{country_code}"
        
        try:
            self.redis.delete(key)
            logger.info("region_unblocked", country=country_code)
            return True
        except Exception as e:
            logger.error("geo_unblock_error", error=str(e))
            return False

    def is_region_blocked(self, country_code: str) -> Tuple[bool, Optional[Dict]]:
        if not self.enabled:
            return False, None
        
        key = f"geo_blocked:{country_code}"
        
        try:
            block_data = self.redis.get(key)
            if block_data:
                import json
                return True, json.loads(block_data)
            return False, None
        except Exception as e:
            logger.error("geo_check_error", error=str(e))
            return False, None

    def is_ip_blocked_by_geo(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        if not self.enabled:
            return False, None
        
        country = self.get_country_from_ip(ip_address)
        
        if country == "LOCAL":
            return False, None
        
        blocked, block_info = self.is_region_blocked(country)
        
        if blocked:
            return True, country
        
        return False, None

    def get_blocked_regions(self) -> List[Dict[str, any]]:
        if not self.enabled:
            return []
        
        blocked = []
        
        try:
            keys = self.redis.keys("geo_blocked:*")
            
            for key in keys:
                country_code = key.decode().replace("geo_blocked:", "")
                blocked_info, block_data = self.is_region_blocked(country_code)
                
                if blocked_info and block_data:
                    blocked.append({
                        "country": country_code,
                        "blocked_at": block_data.get("blocked_at"),
                        "expires_at": block_data.get("expires_at"),
                        "reason": block_data.get("reason", "Unknown")
                    })
            
            return blocked
            
        except Exception as e:
            logger.error("get_blocked_regions_error", error=str(e))
            return []

    def auto_block_attack_regions(
        self,
        db: Session,
        duration_seconds: int = 3600
    ) -> List[str]:
        if not self.enabled:
            return []
        
        region_stats = self.analyze_attack_by_region(db)
        blocked_regions = []
        
        for country, stats in region_stats.items():
            if stats.get("is_attack", False) and country != "LOCAL":
                if self.block_region(
                    country,
                    duration_seconds,
                    f"Auto-blocked: {stats['count']} attacks detected"
                ):
                    blocked_regions.append(country)
        
        return blocked_regions

