import hashlib
import json
from typing import Optional, Dict, List
from fastapi import Request
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.models.tls_fingerprint import TLSFingerprint


class TLSFingerprinter:
    def __init__(self):
        self.redis = get_redis()
        self.cache_ttl = 3600

    def extract_tls_fingerprint(self, request: Request) -> Optional[str]:
        try:
            tls_info = {}
            
            cipher_suites = request.headers.get("x-tls-cipher-suites", "")
            tls_version = request.headers.get("x-tls-version", "")
            tls_extensions = request.headers.get("x-tls-extensions", "")
            tls_curves = request.headers.get("x-tls-curves", "")
            tls_point_formats = request.headers.get("x-tls-point-formats", "")
            
            if not any([cipher_suites, tls_version, tls_extensions]):
                return None
            
            tls_info = {
                "version": tls_version,
                "cipher_suites": cipher_suites,
                "extensions": tls_extensions,
                "curves": tls_curves,
                "point_formats": tls_point_formats
            }
            
            fingerprint_string = json.dumps(tls_info, sort_keys=True)
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:32]
            
            return fingerprint_hash
            
        except Exception as e:
            logger.error("tls_fingerprint_extraction_error", error=str(e))
            return None

    def extract_tls_fingerprint_from_headers(self, headers: Dict) -> Optional[str]:
        try:
            tls_info = {}
            
            cipher_suites = headers.get("x-tls-cipher-suites", "")
            tls_version = headers.get("x-tls-version", "")
            tls_extensions = headers.get("x-tls-extensions", "")
            tls_curves = headers.get("x-tls-curves", "")
            tls_point_formats = headers.get("x-tls-point-formats", "")
            
            if not any([cipher_suites, tls_version, tls_extensions]):
                return None
            
            tls_info = {
                "version": tls_version,
                "cipher_suites": cipher_suites,
                "extensions": tls_extensions,
                "curves": tls_curves,
                "point_formats": tls_point_formats
            }
            
            fingerprint_string = json.dumps(tls_info, sort_keys=True)
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:32]
            
            return fingerprint_hash
            
        except Exception as e:
            logger.error("tls_fingerprint_extraction_error", error=str(e))
            return None

    def get_fingerprint_info(
        self,
        fingerprint_hash: str,
        db: Session
    ) -> Optional[Dict]:
        cache_key = f"tls_fp:{fingerprint_hash}"
        
        cached = self.redis.get(cache_key)
        if cached:
            try:
                return eval(cached)
            except:
                pass
        
        fp_record = db.query(TLSFingerprint).filter(
            TLSFingerprint.fingerprint_hash == fingerprint_hash
        ).first()
        
        if not fp_record:
            return None
        
        info = {
            "fingerprint": fp_record.fingerprint,
            "fingerprint_hash": fp_record.fingerprint_hash,
            "is_whitelisted": fp_record.is_whitelisted,
            "is_blacklisted": fp_record.is_blacklisted,
            "threat_level": fp_record.threat_level,
            "request_count": fp_record.request_count,
            "blocked_count": fp_record.blocked_count,
            "block_ratio": fp_record.blocked_count / fp_record.request_count if fp_record.request_count > 0 else 0.0
        }
        
        self.redis.setex(cache_key, self.cache_ttl, str(info))
        return info

    def is_whitelisted(self, fingerprint_hash: str, db: Session) -> bool:
        info = self.get_fingerprint_info(fingerprint_hash, db)
        return info["is_whitelisted"] if info else False

    def is_blacklisted(self, fingerprint_hash: str, db: Session) -> bool:
        info = self.get_fingerprint_info(fingerprint_hash, db)
        return info["is_blacklisted"] if info else False

    def record_fingerprint(
        self,
        fingerprint_hash: str,
        request_data: Dict,
        db: Session,
        blocked: bool = False
    ):
        try:
            fp_record = db.query(TLSFingerprint).filter(
                TLSFingerprint.fingerprint_hash == fingerprint_hash
            ).first()
            
            if not fp_record:
                fingerprint_string = json.dumps(request_data.get("tls_info", {}), sort_keys=True)
                fp_record = TLSFingerprint(
                    fingerprint=fingerprint_string[:500],
                    fingerprint_hash=fingerprint_hash,
                    request_count=1,
                    blocked_count=1 if blocked else 0,
                    fingerprint_metadata=json.dumps({
                        "user_agent": request_data.get("user_agent", ""),
                        "first_ip": request_data.get("ip_address", "")
                    })
                )
                db.add(fp_record)
            else:
                fp_record.request_count += 1
                if blocked:
                    fp_record.blocked_count += 1
                fp_record.last_seen = datetime.utcnow()
            
            db.commit()
            
            cache_key = f"tls_fp:{fingerprint_hash}"
            self.redis.delete(cache_key)
            
        except Exception as e:
            logger.error("tls_fingerprint_record_error", error=str(e))
            db.rollback()

    def get_fingerprint_stats(
        self,
        fingerprint_hash: str,
        db: Session,
        hours: int = 24
    ) -> Dict:
        since = datetime.utcnow() - timedelta(hours=hours)
        
        from app.models.security_event import SecurityEvent
        
        events = db.query(SecurityEvent).filter(
            SecurityEvent.created_at >= since
        ).all()
        
        matching_events = []
        for event in events:
            if event.payload and isinstance(event.payload, dict):
                event_fp = event.payload.get("tls_fingerprint")
                if event_fp == fingerprint_hash:
                    matching_events.append(event)
        
        return {
            "total_requests": len(matching_events),
            "blocked_requests": sum(1 for e in matching_events if e.blocked == 1),
            "unique_ips": len(set(e.ip_address for e in matching_events)),
            "threat_types": {}
        }

