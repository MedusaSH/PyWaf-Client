import time
from typing import Optional
from fastapi import Request, Response, status
from sqlalchemy.orm import Session
from app.models.security_event import ThreatLevel
from app.security.request_analyzer import RequestAnalyzer
from app.security.threat_detector import ThreatDetector
from app.security.rate_limiter import RateLimiter
from app.security.ip_manager import IPManager
from app.security.ip_reputation import IPReputationEngine
from app.security.behavioral_analyzer import BehavioralAnalyzer
from app.security.adaptive_rate_limiter import AdaptiveRateLimiter
from app.security.challenge_system import ChallengeSystem
from app.security.ml_anomaly_detector import MLAnomalyDetector
from app.security.tls_fingerprinting import TLSFingerprinter
from app.core.logger import logger
from app.core.database import get_db
from app.config import settings


class WAFEngine:
    def __init__(self):
        self.request_analyzer = RequestAnalyzer()
        self.threat_detector = ThreatDetector()
        self.rate_limiter = RateLimiter()
        self.ip_manager = IPManager()
        self.reputation_engine = IPReputationEngine() if settings.ip_reputation_enabled else None
        self.behavioral_analyzer = BehavioralAnalyzer() if settings.behavioral_analysis_enabled else None
        self.adaptive_rate_limiter = AdaptiveRateLimiter() if settings.adaptive_rate_limiting_enabled else None
        self.challenge_system = ChallengeSystem() if settings.challenge_system_enabled else None
        self.ml_detector = MLAnomalyDetector() if settings.behavioral_analysis_enabled else None
        self.tls_fingerprinter = TLSFingerprinter() if getattr(settings, 'tls_fingerprinting_enabled', True) else None

    async def process_request(
        self,
        request: Request,
        db: Session
    ) -> tuple[bool, Optional[Response], Optional[dict]]:
        start_time = time.time()
        
        try:
            analysis_result = await self.request_analyzer.analyze(request)
            ip_address = analysis_result["ip_address"]
            endpoint = analysis_result["endpoint"]
            
            tls_fingerprint_hash = None
            if self.tls_fingerprinter:
                tls_fingerprint_hash = self.tls_fingerprinter.extract_tls_fingerprint(request)
            
            if self.ip_manager.is_whitelisted(ip_address, db):
                return True, None, analysis_result
            
            if self.ip_manager.is_blacklisted(ip_address, db):
                logger.warning("request_blocked_blacklist", ip=ip_address, endpoint=endpoint)
                return False, self._create_blocked_response("IP blacklisted"), analysis_result
            
            reputation = None
            behavioral_data = None
            ml_analysis = None
            
            if self.reputation_engine:
                reputation = self.reputation_engine.calculate_reputation_score(ip_address, db, analysis_result)
                
                if reputation["status"] == "malicious":
                    logger.warning(
                        "request_blocked_malicious_reputation",
                        ip=ip_address,
                        score=reputation["total_score"]
                    )
                    return False, self._create_blocked_response("Malicious IP reputation"), analysis_result
            
            if self.behavioral_analyzer:
                behavioral_data = self.behavioral_analyzer.detect_anomalous_behavior(
                    ip_address,
                    analysis_result,
                    db
                )
            
            if self.ml_detector:
                ml_analysis = self.ml_detector.analyze_request(ip_address, analysis_result, db)
                
                if ml_analysis.get("is_anomalous", False) and ml_analysis.get("anomaly_score", 0) > 0.8:
                    logger.warning(
                        "request_blocked_ml_anomaly",
                        ip=ip_address,
                        score=ml_analysis["anomaly_score"]
                    )
                    return False, self._create_blocked_response("Anomalous behavior detected"), analysis_result
            
            if self.adaptive_rate_limiter and reputation and behavioral_data:
                allowed, ttl, limits = self.adaptive_rate_limiter.check_adaptive_limit(
                    ip_address,
                    endpoint,
                    reputation,
                    behavioral_data,
                    db
                )
                if not allowed:
                    logger.warning(
                        "request_blocked_adaptive_rate_limit",
                        ip=ip_address,
                        endpoint=endpoint,
                        reason=limits.get("reason", "unknown")
                    )
                    
                    if self.challenge_system:
                        should_challenge, challenge_level, challenge_reason = self.challenge_system.should_apply_challenge(
                            reputation.get("total_score", 0),
                            behavioral_data.get("anomaly_score", 0) if behavioral_data else 0,
                            behavioral_data.get("session_stats", {}).get("request_count", 0) if behavioral_data else 0,
                            ip_address,
                            tls_fingerprint_hash
                        )
                        if should_challenge:
                            difficulty = 3
                            if challenge_level == 4:
                                cookie_bypasses = self.challenge_system.get_challenge_bypass_count(ip_address, "cookie")
                                if cookie_bypasses > 0:
                                    difficulty = min(4 + cookie_bypasses, 5)
                            
                            challenge_response = self.challenge_system.create_challenge_response(
                                challenge_level,
                                ip_address,
                                challenge_reason,
                                difficulty
                            )
                            if challenge_response:
                                return False, challenge_response, analysis_result
                    
                    return False, self._create_blocked_response("Rate limit exceeded"), analysis_result
            else:
                if not self.rate_limiter.check_burst(ip_address, endpoint):
                    logger.warning("request_blocked_burst", ip=ip_address, endpoint=endpoint)
                    return False, self._create_blocked_response("Rate limit exceeded"), analysis_result
                
                allowed, ttl = self.rate_limiter.check_limit(ip_address, endpoint)
                if not allowed:
                    logger.warning("request_blocked_rate_limit", ip=ip_address, endpoint=endpoint)
                    return False, self._create_blocked_response("Rate limit exceeded"), analysis_result
            
            if self.challenge_system and reputation and behavioral_data:
                should_challenge, challenge_level, challenge_reason = self.challenge_system.should_apply_challenge(
                    reputation.get("total_score", 0),
                    behavioral_data.get("anomaly_score", 0) if behavioral_data else 0,
                    behavioral_data.get("session_stats", {}).get("request_count", 0) if behavioral_data else 0,
                    ip_address,
                    tls_fingerprint_hash
                )
                
                if should_challenge:
                    difficulty = 3
                    if challenge_level == 4:
                        cookie_bypasses = self.challenge_system.get_challenge_bypass_count(ip_address, "cookie")
                        if cookie_bypasses > 0:
                            difficulty = min(4 + cookie_bypasses, 5)
                    
                    challenge_response = self.challenge_system.create_challenge_response(
                        challenge_level,
                        ip_address,
                        challenge_reason,
                        difficulty
                    )
                    if challenge_response:
                        return False, challenge_response, analysis_result
            
            payload = analysis_result["payload_string"]
            is_threat, threat_type, threat_level = await self.threat_detector.evaluate(
                payload,
                endpoint,
                analysis_result["method"]
            )
            
            if is_threat and threat_type:
                logger.warning(
                    "threat_blocked",
                    threat_type=threat_type,
                    level=threat_level.value,
                    ip=ip_address,
                    endpoint=endpoint
                )
                
                if self.reputation_engine:
                    self.reputation_engine.update_reputation(ip_address, db, analysis_result)
                
                if self.tls_fingerprinter and tls_fingerprint_hash:
                    self.tls_fingerprinter.record_fingerprint(
                        tls_fingerprint_hash,
                        analysis_result,
                        db,
                        blocked=True
                    )
                
                return False, self._create_blocked_response(f"Threat detected: {threat_type}"), analysis_result
            
            if self.tls_fingerprinter and tls_fingerprint_hash:
                self.tls_fingerprinter.record_fingerprint(
                    tls_fingerprint_hash,
                    analysis_result,
                    db,
                    blocked=False
                )
            
            if self.reputation_engine and reputation:
                analysis_result["reputation"] = reputation
            
            if behavioral_data:
                analysis_result["behavioral"] = behavioral_data
            
            if ml_analysis:
                analysis_result["ml_analysis"] = ml_analysis
            
            elapsed_ms = (time.time() - start_time) * 1000
            if elapsed_ms > settings.max_latency_ms:
                logger.warning("request_slow", endpoint=endpoint, elapsed_ms=elapsed_ms)
            
            return True, None, analysis_result
            
        except Exception as e:
            logger.error("waf_engine_error", error=str(e))
            return True, None, None

    def _create_blocked_response(self, reason: str) -> Response:
        return Response(
            content=f'{{"error": "Request blocked", "reason": "{reason}"}}',
            status_code=status.HTTP_403_FORBIDDEN,
            media_type="application/json"
        )

