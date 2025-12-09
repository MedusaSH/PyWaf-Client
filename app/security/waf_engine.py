import time
import json
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
from app.security.syn_cookie_protection import SYNCookieProtection
from app.security.connection_state_protection import ConnectionStateProtection
from app.security.geo_filtering import GeoFiltering
from app.security.connection_metrics_analyzer import ConnectionMetricsAnalyzer
from app.security.behavioral_malice_scorer import BehavioralMaliceScorer
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
        self.syn_cookie_protection = SYNCookieProtection() if getattr(settings, 'syn_cookie_enabled', True) else None
        self.connection_state_protection = ConnectionStateProtection() if getattr(settings, 'connection_state_protection_enabled', True) else None
        self.geo_filtering = GeoFiltering() if getattr(settings, 'geo_filtering_enabled', False) else None
        self.metrics_analyzer = ConnectionMetricsAnalyzer() if getattr(settings, 'connection_metrics_enabled', True) else None
        self.malice_scorer = BehavioralMaliceScorer() if getattr(settings, 'behavioral_malice_scoring_enabled', True) else None

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
            
            if self.geo_filtering:
                geo_blocked, blocked_country = self.geo_filtering.is_ip_blocked_by_geo(ip_address)
                if geo_blocked:
                    logger.warning("request_blocked_geo", ip=ip_address, country=blocked_country, endpoint=endpoint)
                    return False, self._create_blocked_response(f"Region blocked: {blocked_country}"), analysis_result
            
            if self.connection_state_protection:
                conn_allowed, conn_reason = self.connection_state_protection.should_accept_connection(ip_address)
                if not conn_allowed:
                    logger.warning("request_blocked_connection_state", ip=ip_address, reason=conn_reason, endpoint=endpoint)
                    return False, self._create_blocked_response(f"Connection state protection: {conn_reason}"), analysis_result
            
            if self.ip_manager.is_blacklisted(ip_address, db):
                logger.warning("request_blocked_blacklist", ip=ip_address, endpoint=endpoint)
                return False, self._create_blocked_response("IP blacklisted"), analysis_result
            
            if self.syn_cookie_protection:
                if not self.syn_cookie_protection.verify_request_syn_cookie(request):
                    logger.warning("request_blocked_invalid_syn_cookie", ip=ip_address, endpoint=endpoint)
                    return False, self._create_blocked_response("Invalid SYN cookie"), analysis_result
            
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
            
            malice_score_result = None
            if self.malice_scorer:
                malice_score_result = self.malice_scorer.calculate_malice_score(
                    ip_address,
                    analysis_result,
                    db,
                    tls_fingerprint_hash
                )
                
                should_mitigate, mitigation_action = self.malice_scorer.should_apply_mitigation(malice_score_result)
                
                if should_mitigate:
                    if mitigation_action.get("type") == "block":
                        logger.warning(
                            "request_blocked_malice_score",
                            ip=ip_address,
                            score=malice_score_result.get("malice_score", 0),
                            level=malice_score_result.get("malice_level", "unknown")
                        )
                        return False, self._create_blocked_response(mitigation_action.get("reason", "High malice score")), analysis_result
                    
                    elif mitigation_action.get("type") == "challenge" and self.challenge_system:
                        challenge_type = mitigation_action.get("challenge_type")
                        challenge_difficulty = mitigation_action.get("challenge_difficulty", 3)
                        use_tarpit = mitigation_action.get("tarpit", False)
                        
                        if challenge_type == "javascript_tarpit":
                            challenge = self.challenge_system.create_javascript_tarpit_challenge(
                                ip_address,
                                complexity=challenge_difficulty
                            )
                            return False, Response(
                                content=challenge["html_page"],
                                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                media_type="text/html"
                            ), analysis_result
                        elif challenge_type == "proof_of_work":
                            challenge = self.challenge_system.create_proof_of_work_challenge(
                                ip_address,
                                difficulty=challenge_difficulty
                            )
                            return False, Response(
                                content=f'{{"error": "Challenge required", "type": "proof_of_work", "token": "{challenge["token"]}", "difficulty": {challenge["difficulty"]}, "js_code": {json.dumps(challenge["js_code"])}}}',
                                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                media_type="application/json"
                            ), analysis_result
                        elif challenge_type == "encrypted_cookie":
                            challenge = self.challenge_system.create_encrypted_cookie_challenge(ip_address)
                            html_page = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vérification en cours...</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .container {{
            text-align: center;
            padding: 2rem;
        }}
        .spinner {{
            border: 4px solid rgba(255, 255, 255, 0.3);
            border-top: 4px solid white;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        h1 {{
            margin: 0 0 0.5rem 0;
            font-size: 1.5rem;
        }}
        p {{
            margin: 0;
            opacity: 0.9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h1>Vérification en cours...</h1>
        <p>Veuillez patienter pendant que nous vérifions votre navigateur.</p>
    </div>
    <script>{challenge["js_code"]}</script>
</body>
</html>"""
                            return False, Response(
                                content=html_page,
                                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                media_type="text/html"
                            ), analysis_result
            
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
                        headless_detected = analysis_result.get("headless_detected", False)
                        headless_confidence = analysis_result.get("headless_confidence", 0.0)
                        
                        encrypted_cookie = request.cookies.get(self.challenge_system.encrypted_cookie_name)
                        encrypted_cookie_valid = False
                        if encrypted_cookie:
                            encrypted_cookie_valid = self.challenge_system.verify_encrypted_cookie_from_request(
                                ip_address,
                                encrypted_cookie
                            )
                        
                        if not encrypted_cookie_valid:
                            should_challenge, challenge_level, challenge_reason = self.challenge_system.should_apply_challenge(
                                reputation.get("total_score", 0),
                                behavioral_data.get("anomaly_score", 0) if behavioral_data else 0,
                                behavioral_data.get("session_stats", {}).get("request_count", 0) if behavioral_data else 0,
                                ip_address,
                                tls_fingerprint_hash,
                                headless_detected,
                                headless_confidence
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
                                    difficulty,
                                    headless_detected,
                                    headless_confidence
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
            
            encrypted_cookie_valid = False
            if self.challenge_system:
                encrypted_cookie = request.cookies.get(self.challenge_system.encrypted_cookie_name)
                if encrypted_cookie:
                    encrypted_cookie_valid = self.challenge_system.verify_encrypted_cookie_from_request(
                        ip_address,
                        encrypted_cookie
                    )
            
            if self.challenge_system and reputation and behavioral_data and not malice_score_result:
                headless_detected = analysis_result.get("headless_detected", False)
                headless_confidence = analysis_result.get("headless_confidence", 0.0)
                
                if not encrypted_cookie_valid:
                    should_challenge, challenge_level, challenge_reason = self.challenge_system.should_apply_challenge(
                        reputation.get("total_score", 0),
                        behavioral_data.get("anomaly_score", 0) if behavioral_data else 0,
                        behavioral_data.get("session_stats", {}).get("request_count", 0) if behavioral_data else 0,
                        ip_address,
                        tls_fingerprint_hash,
                        headless_detected,
                        headless_confidence
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
                            difficulty,
                            headless_detected,
                            headless_confidence
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
            
            if malice_score_result:
                analysis_result["malice_score"] = malice_score_result
            
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

