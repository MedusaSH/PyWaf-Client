from typing import Dict, Optional, Tuple
from sqlalchemy.orm import Session
from app.security.connection_metrics_analyzer import ConnectionMetricsAnalyzer
from app.security.ip_reputation import IPReputationEngine
from app.security.tls_fingerprinting import TLSFingerprinter
from app.core.logger import logger


class BehavioralMaliceScorer:
    def __init__(self):
        self.metrics_analyzer = ConnectionMetricsAnalyzer()
        self.reputation_engine = IPReputationEngine()
        self.tls_fingerprinter = TLSFingerprinter()
        
        from app.config import settings
        self.error_rate_weight = getattr(settings, 'malice_score_error_rate_weight', 0.25)
        self.low_and_slow_weight = getattr(settings, 'malice_score_low_and_slow_weight', 0.20)
        self.regular_timing_weight = getattr(settings, 'malice_score_regular_timing_weight', 0.20)
        self.reputation_weight = getattr(settings, 'malice_score_reputation_weight', 0.20)
        self.tls_fingerprint_weight = getattr(settings, 'malice_score_tls_weight', 0.15)

    def calculate_malice_score(
        self,
        ip_address: str,
        request_data: Dict,
        db: Session,
        tls_fingerprint_hash: Optional[str] = None,
        window_minutes: int = 5
    ) -> Dict[str, any]:
        metrics = self.metrics_analyzer.get_comprehensive_metrics(ip_address, db, window_minutes)
        
        reputation = None
        if self.reputation_engine:
            reputation = self.reputation_engine.calculate_reputation_score(ip_address, db, request_data)
        
        tls_score = 0.0
        tls_details = {}
        if tls_fingerprint_hash and self.tls_fingerprinter:
            tls_analysis = self.tls_fingerprinter.analyze_fingerprint(tls_fingerprint_hash, db)
            if tls_analysis:
                if tls_analysis.get("is_suspicious", False):
                    tls_score = 0.7
                elif tls_analysis.get("is_malicious", False):
                    tls_score = 1.0
                tls_details = tls_analysis
        
        error_rate_score = min(metrics.get("error_rate", 0.0) * 2.0, 1.0)
        
        low_and_slow_score = 1.0 if metrics.get("is_low_and_slow", False) else 0.0
        
        regular_timing_score = 0.0
        if metrics.get("regular_timing_detected", False):
            variance = metrics.get("inter_request_delay_variance", 1.0)
            if variance < 0.01:
                regular_timing_score = 1.0
            elif variance < 0.1:
                regular_timing_score = 0.7
            elif variance < 0.5:
                regular_timing_score = 0.4
        
        reputation_score = 0.0
        if reputation:
            total_score = reputation.get("total_score", 0.0)
            if total_score >= 70.0:
                reputation_score = 1.0
            elif total_score >= 40.0:
                reputation_score = 0.6
            elif total_score >= 20.0:
                reputation_score = 0.3
        
        weighted_score = (
            error_rate_score * self.error_rate_weight +
            low_and_slow_score * self.low_and_slow_weight +
            regular_timing_score * self.regular_timing_weight +
            reputation_score * self.reputation_weight +
            tls_score * self.tls_fingerprint_weight
        )
        
        malice_level = self._determine_malice_level(weighted_score)
        
        return {
            "malice_score": weighted_score,
            "malice_level": malice_level,
            "components": {
                "error_rate_score": error_rate_score,
                "low_and_slow_score": low_and_slow_score,
                "regular_timing_score": regular_timing_score,
                "reputation_score": reputation_score,
                "tls_score": tls_score
            },
            "metrics": metrics,
            "reputation": reputation,
            "tls_details": tls_details,
            "recommended_action": self._get_recommended_action(malice_level, weighted_score)
        }

    def _determine_malice_level(self, score: float) -> str:
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        else:
            return "clean"

    def _get_recommended_action(
        self,
        malice_level: str,
        score: float
    ) -> Dict[str, any]:
        if malice_level == "critical":
            return {
                "action": "block",
                "challenge_type": None,
                "tarpit": False,
                "reason": "Critical malice score detected"
            }
        elif malice_level == "high":
            return {
                "action": "challenge",
                "challenge_type": "javascript_tarpit",
                "challenge_difficulty": 7,
                "tarpit": True,
                "reason": "High malice score - aggressive challenge required"
            }
        elif malice_level == "medium":
            return {
                "action": "challenge",
                "challenge_type": "proof_of_work",
                "challenge_difficulty": 5,
                "tarpit": True,
                "reason": "Medium malice score - challenge with tarpitting"
            }
        elif malice_level == "low":
            return {
                "action": "challenge",
                "challenge_type": "encrypted_cookie",
                "challenge_difficulty": 3,
                "tarpit": False,
                "reason": "Low malice score - light challenge"
            }
        else:
            return {
                "action": "allow",
                "challenge_type": None,
                "tarpit": False,
                "reason": "Clean behavior"
            }

    def should_apply_mitigation(
        self,
        malice_score_result: Dict[str, any]
    ) -> Tuple[bool, Dict[str, any]]:
        malice_level = malice_score_result.get("malice_level", "clean")
        recommended_action = malice_score_result.get("recommended_action", {})
        
        if recommended_action.get("action") == "block":
            return True, {
                "type": "block",
                "reason": recommended_action.get("reason", "High malice score")
            }
        elif recommended_action.get("action") == "challenge":
            return True, {
                "type": "challenge",
                "challenge_type": recommended_action.get("challenge_type"),
                "challenge_difficulty": recommended_action.get("challenge_difficulty", 3),
                "tarpit": recommended_action.get("tarpit", False),
                "reason": recommended_action.get("reason", "Malice score requires challenge")
            }
        
        return False, {}

