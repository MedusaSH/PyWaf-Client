from typing import Optional
from app.models.security_event import ThreatLevel
from app.security.detectors.sql_injection import SQLInjectionDetector
from app.security.detectors.xss import XSSDetector
from app.security.detectors.path_traversal import PathTraversalDetector
from app.security.detectors.command_injection import CommandInjectionDetector
from app.config import settings
from app.core.logger import logger


class ThreatDetector:
    def __init__(self):
        self.sql_detector = SQLInjectionDetector()
        self.xss_detector = XSSDetector()
        self.path_traversal_detector = PathTraversalDetector()
        self.command_injection_detector = CommandInjectionDetector()

    async def evaluate(
        self,
        payload: str,
        endpoint: str,
        method: str
    ) -> tuple[bool, Optional[str], ThreatLevel]:
        if not payload:
            return False, None, ThreatLevel.LOW
        
        threats = []
        
        if settings.sql_injection_enabled:
            detected, reason = self.sql_detector.detect(payload)
            if detected:
                threats.append(("sql_injection", reason, ThreatLevel.CRITICAL))
        
        if settings.xss_protection_enabled:
            detected, reason = self.xss_detector.detect(payload)
            if detected:
                threats.append(("xss", reason, ThreatLevel.HIGH))
        
        detected, reason = self.path_traversal_detector.detect(payload)
        if detected:
            threats.append(("path_traversal", reason, ThreatLevel.HIGH))
        
        detected, reason = self.command_injection_detector.detect(payload)
        if detected:
            threats.append(("command_injection", reason, ThreatLevel.CRITICAL))
        
        if not threats:
            return False, None, ThreatLevel.LOW
        
        highest_threat = max(threats, key=lambda x: self._threat_level_value(x[2]))
        threat_type, reason, level = highest_threat
        
        logger.warning(
            "threat_detected",
            threat_type=threat_type,
            level=level.value,
            endpoint=endpoint,
            method=method
        )
        
        return True, threat_type, level

    def _threat_level_value(self, level: ThreatLevel) -> int:
        mapping = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
        }
        return mapping.get(level, 0)

