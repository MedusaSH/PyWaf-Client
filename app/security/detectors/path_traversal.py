import re
from app.security.detectors.base import BaseDetector
from typing import Optional


class PathTraversalDetector(BaseDetector):
    def __init__(self):
        self.patterns = [
            r"\.\./",
            r"\.\.\\",
            r"\.\.%2f",
            r"\.\.%5c",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%252f",
            r"\.\.%255c",
            r"\.\.%c0%af",
            r"\.\.%c1%9c",
            r"/etc/passwd",
            r"/etc/shadow",
            r"/proc/self/environ",
            r"\.\./\.\./\.\./",
            r"\.\.\\\.\.\\\.\.\\",
            r"\.\.%2f\.\.%2f",
            r"\.\.%5c\.\.%5c",
        ]

    def detect(self, payload: str) -> tuple[bool, Optional[str]]:
        normalized = payload
        
        for pattern in self.patterns:
            if re.search(pattern, normalized, re.IGNORECASE):
                return True, f"Path traversal pattern detected: {pattern}"
        
        if self._detect_absolute_path(normalized):
            return True, "Absolute path traversal detected"
        
        if self._detect_encoded_traversal(normalized):
            return True, "Encoded path traversal detected"
        
        return False, None

    def _detect_absolute_path(self, payload: str) -> bool:
        absolute_patterns = [
            r"^/etc/",
            r"^/proc/",
            r"^/sys/",
            r"^c:\\windows\\",
            r"^c:\\winnt\\",
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in absolute_patterns)

    def _detect_encoded_traversal(self, payload: str) -> bool:
        encoded_patterns = [
            r"%2e%2e",
            r"%252e%252e",
            r"%c0%ae%c0%ae",
            r"%c1%9c",
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in encoded_patterns)

