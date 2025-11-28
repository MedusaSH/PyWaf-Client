import re
from app.security.detectors.base import BaseDetector
from typing import Optional


class XSSDetector(BaseDetector):
    def __init__(self):
        self.patterns = [
            r"<script[^>]*>.*?</script>",
            r"<iframe[^>]*>.*?</iframe>",
            r"<object[^>]*>.*?</object>",
            r"<embed[^>]*>",
            r"<img[^>]*onerror\s*=",
            r"<img[^>]*onload\s*=",
            r"<body[^>]*onload\s*=",
            r"<svg[^>]*onload\s*=",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*src\s*=\s*['\"]?javascript:",
            r"<script[^>]*src\s*=\s*['\"]?javascript:",
            r"eval\s*\(",
            r"expression\s*\(",
            r"vbscript:",
            r"<link[^>]*href\s*=\s*['\"]?javascript:",
            r"<style[^>]*>.*?expression\s*\(.*?</style>",
            r"<meta[^>]*http-equiv\s*=\s*['\"]?refresh",
            r"<base[^>]*href",
            r"<form[^>]*action\s*=\s*['\"]?javascript:",
            r"<input[^>]*onfocus\s*=",
            r"<textarea[^>]*onfocus\s*=",
            r"<select[^>]*onfocus\s*=",
            r"<button[^>]*onclick\s*=",
            r"<div[^>]*onclick\s*=",
            r"<a[^>]*href\s*=\s*['\"]?javascript:",
        ]

    def detect(self, payload: str) -> tuple[bool, Optional[str]]:
        normalized = payload
        
        for pattern in self.patterns:
            if re.search(pattern, normalized, re.IGNORECASE | re.DOTALL):
                return True, f"XSS pattern detected: {pattern}"
        
        if self._detect_reflected_xss(normalized):
            return True, "Reflected XSS detected"
        
        if self._detect_stored_xss(normalized):
            return True, "Stored XSS detected"
        
        if self._detect_dom_xss(normalized):
            return True, "DOM-based XSS detected"
        
        return False, None

    def _detect_reflected_xss(self, payload: str) -> bool:
        script_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=\s*['\"]",
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in script_patterns)

    def _detect_stored_xss(self, payload: str) -> bool:
        stored_patterns = [
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<img[^>]*onerror",
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in stored_patterns)

    def _detect_dom_xss(self, payload: str) -> bool:
        dom_patterns = [
            r"document\.(cookie|location|write|writeln)",
            r"window\.(location|open)",
            r"eval\s*\(",
            r"innerHTML\s*=",
            r"outerHTML\s*=",
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in dom_patterns)

