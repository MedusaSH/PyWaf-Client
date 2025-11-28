import re
from app.security.detectors.base import BaseDetector
from typing import Optional


class SQLInjectionDetector(BaseDetector):
    def __init__(self):
        self.patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bselect\b.*\bfrom\b)",
            r"(\binsert\b.*\binto\b.*\bvalues\b)",
            r"(\bdelete\b.*\bfrom\b)",
            r"(\bdrop\b.*\btable\b)",
            r"(\bupdate\b.*\bset\b)",
            r"(\bor\b.*=.*)",
            r"(\band\b.*=.*)",
            r"('.*or.*'.*=.*')",
            r"('.*or.*'.*'.*=.*')",
            r"('.*or.*'.*'.*'.*=.*')",
            r"(\bor\b.*1\s*=\s*1)",
            r"(\band\b.*1\s*=\s*1)",
            r"(\bor\b.*'1'\s*=\s*'1')",
            r"(\band\b.*'1'\s*=\s*'1')",
            r"(\bexec\b.*\()",
            r"(\bexecute\b.*\()",
            r"(\bxp_cmdshell\b)",
            r"(\bsp_executesql\b)",
            r"(;\s*shutdown\s*;)",
            r"(;\s*drop\s+table\s+)",
            r"(--)",
            r"(/\*.*\*/)",
            r"(\bwaitfor\b.*\bdelay\b)",
            r"(\bpg_sleep\b)",
            r"(\bsleep\b\s*\()",
            r"(\bbenchmark\b\s*\()",
        ]

    def detect(self, payload: str) -> tuple[bool, Optional[str]]:
        normalized = self.normalize_payload(payload)
        
        for pattern in self.patterns:
            if re.search(pattern, normalized, re.IGNORECASE | re.DOTALL):
                return True, f"SQL injection pattern detected: {pattern}"
        
        if self._detect_union_based(normalized):
            return True, "Union-based SQL injection detected"
        
        if self._detect_boolean_based(normalized):
            return True, "Boolean-based SQL injection detected"
        
        if self._detect_time_based(normalized):
            return True, "Time-based SQL injection detected"
        
        return False, None

    def _detect_union_based(self, payload: str) -> bool:
        union_pattern = r"\bunion\b.*\bselect\b"
        return bool(re.search(union_pattern, payload, re.IGNORECASE))

    def _detect_boolean_based(self, payload: str) -> bool:
        boolean_patterns = [
            r"'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+",
            r"'\s*(or|and)\s*'?[a-z]+'?\s*=\s*'?[a-z]+",
            r"'\s*(or|and)\s*1\s*=\s*1",
            r"'\s*(or|and)\s*'1'\s*=\s*'1'",
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in boolean_patterns)

    def _detect_time_based(self, payload: str) -> bool:
        time_patterns = [
            r"waitfor\s+delay",
            r"pg_sleep\s*\(",
            r"sleep\s*\(",
            r"benchmark\s*\(",
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in time_patterns)

