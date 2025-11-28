import re
from app.security.detectors.base import BaseDetector
from typing import Optional


class CommandInjectionDetector(BaseDetector):
    def __init__(self):
        self.patterns = [
            r"[;&|`]\s*(ls|cat|pwd|whoami|id|uname|ps|netstat)",
            r"[;&|`]\s*(rm|del|mkdir|rmdir|mv|cp)",
            r"[;&|`]\s*(wget|curl|nc|netcat|telnet)",
            r"[;&|`]\s*(python|perl|ruby|php|node)\s",
            r"[;&|`]\s*(bash|sh|zsh|csh|ksh)\s",
            r"[;&|`]\s*(echo|print|printf)\s",
            r"\|\s*(bash|sh|nc|nc)",
            r"`[^`]+`",
            r"\$\([^)]+\)",
            r"&&\s*\w+",
            r"\|\|\s*\w+",
            r";\s*\w+",
            r"\|\s*\w+",
            r"<\([^)]+\)",
            r">\([^)]+\)",
        ]

    def detect(self, payload: str) -> tuple[bool, Optional[str]]:
        normalized = payload
        
        for pattern in self.patterns:
            if re.search(pattern, normalized, re.IGNORECASE):
                return True, f"Command injection pattern detected: {pattern}"
        
        if self._detect_shell_metacharacters(normalized):
            return True, "Shell metacharacters detected"
        
        if self._detect_command_chaining(normalized):
            return True, "Command chaining detected"
        
        return False, None

    def _detect_shell_metacharacters(self, payload: str) -> bool:
        metachar_patterns = [
            r"[;&|`$()<>]",
            r"\|\|",
            r"&&",
        ]
        return any(re.search(p, payload) for p in metachar_patterns)

    def _detect_command_chaining(self, payload: str) -> bool:
        chaining_patterns = [
            r"[;&|]\s*\w+",
            r"&&\s*\w+",
            r"\|\|\s*\w+",
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in chaining_patterns)

