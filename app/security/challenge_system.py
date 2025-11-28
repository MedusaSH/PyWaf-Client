import secrets
import hashlib
import time
import json
from typing import Optional, Dict, Tuple
from fastapi import Response, status
from app.core.redis_client import get_redis
from app.core.logger import logger


class ChallengeSystem:
    def __init__(self):
        self.redis = get_redis()
        self.challenge_ttl = 300
        self.cookie_name = "waf_challenge"
        self.cookie_ttl = 3600
        self.staged_escalation_enabled = True
        self.challenge_bypass_threshold = 3

    def generate_challenge_token(self) -> str:
        return secrets.token_urlsafe(32)

    def create_cookie_challenge(self, ip_address: str) -> Dict[str, str]:
        token = self.generate_challenge_token()
        challenge_key = f"challenge:cookie:{ip_address}:{token}"
        
        challenge_data = {
            "type": "cookie",
            "token": token,
            "timestamp": time.time(),
            "ip": ip_address
        }
        
        self.redis.setex(challenge_key, self.challenge_ttl, "1")
        
        return {
            "token": token,
            "cookie_name": self.cookie_name,
            "cookie_value": token
        }

    def verify_cookie_challenge(self, ip_address: str, token: str) -> bool:
        challenge_key = f"challenge:cookie:{ip_address}:{token}"
        return self.redis.exists(challenge_key) > 0

    def create_proof_of_work_challenge(
        self,
        ip_address: str,
        difficulty: int = 3
    ) -> Dict[str, any]:
        token = self.generate_challenge_token()
        
        challenge_key = f"challenge:pow:{ip_address}:{token}"
        
        challenge_data = {
            "type": "proof_of_work",
            "token": token,
            "difficulty": difficulty,
            "timestamp": time.time(),
            "ip": ip_address
        }
        
        self.redis.setex(challenge_key, self.challenge_ttl, str(challenge_data))
        
        return {
            "type": "proof_of_work",
            "token": token,
            "difficulty": difficulty,
            "challenge": self._generate_pow_challenge(token, difficulty),
            "js_code": self._generate_pow_js_code(token, difficulty)
        }

    def _generate_pow_challenge(self, token: str, difficulty: int) -> str:
        return hashlib.sha256(f"{token}:{difficulty}".encode()).hexdigest()

    def verify_proof_of_work(
        self,
        ip_address: str,
        token: str,
        nonce: str,
        difficulty: Optional[int] = None
    ) -> bool:
        challenge_key = f"challenge:pow:{ip_address}:{token}"
        challenge_data = self.redis.get(challenge_key)
        
        if not challenge_data:
            return False
        
        try:
            if difficulty is None:
                difficulty = 3
            
            challenge_hash = hashlib.sha256(f"{token}:{nonce}".encode()).hexdigest()
            
            return challenge_hash.startswith("0" * difficulty)
        except:
            return False

    def _generate_pow_js_code(self, token: str, difficulty: int) -> str:
        return f"""
(async function() {{
    const token = '{token}';
    const difficulty = {difficulty};
    const target = '0'.repeat(difficulty);
    
    async function sha256(message) {{
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('');
    }}
    
    async function solvePow() {{
        let nonce = 0;
        const startTime = Date.now();
        
        while (true) {{
            const message = token + ':' + nonce;
            const hashHex = await sha256(message);
            
            if (hashHex.startsWith(target)) {{
                const solveTime = (Date.now() - startTime) / 1000;
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/challenges/verify-pow', true);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.onreadystatechange = function() {{
                    if (xhr.readyState === 4) {{
                        if (xhr.status === 200) {{
                            const response = JSON.parse(xhr.responseText);
                            if (response.verified) {{
                                window.location.reload();
                            }}
                        }}
                    }}
                }};
                xhr.send(JSON.stringify({{ 
                    token: token, 
                    nonce: nonce.toString(),
                    ip_address: window.location.hostname
                }}));
                return;
            }}
            nonce++;
        }}
    }}
    
    solvePow();
}})();
"""

    def track_challenge_bypass(
        self,
        identifier: str,
        challenge_type: str
    ):
        bypass_key = f"challenge_bypass:{identifier}:{challenge_type}"
        bypass_count = self.redis.incr(bypass_key)
        self.redis.expire(bypass_key, 3600)
        return bypass_count

    def get_challenge_bypass_count(
        self,
        identifier: str,
        challenge_type: str
    ) -> int:
        bypass_key = f"challenge_bypass:{identifier}:{challenge_type}"
        count = self.redis.get(bypass_key)
        return int(count) if count else 0

    def get_staged_challenge_level(
        self,
        identifier: str,
        reputation_score: float,
        anomaly_score: float,
        request_count: int,
        fingerprint_hash: Optional[str] = None
    ) -> Tuple[int, str]:
        base_level = self.get_challenge_level(reputation_score, anomaly_score, request_count)
        
        if not self.staged_escalation_enabled:
            return base_level, "base"
        
        cookie_bypasses = self.get_challenge_bypass_count(identifier, "cookie")
        pow_bypasses = self.get_challenge_bypass_count(identifier, "pow")
        
        if pow_bypasses >= self.challenge_bypass_threshold:
            return 5, "multiple_bypasses"
        
        if cookie_bypasses >= self.challenge_bypass_threshold:
            if base_level < 3:
                return 3, "cookie_bypassed"
            elif base_level < 4:
                return 4, "escalated_after_cookie_bypass"
        
        if fingerprint_hash:
            fp_bypasses = self.get_challenge_bypass_count(f"fp:{fingerprint_hash}", "cookie")
            if fp_bypasses >= self.challenge_bypass_threshold:
                return max(base_level, 3), "fingerprint_bypassed"
        
        return base_level, "normal"

    def get_challenge_level(
        self,
        reputation_score: float,
        anomaly_score: float,
        request_count: int
    ) -> int:
        if reputation_score >= 70.0 or anomaly_score >= 0.8:
            return 5
        elif reputation_score >= 40.0 or anomaly_score >= 0.6:
            return 4
        elif anomaly_score >= 0.4 or request_count > 50:
            return 3
        elif request_count > 20:
            return 2
        else:
            return 1

    def create_challenge_response(
        self,
        level: int,
        ip_address: str,
        reason: str,
        difficulty: int = 3
    ) -> Response:
        if level >= 5:
            return Response(
                content='{"error": "Access denied", "reason": "Malicious activity detected"}',
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="application/json"
            )
        
        if level == 4:
            challenge = self.create_proof_of_work_challenge(ip_address, difficulty)
            return Response(
                content=f'{{"error": "Challenge required", "type": "proof_of_work", "token": "{challenge["token"]}", "difficulty": {challenge["difficulty"]}, "js_code": {json.dumps(challenge["js_code"])}}}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json"
            )
        
        if level == 3:
            challenge = self.create_cookie_challenge(ip_address)
            response = Response(
                content='{"error": "Challenge required", "type": "cookie", "message": "Please enable cookies"}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json"
            )
            response.set_cookie(
                key=self.cookie_name,
                value=challenge["cookie_value"],
                max_age=self.cookie_ttl,
                httponly=True,
                samesite="strict"
            )
            return response
        
        return None

    def should_apply_challenge(
        self,
        reputation_score: float,
        anomaly_score: float,
        request_count: int,
        identifier: str = "",
        fingerprint_hash: Optional[str] = None
    ) -> Tuple[bool, int, str]:
        level, reason = self.get_staged_challenge_level(
            identifier,
            reputation_score,
            anomaly_score,
            request_count,
            fingerprint_hash
        )
        return level > 1, level, reason

