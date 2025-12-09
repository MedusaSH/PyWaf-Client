import secrets
import hashlib
import time
import json
import base64
from typing import Optional, Dict, Tuple
from fastapi import Response, status
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from app.core.redis_client import get_redis
from app.core.logger import logger
from app.config import settings


class ChallengeSystem:
    def __init__(self):
        self.redis = get_redis()
        self.challenge_ttl = 300
        self.cookie_name = "waf_challenge"
        self.cookie_ttl = getattr(settings, 'encrypted_cookie_ttl', 3600)
        self.staged_escalation_enabled = True
        self.challenge_bypass_threshold = settings.challenge_bypass_threshold
        self.encrypted_cookie_name = "waf_legit_token"
        self.javascript_tarpit_enabled = getattr(settings, 'javascript_tarpit_enabled', True)
        self.javascript_tarpit_complexity_min = getattr(settings, 'javascript_tarpit_complexity_min', 4)
        self.javascript_tarpit_complexity_max = getattr(settings, 'javascript_tarpit_complexity_max', 7)
        self.javascript_tarpit_min_solve_time = getattr(settings, 'javascript_tarpit_min_solve_time_ms', 100.0)
        self.javascript_tarpit_max_solve_time = getattr(settings, 'javascript_tarpit_max_solve_time_ms', 30000.0)
        self.encrypted_cookie_enabled = getattr(settings, 'encrypted_cookie_challenge_enabled', True)
        self.headless_confidence_threshold = getattr(settings, 'headless_detection_confidence_threshold', 0.6)
        self._cipher_suite = self._init_cipher_suite()

    def _init_cipher_suite(self) -> Fernet:
        secret_key = settings.secret_key.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"waf_challenge_salt",
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret_key))
        return Fernet(key)

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
        fingerprint_hash: Optional[str] = None,
        headless_detected: bool = False,
        headless_confidence: float = 0.0
    ) -> Tuple[int, str]:
        base_level = self.get_challenge_level(reputation_score, anomaly_score, request_count)
        
        if not self.staged_escalation_enabled:
            return base_level, "base"
        
        if headless_detected and headless_confidence >= self.headless_confidence_threshold:
            if base_level < 4:
                return 4, "headless_detected"
            elif base_level < 5:
                return 5, "headless_high_confidence"
        
        cookie_bypasses = self.get_challenge_bypass_count(identifier, "cookie")
        pow_bypasses = self.get_challenge_bypass_count(identifier, "pow")
        tarpit_bypasses = self.get_challenge_bypass_count(identifier, "tarpit")
        encrypted_cookie_bypasses = self.get_challenge_bypass_count(identifier, "encrypted_cookie")
        
        total_bypasses = pow_bypasses + tarpit_bypasses + encrypted_cookie_bypasses
        if total_bypasses >= self.challenge_bypass_threshold:
            return 5, "multiple_bypasses"
        
        if pow_bypasses >= self.challenge_bypass_threshold:
            return 5, "pow_bypassed"
        
        if tarpit_bypasses >= self.challenge_bypass_threshold:
            if base_level < 4:
                return 4, "tarpit_bypassed"
        
        if encrypted_cookie_bypasses >= self.challenge_bypass_threshold:
            if base_level < 3:
                return 3, "encrypted_cookie_bypassed"
            elif base_level < 4:
                return 4, "escalated_after_encrypted_cookie_bypass"
        
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
        difficulty: int = 3,
        headless_detected: bool = False,
        headless_confidence: float = 0.0
    ) -> Response:
        if level >= 5:
            return Response(
                content='{"error": "Access denied", "reason": "Malicious activity detected"}',
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="application/json"
            )
        
        if level == 4:
            if headless_detected and headless_confidence >= self.headless_confidence_threshold:
                challenge = self.create_javascript_tarpit_challenge(ip_address, complexity=6)
                return Response(
                    content=challenge["html_page"],
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    media_type="text/html"
                )
            else:
                challenge = self.create_proof_of_work_challenge(ip_address, difficulty)
                return Response(
                    content=f'{{"error": "Challenge required", "type": "proof_of_work", "token": "{challenge["token"]}", "difficulty": {challenge["difficulty"]}, "js_code": {json.dumps(challenge["js_code"])}}}',
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    media_type="application/json"
                )
        
        if level == 3:
            challenge = self.create_encrypted_cookie_challenge(ip_address)
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
            return Response(
                content=html_page,
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="text/html"
            )
        
        return None

    def should_apply_challenge(
        self,
        reputation_score: float,
        anomaly_score: float,
        request_count: int,
        identifier: str = "",
        fingerprint_hash: Optional[str] = None,
        headless_detected: bool = False,
        headless_confidence: float = 0.0
    ) -> Tuple[bool, int, str]:
        level, reason = self.get_staged_challenge_level(
            identifier,
            reputation_score,
            anomaly_score,
            request_count,
            fingerprint_hash,
            headless_detected,
            headless_confidence
        )
        return level > 1, level, reason

    def create_javascript_tarpit_challenge(
        self,
        ip_address: str,
        complexity: Optional[int] = None
    ) -> Dict[str, any]:
        if not self.javascript_tarpit_enabled:
            return self.create_proof_of_work_challenge(ip_address, 3)
        
        if complexity is None:
            complexity = self.javascript_tarpit_complexity_min
        complexity = max(self.javascript_tarpit_complexity_min, min(complexity, self.javascript_tarpit_complexity_max))
        token = self.generate_challenge_token()
        challenge_key = f"challenge:tarpit:{ip_address}:{token}"
        
        challenge_data = {
            "type": "javascript_tarpit",
            "token": token,
            "complexity": complexity,
            "timestamp": time.time(),
            "ip": ip_address
        }
        
        self.redis.setex(challenge_key, self.challenge_ttl, json.dumps(challenge_data))
        
        js_code = self._generate_tarpit_js_code(token, complexity)
        html_page = self._generate_tarpit_html_page(token, js_code)
        
        return {
            "type": "javascript_tarpit",
            "token": token,
            "complexity": complexity,
            "js_code": js_code,
            "html_page": html_page
        }

    def _generate_tarpit_js_code(self, token: str, complexity: int) -> str:
        iterations = 1000 * (2 ** complexity)
        return f"""
(function() {{
    const token = '{token}';
    const iterations = {iterations};
    const startTime = performance.now();
    
    function computeHash(input) {{
        let hash = 0;
        for (let i = 0; i < input.length; i++) {{
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }}
        return hash;
    }}
    
    function solveTarpit() {{
        let result = 0;
        const baseString = token + window.location.href + navigator.userAgent;
        
        for (let i = 0; i < iterations; i++) {{
            const hash1 = computeHash(baseString + i);
            const hash2 = computeHash(i + baseString);
            result = (result + hash1 * hash2) % 2147483647;
            
            if (i % 10000 === 0) {{
                if (document.hidden) {{
                    return;
                }}
            }}
        }}
        
        const solveTime = performance.now() - startTime;
        const solution = (result ^ computeHash(token)).toString(36);
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/challenges/verify-tarpit', true);
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
            solution: solution,
            solve_time: solveTime
        }}));
    }}
    
    if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', solveTarpit);
    }} else {{
        solveTarpit();
    }}
}})();
"""

    def _generate_tarpit_html_page(self, token: str, js_code: str) -> str:
        return f"""<!DOCTYPE html>
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
    <script>{js_code}</script>
</body>
</html>"""

    def verify_javascript_tarpit(
        self,
        ip_address: str,
        token: str,
        solution: str,
        solve_time: float
    ) -> bool:
        challenge_key = f"challenge:tarpit:{ip_address}:{token}"
        challenge_data = self.redis.get(challenge_key)
        
        if not challenge_data:
            return False
        
        try:
            data = json.loads(challenge_data)
            expected_complexity = data.get("complexity", 5)
            
            if solve_time < self.javascript_tarpit_min_solve_time:
                return False
            
            if solve_time > self.javascript_tarpit_max_solve_time:
                return False
            
            expected_result = self._compute_tarpit_solution(token, expected_complexity)
            
            if solution == expected_result:
                self.redis.delete(challenge_key)
                return True
            
            return False
        except Exception:
            return False

    def _compute_tarpit_solution(self, token: str, complexity: int) -> str:
        iterations = 1000 * (2 ** complexity)
        result = 0
        
        for i in range(iterations):
            hash1 = int(hashlib.sha256(f"{token}{i}".encode()).hexdigest()[:8], 16) & 0x7FFFFFFF
            hash2 = int(hashlib.sha256(f"{i}{token}".encode()).hexdigest()[:8], 16) & 0x7FFFFFFF
            result = (result + hash1 * hash2) % 2147483647
        
        token_hash = int(hashlib.sha256(token.encode()).hexdigest()[:8], 16) & 0x7FFFFFFF
        solution = (result ^ token_hash) % 2147483647
        
        base36_chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        if solution == 0:
            return "0"
        
        encoded = ""
        num = solution
        while num > 0:
            encoded = base36_chars[num % 36] + encoded
            num //= 36
        
        return encoded

    def create_encrypted_cookie_challenge(
        self,
        ip_address: str
    ) -> Dict[str, any]:
        if not self.encrypted_cookie_enabled:
            return self.create_cookie_challenge(ip_address)
        token = self.generate_challenge_token()
        timestamp = int(time.time())
        
        challenge_data = {
            "token": token,
            "ip": ip_address,
            "timestamp": timestamp,
            "nonce": secrets.token_hex(16)
        }
        
        encrypted_data = self._encrypt_challenge_data(challenge_data)
        challenge_key = f"challenge:encrypted_cookie:{ip_address}:{token}"
        
        self.redis.setex(challenge_key, self.challenge_ttl, json.dumps(challenge_data))
        
        js_code = self._generate_encrypted_cookie_js_code(token, encrypted_data)
        
        return {
            "type": "encrypted_cookie",
            "token": token,
            "encrypted_data": encrypted_data,
            "js_code": js_code,
            "cookie_name": self.encrypted_cookie_name
        }

    def _encrypt_challenge_data(self, data: Dict) -> str:
        json_data = json.dumps(data)
        encrypted = self._cipher_suite.encrypt(json_data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def _decrypt_challenge_data(self, encrypted_data: str) -> Optional[Dict]:
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self._cipher_suite.decrypt(decoded)
            return json.loads(decrypted.decode())
        except Exception:
            return None

    def _generate_encrypted_cookie_js_code(self, token: str, encrypted_data: str) -> str:
        return f"""
(function() {{
    const token = '{token}';
    const encryptedData = '{encrypted_data}';
    const cookieName = '{self.encrypted_cookie_name}';
    
    function setCookie(name, value, days) {{
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = name + '=' + value + ';expires=' + expires.toUTCString() + ';path=/;SameSite=Strict';
    }}
    
    function verifyAndSetCookie() {{
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/challenges/verify-encrypted-cookie', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function() {{
            if (xhr.readyState === 4) {{
                if (xhr.status === 200) {{
                    const response = JSON.parse(xhr.responseText);
                    if (response.verified) {{
                        setCookie(cookieName, encryptedData, 1);
                        window.location.reload();
                    }}
                }}
            }}
        }};
        xhr.send(JSON.stringify({{
            token: token,
            encrypted_data: encryptedData
        }}));
    }}
    
    if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', verifyAndSetCookie);
    }} else {{
        verifyAndSetCookie();
    }}
}})();
"""

    def verify_encrypted_cookie_challenge(
        self,
        ip_address: str,
        token: str,
        encrypted_data: str
    ) -> bool:
        challenge_key = f"challenge:encrypted_cookie:{ip_address}:{token}"
        stored_data = self.redis.get(challenge_key)
        
        if not stored_data:
            return False
        
        try:
            decrypted = self._decrypt_challenge_data(encrypted_data)
            if not decrypted:
                return False
            
            stored = json.loads(stored_data)
            
            if decrypted.get("token") != stored.get("token"):
                return False
            
            if decrypted.get("ip") != ip_address:
                return False
            
            timestamp = decrypted.get("timestamp", 0)
            if time.time() - timestamp > self.challenge_ttl:
                return False
            
            self.redis.delete(challenge_key)
            return True
        except Exception:
            return False

    def verify_encrypted_cookie_from_request(
        self,
        ip_address: str,
        cookie_value: str
    ) -> bool:
        try:
            decrypted = self._decrypt_challenge_data(cookie_value)
            if not decrypted:
                return False
            
            if decrypted.get("ip") != ip_address:
                return False
            
            timestamp = decrypted.get("timestamp", 0)
            if time.time() - timestamp > self.cookie_ttl:
                return False
            
            return True
        except Exception:
            return False

