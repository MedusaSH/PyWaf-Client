import re
from typing import Dict, Optional, Tuple
from fastapi import Request
from app.core.logger import logger


class HeadlessDetector:
    def __init__(self):
        self.headless_indicators = {
            "puppeteer": [
                "headlesschrome",
                "headless",
                "puppeteer",
                "chrome-lighthouse"
            ],
            "selenium": [
                "selenium",
                "webdriver",
                "selenium-webdriver",
                "phantomjs",
                "ghostdriver"
            ],
            "playwright": [
                "playwright",
                "playwright-firefox",
                "playwright-chromium"
            ],
            "automation": [
                "automation",
                "webdriver",
                "testcafe",
                "cypress"
            ]
        }
        
        self.suspicious_headers = [
            "x-forwarded-for",
            "x-real-ip",
            "via",
            "proxy-connection"
        ]
        
        self.headless_ua_patterns = [
            r"headless",
            r"phantomjs",
            r"selenium",
            r"webdriver",
            r"puppeteer",
            r"playwright",
            r"automation",
            r"testcafe",
            r"cypress"
        ]

    def detect_headless(self, request: Request) -> Tuple[bool, float, Dict[str, any]]:
        user_agent = request.headers.get("user-agent", "").lower()
        headers = dict(request.headers)
        
        detection_score = 0.0
        indicators = []
        confidence = 0.0
        
        ua_detection = self._analyze_user_agent(user_agent)
        if ua_detection["detected"]:
            detection_score += 0.6
            indicators.extend(ua_detection["indicators"])
        
        header_detection = self._analyze_headers(headers)
        if header_detection["detected"]:
            detection_score += 0.3
            indicators.extend(header_detection["indicators"])
        
        behavior_detection = self._analyze_behavior(request)
        if behavior_detection["detected"]:
            detection_score += 0.1
            indicators.extend(behavior_detection["indicators"])
        
        if detection_score >= 0.6:
            confidence = min(detection_score, 1.0)
            detected = True
        elif detection_score >= 0.3:
            confidence = detection_score
            detected = True
        else:
            detected = False
            confidence = detection_score
        
        return detected, confidence, {
            "indicators": list(set(indicators)),
            "user_agent": user_agent,
            "detection_score": detection_score,
            "ua_analysis": ua_detection,
            "header_analysis": header_detection,
            "behavior_analysis": behavior_detection
        }

    def _analyze_user_agent(self, user_agent: str) -> Dict[str, any]:
        if not user_agent:
            return {"detected": True, "indicators": ["missing_user_agent"]}
        
        detected = False
        indicators = []
        
        for pattern in self.headless_ua_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                detected = True
                indicators.append(f"ua_pattern:{pattern}")
        
        for category, keywords in self.headless_indicators.items():
            for keyword in keywords:
                if keyword in user_agent:
                    detected = True
                    indicators.append(f"ua_keyword:{category}:{keyword}")
        
        if len(user_agent) < 20:
            indicators.append("ua_too_short")
        
        if "mozilla" not in user_agent and "chrome" not in user_agent and "safari" not in user_agent and "firefox" not in user_agent:
            if user_agent:
                indicators.append("ua_unusual_format")
        
        return {
            "detected": detected,
            "indicators": indicators,
            "user_agent": user_agent
        }

    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, any]:
        detected = False
        indicators = []
        
        if "accept-language" not in headers:
            indicators.append("missing_accept_language")
        
        if "accept-encoding" not in headers:
            indicators.append("missing_accept_encoding")
        
        accept_language = headers.get("accept-language", "")
        if accept_language and len(accept_language) < 5:
            indicators.append("accept_language_too_short")
        
        if "sec-ch-ua" not in headers:
            indicators.append("missing_sec_ch_ua")
        
        if "sec-fetch-dest" not in headers:
            indicators.append("missing_sec_fetch_dest")
        
        if "sec-fetch-mode" not in headers:
            indicators.append("missing_sec_fetch_mode")
        
        if "sec-fetch-site" not in headers:
            indicators.append("missing_sec_fetch_site")
        
        if "sec-fetch-user" not in headers:
            indicators.append("missing_sec_fetch_user")
        
        webdriver_header = headers.get("webdriver", "")
        if webdriver_header:
            detected = True
            indicators.append("webdriver_header_present")
        
        if "x-requested-with" in headers:
            x_requested_with = headers.get("x-requested-with", "").lower()
            if "xmlhttprequest" not in x_requested_with:
                indicators.append("unusual_x_requested_with")
        
        connection = headers.get("connection", "").lower()
        if connection and connection != "keep-alive" and connection != "close":
            indicators.append("unusual_connection_header")
        
        if len(indicators) >= 3:
            detected = True
        
        return {
            "detected": detected,
            "indicators": indicators
        }

    def _analyze_behavior(self, request: Request) -> Dict[str, any]:
        detected = False
        indicators = []
        
        referer = request.headers.get("referer", "")
        if not referer and request.method == "GET":
            indicators.append("missing_referer_on_get")
        
        accept = request.headers.get("accept", "")
        if accept:
            if "text/html" not in accept and "application/json" not in accept:
                indicators.append("unusual_accept_header")
        else:
            indicators.append("missing_accept_header")
        
        if len(indicators) >= 2:
            detected = True
        
        return {
            "detected": detected,
            "indicators": indicators
        }

    def get_headless_type(self, detection_result: Dict[str, any]) -> Optional[str]:
        indicators = detection_result.get("indicators", [])
        
        if any("puppeteer" in ind for ind in indicators):
            return "puppeteer"
        elif any("selenium" in ind for ind in indicators):
            return "selenium"
        elif any("playwright" in ind for ind in indicators):
            return "playwright"
        elif any("webdriver" in ind for ind in indicators):
            return "webdriver"
        elif any("automation" in ind for ind in indicators):
            return "automation"
        
        return None

