from typing import Optional, Any
from fastapi import Request
from app.core.logger import logger
from app.security.headless_detector import HeadlessDetector
from app.config import settings


class RequestAnalyzer:
    def __init__(self):
        self.headless_detection_enabled = getattr(settings, 'headless_detection_enabled', True)
        self.headless_detector = HeadlessDetector() if self.headless_detection_enabled else None

    async def analyze(self, request: Request) -> dict[str, Any]:
        ip_address = self._get_client_ip(request)
        endpoint = str(request.url.path)
        method = request.method
        user_agent = request.headers.get("user-agent", "")
        
        query_params = dict(request.query_params)
        form_data = {}
        json_data = {}
        
        if request.headers.get("content-type", "").startswith("application/json"):
            try:
                json_data = await request.json()
            except Exception:
                pass
        elif request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            try:
                form_data = await request.form()
                form_data = dict(form_data)
            except Exception:
                pass
        
        payload_string = self._build_payload_string(query_params, form_data, json_data)
        
        if self.headless_detector:
            headless_detected, headless_confidence, headless_details = self.headless_detector.detect_headless(request)
            headless_type = self.headless_detector.get_headless_type(headless_details) if headless_detected else None
        else:
            headless_detected = False
            headless_confidence = 0.0
            headless_type = None
            headless_details = {}
        
        return {
            "ip_address": ip_address,
            "endpoint": endpoint,
            "method": method,
            "user_agent": user_agent,
            "query_params": query_params,
            "form_data": form_data,
            "json_data": json_data,
            "payload_string": payload_string,
            "headers": dict(request.headers),
            "headless_detected": headless_detected,
            "headless_confidence": headless_confidence,
            "headless_type": headless_type,
            "headless_details": headless_details,
        }

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        if request.client:
            return request.client.host
        
        return "unknown"

    def _build_payload_string(
        self,
        query_params: dict,
        form_data: dict,
        json_data: dict
    ) -> str:
        parts = []
        
        if query_params:
            parts.append(str(query_params))
        
        if form_data:
            parts.append(str(form_data))
        
        if json_data:
            parts.append(str(json_data))
        
        return " ".join(parts)

