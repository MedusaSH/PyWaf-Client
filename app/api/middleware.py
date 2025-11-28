import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from app.security.waf_engine import WAFEngine
from app.core.database import SessionLocal
from app.core.logger import logger
from app.models.security_event import SecurityEvent, ThreatLevel
from app.schemas.security_event import SecurityEventCreate


class WAFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, target_url: str = None):
        super().__init__(app)
        self.waf_engine = WAFEngine()
        self.target_url = target_url

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/") or request.url.path.startswith("/docs"):
            return await call_next(request)
        
        db = SessionLocal()
        try:
            allowed, blocked_response, analysis_result = await self.waf_engine.process_request(
                request,
                db
            )
            
            if not allowed and blocked_response:
                if analysis_result:
                    await self._log_security_event(
                        db,
                        analysis_result,
                        "blocked",
                        ThreatLevel.HIGH
                    )
                return blocked_response
            
            if analysis_result:
                response = await call_next(request)
                
                if response.status_code >= 400:
                    await self._log_security_event(
                        db,
                        analysis_result,
                        "suspicious",
                        ThreatLevel.MEDIUM
                    )
                
                return response
            
            return await call_next(request)
            
        except Exception as e:
            logger.error("middleware_error", error=str(e))
            return await call_next(request)
        finally:
            db.close()

    async def _log_security_event(
        self,
        db: Session,
        analysis_result: dict,
        threat_type: str,
        threat_level: ThreatLevel
    ):
        try:
            event = SecurityEvent(
                ip_address=analysis_result.get("ip_address", "unknown"),
                endpoint=analysis_result.get("endpoint", ""),
                method=analysis_result.get("method", ""),
                threat_type=threat_type,
                threat_level=threat_level,
                payload=analysis_result,
                user_agent=analysis_result.get("user_agent"),
                blocked=1 if threat_type == "blocked" else 0
            )
            db.add(event)
            db.commit()
        except Exception as e:
            logger.error("log_security_event_error", error=str(e))
            db.rollback()

