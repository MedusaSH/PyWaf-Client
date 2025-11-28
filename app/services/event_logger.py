from sqlalchemy.orm import Session
from app.models.security_event import SecurityEvent, ThreatLevel
from app.core.logger import logger
from typing import Optional, Any


class EventLogger:
    @staticmethod
    def log_security_event(
        db: Session,
        ip_address: str,
        endpoint: str,
        method: str,
        threat_type: str,
        threat_level: ThreatLevel,
        payload: Optional[dict[str, Any]] = None,
        user_agent: Optional[str] = None,
        blocked: int = 1
    ) -> SecurityEvent:
        try:
            event = SecurityEvent(
                ip_address=ip_address,
                endpoint=endpoint,
                method=method,
                threat_type=threat_type,
                threat_level=threat_level,
                payload=payload,
                user_agent=user_agent,
                blocked=blocked
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            
            logger.info(
                "security_event_logged",
                event_id=event.id,
                threat_type=threat_type,
                threat_level=threat_level.value
            )
            
            return event
            
        except Exception as e:
            logger.error("event_logger_error", error=str(e))
            db.rollback()
            raise

