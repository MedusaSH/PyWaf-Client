from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import Optional
from datetime import datetime, timedelta
from app.api.dependencies import get_database
from app.models.security_event import SecurityEvent, ThreatLevel
from app.schemas.security_event import SecurityEventResponse
from app.core.logger import logger

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/events", response_model=list[SecurityEventResponse])
async def get_security_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    threat_level: Optional[ThreatLevel] = None,
    threat_type: Optional[str] = None,
    ip_address: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_database)
):
    query = db.query(SecurityEvent)
    
    if threat_level:
        query = query.filter(SecurityEvent.threat_level == threat_level)
    
    if threat_type:
        query = query.filter(SecurityEvent.threat_type == threat_type)
    
    if ip_address:
        query = query.filter(SecurityEvent.ip_address == ip_address)
    
    if start_date:
        query = query.filter(SecurityEvent.created_at >= start_date)
    
    if end_date:
        query = query.filter(SecurityEvent.created_at <= end_date)
    
    events = query.order_by(desc(SecurityEvent.created_at)).offset(skip).limit(limit).all()
    
    return events


@router.get("/events/stats")
async def get_security_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_database)
):
    since = datetime.utcnow() - timedelta(hours=hours)
    
    total_blocked = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= since,
        SecurityEvent.blocked == 1
    ).scalar()
    
    by_threat_type = db.query(
        SecurityEvent.threat_type,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= since
    ).group_by(SecurityEvent.threat_type).all()
    
    by_level = db.query(
        SecurityEvent.threat_level,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= since
    ).group_by(SecurityEvent.threat_level).all()
    
    top_ips = db.query(
        SecurityEvent.ip_address,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= since
    ).group_by(SecurityEvent.ip_address).order_by(desc("count")).limit(10).all()
    
    return {
        "total_blocked": total_blocked or 0,
        "by_threat_type": {t[0]: t[1] for t in by_threat_type},
        "by_level": {t[0].value: t[1] for t in by_level},
        "top_ips": [{"ip": ip[0], "count": ip[1]} for ip in top_ips],
        "period_hours": hours
    }

