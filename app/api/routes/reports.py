from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from typing import Optional
from app.api.dependencies import get_database
from app.models.security_event import SecurityEvent

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/daily")
async def get_daily_report(
    date: Optional[datetime] = Query(None),
    db: Session = Depends(get_database)
):
    if date is None:
        date = datetime.utcnow()
    
    start_date = date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_date = start_date + timedelta(days=1)
    
    total_requests = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= start_date,
        SecurityEvent.created_at < end_date
    ).scalar() or 0
    
    blocked_requests = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= start_date,
        SecurityEvent.created_at < end_date,
        SecurityEvent.blocked == 1
    ).scalar() or 0
    
    by_threat_type = db.query(
        SecurityEvent.threat_type,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= start_date,
        SecurityEvent.created_at < end_date
    ).group_by(SecurityEvent.threat_type).all()
    
    top_ips = db.query(
        SecurityEvent.ip_address,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= start_date,
        SecurityEvent.created_at < end_date
    ).group_by(SecurityEvent.ip_address).order_by(desc("count")).limit(20).all()
    
    top_endpoints = db.query(
        SecurityEvent.endpoint,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= start_date,
        SecurityEvent.created_at < end_date
    ).group_by(SecurityEvent.endpoint).order_by(desc("count")).limit(20).all()
    
    return {
        "date": start_date.isoformat(),
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "block_rate": (blocked_requests / total_requests * 100) if total_requests > 0 else 0,
        "by_threat_type": {t[0]: t[1] for t in by_threat_type},
        "top_ips": [{"ip": ip[0], "count": ip[1]} for ip in top_ips],
        "top_endpoints": [{"endpoint": ep[0], "count": ep[1]} for ep in top_endpoints]
    }

