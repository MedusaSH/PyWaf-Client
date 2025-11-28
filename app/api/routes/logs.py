from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional
from datetime import datetime
from app.api.dependencies import get_database
from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventResponse

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("/security", response_model=list[SecurityEventResponse])
async def get_security_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    ip_address: Optional[str] = None,
    endpoint: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_database)
):
    query = db.query(SecurityEvent)
    
    if ip_address:
        query = query.filter(SecurityEvent.ip_address == ip_address)
    
    if endpoint:
        query = query.filter(SecurityEvent.endpoint == endpoint)
    
    if start_date:
        query = query.filter(SecurityEvent.created_at >= start_date)
    
    if end_date:
        query = query.filter(SecurityEvent.created_at <= end_date)
    
    logs = query.order_by(desc(SecurityEvent.created_at)).offset(skip).limit(limit).all()
    
    return logs

