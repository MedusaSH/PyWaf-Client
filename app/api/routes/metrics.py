from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, extract
from datetime import datetime, timedelta
from app.api.dependencies import get_database
from app.models.security_event import SecurityEvent
from app.schemas.metrics import MetricsResponse, TrendData

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("/overview", response_model=MetricsResponse)
async def get_metrics_overview(
    hours: int = 24,
    db: Session = Depends(get_database)
):
    since = datetime.utcnow() - timedelta(hours=hours)
    previous_since = datetime.utcnow() - timedelta(hours=hours * 2)
    
    total_blocked = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= since,
        SecurityEvent.blocked == 1
    ).scalar() or 0
    
    previous_blocked = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= previous_since,
        SecurityEvent.created_at < since,
        SecurityEvent.blocked == 1
    ).scalar() or 0
    
    false_positives = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= since,
        SecurityEvent.blocked == 0
    ).scalar() or 0
    
    previous_false_positives = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= previous_since,
        SecurityEvent.created_at < since,
        SecurityEvent.blocked == 0
    ).scalar() or 0
    
    top_ips = db.query(
        SecurityEvent.ip_address,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= since
    ).group_by(SecurityEvent.ip_address).order_by(desc("count")).limit(10).all()
    
    top_endpoints = db.query(
        SecurityEvent.endpoint,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= since
    ).group_by(SecurityEvent.endpoint).order_by(desc("count")).limit(10).all()
    
    threat_categories = db.query(
        SecurityEvent.threat_type,
        func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= since
    ).group_by(SecurityEvent.threat_type).all()
    
    def calculate_trend(current: int, previous: int) -> TrendData:
        if previous == 0:
            is_positive = current > 0
            return TrendData(value=0.0, is_positive=is_positive)
        change = ((current - previous) / previous) * 100
        return TrendData(value=round(abs(change), 1), is_positive=change <= 0)
    
    trends = {
        "requests_blocked": calculate_trend(total_blocked, previous_blocked),
        "false_positives": calculate_trend(false_positives, previous_false_positives),
    }
    
    return MetricsResponse(
        requests_blocked=total_blocked,
        false_positives=false_positives,
        response_time_avg_ms=0.0,
        top_attacking_ips=[{"ip": ip[0], "count": ip[1]} for ip in top_ips],
        most_targeted_endpoints=[{"endpoint": ep[0], "count": ep[1]} for ep in top_endpoints],
        threat_categories={cat[0]: cat[1] for cat in threat_categories},
        trends=trends
    )


@router.get("/traffic-by-hour")
async def get_traffic_by_hour(
    hours: int = 24,
    db: Session = Depends(get_database)
):
    since = datetime.utcnow() - timedelta(hours=hours)
    
    traffic_data = db.query(
        extract('hour', SecurityEvent.created_at).label('hour'),
        func.count(SecurityEvent.id).label('total'),
        func.sum(func.cast(SecurityEvent.blocked == 1, func.Integer)).label('blocked')
    ).filter(
        SecurityEvent.created_at >= since
    ).group_by(
        extract('hour', SecurityEvent.created_at)
    ).order_by('hour').all()
    
    traffic_dict = {int(hour): {'requests': int(total), 'blocked': int(blocked or 0)} for hour, total, blocked in traffic_data}
    
    result = []
    for i in range(hours):
        hour_key = (datetime.utcnow() - timedelta(hours=hours - i - 1)).hour
        data = traffic_dict.get(hour_key, {'requests': 0, 'blocked': 0})
        result.append({
            'time': f'{hour_key}h',
            'requests': data['requests'],
            'blocked': data['blocked']
        })
    
    return result

