from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.api.dependencies import get_database
from app.security.connection_metrics_analyzer import ConnectionMetricsAnalyzer
from app.security.behavioral_malice_scorer import BehavioralMaliceScorer
from app.core.logger import logger

router = APIRouter(prefix="/api/connection-metrics", tags=["connection-metrics"])


@router.get("/{ip_address}")
async def get_connection_metrics(
    ip_address: str,
    window_minutes: Optional[int] = Query(5, ge=1, le=60),
    db: Session = Depends(get_database)
):
    try:
        metrics_analyzer = ConnectionMetricsAnalyzer()
        
        if not metrics_analyzer:
            raise HTTPException(status_code=400, detail="Connection metrics analyzer is disabled")
        
        metrics = metrics_analyzer.get_comprehensive_metrics(ip_address, db, window_minutes)
        
        return {
            "ip_address": ip_address,
            "window_minutes": window_minutes,
            "metrics": metrics
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("connection_metrics_error", ip=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail="Error getting connection metrics")


@router.get("/{ip_address}/malice-score")
async def get_malice_score(
    ip_address: str,
    window_minutes: Optional[int] = Query(5, ge=1, le=60),
    db: Session = Depends(get_database)
):
    try:
        malice_scorer = BehavioralMaliceScorer()
        
        if not malice_scorer:
            raise HTTPException(status_code=400, detail="Behavioral malice scorer is disabled")
        
        from app.security.request_analyzer import RequestAnalyzer
        request_analyzer = RequestAnalyzer()
        
        from fastapi import Request as FastAPIRequest
        from starlette.requests import Request as StarletteRequest
        
        dummy_request = None
        request_data = {
            "ip_address": ip_address,
            "endpoint": "/",
            "method": "GET",
            "user_agent": "",
            "headers": {}
        }
        
        score_result = malice_scorer.calculate_malice_score(
            ip_address,
            request_data,
            db,
            None,
            window_minutes
        )
        
        return {
            "ip_address": ip_address,
            "window_minutes": window_minutes,
            "malice_score": score_result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("malice_score_error", ip=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail="Error calculating malice score")

