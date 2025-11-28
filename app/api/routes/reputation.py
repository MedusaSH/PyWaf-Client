from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from app.api.dependencies import get_database
from app.security.ip_reputation import IPReputationEngine
from app.security.behavioral_analyzer import BehavioralAnalyzer
from app.security.ml_anomaly_detector import MLAnomalyDetector
from app.core.logger import logger

router = APIRouter(prefix="/api/reputation", tags=["reputation"])


@router.get("/{ip_address}")
async def get_ip_reputation(
    ip_address: str,
    db: Session = Depends(get_database)
):
    try:
        engine = IPReputationEngine()
        reputation = engine.get_reputation(ip_address, db)
        return reputation
    except Exception as e:
        logger.error("reputation_lookup_error", ip=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail="Error retrieving reputation")


@router.get("/{ip_address}/behavioral")
async def get_behavioral_analysis(
    ip_address: str,
    db: Session = Depends(get_database)
):
    try:
        analyzer = BehavioralAnalyzer()
        
        from app.models.security_event import SecurityEvent
        from datetime import datetime, timedelta
        
        since = datetime.utcnow() - timedelta(hours=1)
        recent_events = db.query(SecurityEvent).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since
        ).limit(100).all()
        
        if not recent_events:
            return {
                "ip_address": ip_address,
                "is_bot": False,
                "is_scraper": False,
                "is_automated": False,
                "confidence": 0.0,
                "patterns": []
            }
        
        analysis = analyzer.analyze_request_pattern(
            ip_address,
            recent_events[0].endpoint if recent_events else "",
            analyzer.generate_fingerprint({
                "user_agent": recent_events[0].user_agent if recent_events and recent_events[0].user_agent else "",
                "headers": {}
            }),
            db
        )
        
        return {
            "ip_address": ip_address,
            **analysis
        }
    except Exception as e:
        logger.error("behavioral_analysis_error", ip=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail="Error performing behavioral analysis")


@router.get("/{ip_address}/ml")
async def get_ml_analysis(
    ip_address: str,
    db: Session = Depends(get_database)
):
    try:
        detector = MLAnomalyDetector()
        
        analysis = detector.analyze_request(
            ip_address,
            {},
            db
        )
        
        return {
            "ip_address": ip_address,
            **analysis
        }
    except Exception as e:
        logger.error("ml_analysis_error", ip=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail="Error performing ML analysis")


@router.get("/{ip_address}/full")
async def get_full_analysis(
    ip_address: str,
    db: Session = Depends(get_database)
):
    try:
        reputation_engine = IPReputationEngine()
        behavioral_analyzer = BehavioralAnalyzer()
        ml_detector = MLAnomalyDetector()
        
        reputation = reputation_engine.get_reputation(ip_address, db)
        
        from app.models.security_event import SecurityEvent
        from datetime import datetime, timedelta
        
        since = datetime.utcnow() - timedelta(hours=1)
        recent_events = db.query(SecurityEvent).filter(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= since
        ).limit(100).all()
        
        behavioral = None
        if recent_events:
            behavioral = behavioral_analyzer.analyze_request_pattern(
                ip_address,
                recent_events[0].endpoint if recent_events else "",
                behavioral_analyzer.generate_fingerprint({
                    "user_agent": recent_events[0].user_agent if recent_events and recent_events[0].user_agent else "",
                    "headers": {}
                }),
                db
            )
        
        ml_analysis = ml_detector.analyze_request(ip_address, {}, db)
        
        return {
            "ip_address": ip_address,
            "reputation": reputation,
            "behavioral": behavioral,
            "ml_analysis": ml_analysis,
            "risk_score": max(
                reputation.get("total_score", 0),
                behavioral.get("confidence", 0) * 100 if behavioral else 0,
                ml_analysis.get("anomaly_score", 0) * 100
            )
        }
    except Exception as e:
        logger.error("full_analysis_error", ip=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail="Error performing full analysis")

