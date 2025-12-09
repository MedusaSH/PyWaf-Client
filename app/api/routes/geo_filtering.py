from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from app.api.dependencies import get_database
from app.security.geo_filtering import GeoFiltering
from app.core.logger import logger

router = APIRouter(prefix="/api/geo-filtering", tags=["geo-filtering"])


class BlockRegionRequest(BaseModel):
    country_code: str
    duration_seconds: int = 3600
    reason: str = "DDoS attack detected"


class UnblockRegionRequest(BaseModel):
    country_code: str


@router.get("/status")
async def get_geo_filtering_status(
    db: Session = Depends(get_database)
):
    try:
        geo_filtering = GeoFiltering()
        
        if not geo_filtering.enabled:
            return {
                "enabled": False,
                "message": "Geo filtering is disabled"
            }
        
        blocked_regions = geo_filtering.get_blocked_regions()
        
        return {
            "enabled": True,
            "blocked_regions": blocked_regions,
            "count": len(blocked_regions)
        }
    except Exception as e:
        logger.error("geo_filtering_status_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error getting geo filtering status")


@router.get("/analysis")
async def analyze_attacks_by_region(
    time_window_minutes: Optional[int] = None,
    db: Session = Depends(get_database)
):
    try:
        geo_filtering = GeoFiltering()
        
        if not geo_filtering.enabled:
            raise HTTPException(status_code=400, detail="Geo filtering is disabled")
        
        region_stats = geo_filtering.analyze_attack_by_region(db, time_window_minutes)
        
        return {
            "time_window_minutes": time_window_minutes or geo_filtering.analysis_window_minutes,
            "attack_threshold": geo_filtering.attack_threshold,
            "regions": region_stats
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("geo_analysis_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error analyzing attacks by region")


@router.post("/block")
async def block_region(
    request: BlockRegionRequest,
    db: Session = Depends(get_database)
):
    try:
        geo_filtering = GeoFiltering()
        
        if not geo_filtering.enabled:
            raise HTTPException(status_code=400, detail="Geo filtering is disabled")
        
        success = geo_filtering.block_region(
            request.country_code,
            request.duration_seconds,
            request.reason
        )
        
        if success:
            return {
                "success": True,
                "country_code": request.country_code,
                "duration_seconds": request.duration_seconds,
                "message": f"Region {request.country_code} blocked successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to block region")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("geo_block_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error blocking region")


@router.post("/unblock")
async def unblock_region(
    request: UnblockRegionRequest,
    db: Session = Depends(get_database)
):
    try:
        geo_filtering = GeoFiltering()
        
        success = geo_filtering.unblock_region(request.country_code)
        
        if success:
            return {
                "success": True,
                "country_code": request.country_code,
                "message": f"Region {request.country_code} unblocked successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to unblock region")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("geo_unblock_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error unblocking region")


@router.post("/auto-block")
async def auto_block_attack_regions(
    duration_seconds: int = Body(3600, embed=True),
    db: Session = Depends(get_database)
):
    try:
        geo_filtering = GeoFiltering()
        
        if not geo_filtering.enabled:
            raise HTTPException(status_code=400, detail="Geo filtering is disabled")
        
        blocked_regions = geo_filtering.auto_block_attack_regions(db, duration_seconds)
        
        return {
            "success": True,
            "blocked_regions": blocked_regions,
            "count": len(blocked_regions),
            "duration_seconds": duration_seconds,
            "message": f"Auto-blocked {len(blocked_regions)} regions"
        }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("geo_auto_block_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error auto-blocking regions")


@router.get("/connection-state")
async def get_connection_state_status():
    try:
        from app.security.connection_state_protection import ConnectionStateProtection
        
        protection = ConnectionStateProtection()
        status = protection.get_protection_status()
        
        return status
    except Exception as e:
        logger.error("connection_state_status_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error getting connection state status")

