from fastapi import APIRouter, Depends, Query, HTTPException, Body
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel
from app.api.dependencies import get_database
from app.security.tls_fingerprinting import TLSFingerprinter
from app.models.tls_fingerprint import TLSFingerprint
from app.core.logger import logger

router = APIRouter(prefix="/api/tls-fingerprint", tags=["tls-fingerprint"])


class TLSFingerprintUpdate(BaseModel):
    is_whitelisted: Optional[bool] = None
    is_blacklisted: Optional[bool] = None
    threat_level: Optional[str] = None
    description: Optional[str] = None


@router.get("/{fingerprint_hash}")
async def get_fingerprint_info(
    fingerprint_hash: str,
    db: Session = Depends(get_database)
):
    try:
        fingerprinter = TLSFingerprinter()
        info = fingerprinter.get_fingerprint_info(fingerprint_hash, db)
        
        if not info:
            raise HTTPException(status_code=404, detail="Fingerprint not found")
        
        return info
    except HTTPException:
        raise
    except Exception as e:
        logger.error("fingerprint_lookup_error", fingerprint=fingerprint_hash, error=str(e))
        raise HTTPException(status_code=500, detail="Error retrieving fingerprint")


@router.put("/{fingerprint_hash}")
async def update_fingerprint(
    fingerprint_hash: str,
    update: TLSFingerprintUpdate,
    db: Session = Depends(get_database)
):
    try:
        fp_record = db.query(TLSFingerprint).filter(
            TLSFingerprint.fingerprint_hash == fingerprint_hash
        ).first()
        
        if not fp_record:
            raise HTTPException(status_code=404, detail="Fingerprint not found")
        
        if update.is_whitelisted is not None:
            fp_record.is_whitelisted = update.is_whitelisted
            if update.is_whitelisted:
                fp_record.is_blacklisted = False
        
        if update.is_blacklisted is not None:
            fp_record.is_blacklisted = update.is_blacklisted
            if update.is_blacklisted:
                fp_record.is_whitelisted = False
        
        if update.threat_level is not None:
            fp_record.threat_level = update.threat_level
        
        if update.description is not None:
            fp_record.description = update.description
        
        db.commit()
        
        fingerprinter = TLSFingerprinter()
        cache_key = f"tls_fp:{fingerprint_hash}"
        fingerprinter.redis.delete(cache_key)
        
        return {"message": "Fingerprint updated", "fingerprint_hash": fingerprint_hash}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("fingerprint_update_error", fingerprint=fingerprint_hash, error=str(e))
        db.rollback()
        raise HTTPException(status_code=500, detail="Error updating fingerprint")


@router.get("/{fingerprint_hash}/stats")
async def get_fingerprint_stats(
    fingerprint_hash: str,
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_database)
):
    try:
        fingerprinter = TLSFingerprinter()
        stats = fingerprinter.get_fingerprint_stats(fingerprint_hash, db, hours)
        return stats
    except Exception as e:
        logger.error("fingerprint_stats_error", fingerprint=fingerprint_hash, error=str(e))
        raise HTTPException(status_code=500, detail="Error retrieving fingerprint stats")


@router.get("")
async def list_fingerprints(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    is_whitelisted: Optional[bool] = None,
    is_blacklisted: Optional[bool] = None,
    threat_level: Optional[str] = None,
    db: Session = Depends(get_database)
):
    try:
        query = db.query(TLSFingerprint)
        
        if is_whitelisted is not None:
            query = query.filter(TLSFingerprint.is_whitelisted == is_whitelisted)
        
        if is_blacklisted is not None:
            query = query.filter(TLSFingerprint.is_blacklisted == is_blacklisted)
        
        if threat_level:
            query = query.filter(TLSFingerprint.threat_level == threat_level)
        
        fingerprints = query.order_by(TLSFingerprint.last_seen.desc()).offset(skip).limit(limit).all()
        
        return [
            {
                "fingerprint_hash": fp.fingerprint_hash,
                "is_whitelisted": fp.is_whitelisted,
                "is_blacklisted": fp.is_blacklisted,
                "threat_level": fp.threat_level,
                "request_count": fp.request_count,
                "blocked_count": fp.blocked_count,
                "block_ratio": fp.blocked_count / fp.request_count if fp.request_count > 0 else 0.0,
                "first_seen": fp.first_seen.isoformat() if fp.first_seen else None,
                "last_seen": fp.last_seen.isoformat() if fp.last_seen else None,
                "description": fp.description
            }
            for fp in fingerprints
        ]
    except Exception as e:
        logger.error("fingerprint_list_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error listing fingerprints")


@router.post("/{fingerprint_hash}/whitelist")
async def whitelist_fingerprint(
    fingerprint_hash: str,
    db: Session = Depends(get_database)
):
    try:
        fp_record = db.query(TLSFingerprint).filter(
            TLSFingerprint.fingerprint_hash == fingerprint_hash
        ).first()
        
        if not fp_record:
            raise HTTPException(status_code=404, detail="Fingerprint not found")
        
        fp_record.is_whitelisted = True
        fp_record.is_blacklisted = False
        
        db.commit()
        
        fingerprinter = TLSFingerprinter()
        cache_key = f"tls_fp:{fingerprint_hash}"
        fingerprinter.redis.delete(cache_key)
        
        return {"message": "Fingerprint whitelisted", "fingerprint_hash": fingerprint_hash}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("fingerprint_whitelist_error", fingerprint=fingerprint_hash, error=str(e))
        db.rollback()
        raise HTTPException(status_code=500, detail="Error whitelisting fingerprint")


@router.post("/{fingerprint_hash}/blacklist")
async def blacklist_fingerprint(
    fingerprint_hash: str,
    db: Session = Depends(get_database)
):
    try:
        fp_record = db.query(TLSFingerprint).filter(
            TLSFingerprint.fingerprint_hash == fingerprint_hash
        ).first()
        
        if not fp_record:
            raise HTTPException(status_code=404, detail="Fingerprint not found")
        
        fp_record.is_blacklisted = True
        fp_record.is_whitelisted = False
        
        db.commit()
        
        fingerprinter = TLSFingerprinter()
        cache_key = f"tls_fp:{fingerprint_hash}"
        fingerprinter.redis.delete(cache_key)
        
        return {"message": "Fingerprint blacklisted", "fingerprint_hash": fingerprint_hash}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("fingerprint_blacklist_error", fingerprint=fingerprint_hash, error=str(e))
        db.rollback()
        raise HTTPException(status_code=500, detail="Error blacklisting fingerprint")

