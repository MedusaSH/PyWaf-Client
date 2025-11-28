from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from app.api.dependencies import get_database
from app.models.ip_list import IPList, IPListType
from app.schemas.ip_list import IPListCreate, IPListResponse
from app.security.ip_manager import IPManager

router = APIRouter(prefix="/api/rules", tags=["ip-list"])
ip_manager = IPManager()


@router.post("/whitelist", response_model=IPListResponse, status_code=status.HTTP_201_CREATED)
async def add_to_whitelist(
    ip_data: IPListCreate,
    db: Session = Depends(get_database)
):
    if ip_data.list_type != IPListType.WHITELIST:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="list_type must be WHITELIST"
        )
    
    ip_entry = ip_manager.add_to_whitelist(
        ip_data.ip_address,
        ip_data.reason,
        ip_data.expires_at,
        db
    )
    
    return ip_entry


@router.post("/blacklist", response_model=IPListResponse, status_code=status.HTTP_201_CREATED)
async def add_to_blacklist(
    ip_data: IPListCreate,
    db: Session = Depends(get_database)
):
    if ip_data.list_type != IPListType.BLACKLIST:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="list_type must be BLACKLIST"
        )
    
    ip_entry = ip_manager.add_to_blacklist(
        ip_data.ip_address,
        ip_data.reason,
        ip_data.expires_at,
        db
    )
    
    return ip_entry


@router.get("/whitelist", response_model=list[IPListResponse])
async def get_whitelist(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_database)
):
    ips = db.query(IPList).filter(
        IPList.list_type == IPListType.WHITELIST
    ).offset(skip).limit(limit).all()
    
    return ips


@router.get("/blacklist", response_model=list[IPListResponse])
async def get_blacklist(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_database)
):
    ips = db.query(IPList).filter(
        IPList.list_type == IPListType.BLACKLIST
    ).offset(skip).limit(limit).all()
    
    return ips


@router.delete("/whitelist/{ip_address}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_from_whitelist(
    ip_address: str,
    db: Session = Depends(get_database)
):
    ip_entry = db.query(IPList).filter(
        IPList.ip_address == ip_address,
        IPList.list_type == IPListType.WHITELIST
    ).first()
    
    if not ip_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IP not found in whitelist"
        )
    
    db.delete(ip_entry)
    db.commit()
    
    return None


@router.delete("/blacklist/{ip_address}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_from_blacklist(
    ip_address: str,
    db: Session = Depends(get_database)
):
    ip_entry = db.query(IPList).filter(
        IPList.ip_address == ip_address,
        IPList.list_type == IPListType.BLACKLIST
    ).first()
    
    if not ip_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IP not found in blacklist"
        )
    
    db.delete(ip_entry)
    db.commit()
    
    return None

