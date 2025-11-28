from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional
from app.api.dependencies import get_database
from app.models.rule import Rule
from app.schemas.rule import RuleCreate, RuleResponse

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule_data: RuleCreate,
    db: Session = Depends(get_database)
):
    existing = db.query(Rule).filter(Rule.name == rule_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rule with this name already exists"
        )
    
    rule = Rule(**rule_data.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    
    return rule


@router.get("", response_model=list[RuleResponse])
async def get_rules(
    skip: int = 0,
    limit: int = 100,
    enabled: Optional[bool] = None,
    threat_type: Optional[str] = None,
    db: Session = Depends(get_database)
):
    query = db.query(Rule)
    
    if enabled is not None:
        query = query.filter(Rule.enabled == enabled)
    
    if threat_type:
        query = query.filter(Rule.threat_type == threat_type)
    
    rules = query.offset(skip).limit(limit).all()
    
    return rules


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: int,
    db: Session = Depends(get_database)
):
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: int,
    rule_data: RuleCreate,
    db: Session = Depends(get_database)
):
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    for key, value in rule_data.model_dump().items():
        setattr(rule, key, value)
    
    db.commit()
    db.refresh(rule)
    
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int,
    db: Session = Depends(get_database)
):
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    db.delete(rule)
    db.commit()
    
    return None

