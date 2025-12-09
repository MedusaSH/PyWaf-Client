from fastapi import APIRouter, Depends, Body, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.api.dependencies import get_database
from app.security.challenge_system import ChallengeSystem
from app.core.logger import logger

router = APIRouter(prefix="/api/challenges", tags=["challenges"])


class PoWVerification(BaseModel):
    token: str
    nonce: str
    ip_address: str


class TarpitVerification(BaseModel):
    token: str
    solution: str
    solve_time: float


class EncryptedCookieVerification(BaseModel):
    token: str
    encrypted_data: str


@router.post("/verify-pow")
async def verify_proof_of_work(
    verification: PoWVerification,
    db: Session = Depends(get_database)
):
    try:
        challenge_system = ChallengeSystem()
        
        verified = challenge_system.verify_proof_of_work(
            verification.ip_address,
            verification.token,
            verification.nonce
        )
        
        if verified:
            challenge_key = f"challenge:pow:{verification.ip_address}:{verification.token}"
            challenge_system.redis.delete(challenge_key)
            
            return {
                "verified": True,
                "message": "Proof of work verified"
            }
        else:
            return {
                "verified": False,
                "message": "Invalid proof of work"
            }
            
    except Exception as e:
        logger.error("pow_verification_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error verifying proof of work")


@router.post("/verify-cookie")
async def verify_cookie_challenge(
    token: str = Body(...),
    ip_address: str = Body(...),
    db: Session = Depends(get_database)
):
    try:
        challenge_system = ChallengeSystem()
        
        verified = challenge_system.verify_cookie_challenge(
            ip_address,
            token
        )
        
        if verified:
            challenge_key = f"challenge:cookie:{ip_address}:{token}"
            challenge_system.redis.delete(challenge_key)
            
            return {
                "verified": True,
                "message": "Cookie challenge verified"
            }
        else:
            challenge_system.track_challenge_bypass(ip_address, "cookie")
            return {
                "verified": False,
                "message": "Invalid cookie challenge"
            }
            
    except Exception as e:
        logger.error("cookie_verification_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error verifying cookie challenge")


@router.post("/verify-tarpit")
async def verify_javascript_tarpit(
    verification: TarpitVerification,
    request: Request,
    db: Session = Depends(get_database)
):
    try:
        challenge_system = ChallengeSystem()
        
        ip_address = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ip_address = forwarded.split(",")[0].strip()
        
        verified = challenge_system.verify_javascript_tarpit(
            ip_address,
            verification.token,
            verification.solution,
            verification.solve_time
        )
        
        if verified:
            return {
                "verified": True,
                "message": "JavaScript tarpit challenge verified"
            }
        else:
            challenge_system.track_challenge_bypass(ip_address, "tarpit")
            return {
                "verified": False,
                "message": "Invalid tarpit challenge solution"
            }
            
    except Exception as e:
        logger.error("tarpit_verification_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error verifying tarpit challenge")


@router.post("/verify-encrypted-cookie")
async def verify_encrypted_cookie_challenge(
    verification: EncryptedCookieVerification,
    request: Request,
    db: Session = Depends(get_database)
):
    try:
        challenge_system = ChallengeSystem()
        
        ip_address = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ip_address = forwarded.split(",")[0].strip()
        
        verified = challenge_system.verify_encrypted_cookie_challenge(
            ip_address,
            verification.token,
            verification.encrypted_data
        )
        
        if verified:
            return {
                "verified": True,
                "message": "Encrypted cookie challenge verified"
            }
        else:
            challenge_system.track_challenge_bypass(ip_address, "encrypted_cookie")
            return {
                "verified": False,
                "message": "Invalid encrypted cookie challenge"
            }
            
    except Exception as e:
        logger.error("encrypted_cookie_verification_error", error=str(e))
        raise HTTPException(status_code=500, detail="Error verifying encrypted cookie challenge")

