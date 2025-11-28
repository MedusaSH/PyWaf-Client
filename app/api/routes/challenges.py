from fastapi import APIRouter, Depends, Body, HTTPException
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

