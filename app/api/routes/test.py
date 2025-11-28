from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/test", tags=["test"])


@router.get("")
async def test_endpoint():
    return JSONResponse(
        content={
            "status": "ok",
            "message": "Test endpoint accessible",
            "timestamp": "2024-01-01T00:00:00Z"
        },
        status_code=200
    )

