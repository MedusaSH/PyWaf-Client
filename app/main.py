from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.api.middleware import WAFMiddleware
from app.api.routes import security, ip_list, metrics, rules, logs, reports, reputation, tls_fingerprint, challenges, test
from app.core.database import engine, Base
from app.core.logger import logger
from app.config import settings

try:
    if engine and hasattr(engine, 'url') and engine.url.drivername != 'sqlite':
        try:
            Base.metadata.create_all(bind=engine)
        except Exception as db_error:
            logger.warning("database_init_failed", error=str(db_error))
except Exception as e:
    logger.warning("database_init_error", error=str(e))

app = FastAPI(
    title="WAF API",
    description="Web Application Firewall API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(WAFMiddleware)

app.include_router(security.router)
app.include_router(ip_list.router)
app.include_router(metrics.router)
app.include_router(rules.router)
app.include_router(logs.router)
app.include_router(reports.router)
app.include_router(reputation.router)
app.include_router(tls_fingerprint.router)
app.include_router(challenges.router)
app.include_router(test.router)


@app.get("/")
async def root():
    return {"status": "ok", "service": "WAF"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.on_event("startup")
async def startup_event():
    logger.info("waf_startup", environment=settings.environment)


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("waf_shutdown")

