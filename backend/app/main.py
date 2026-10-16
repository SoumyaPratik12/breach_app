from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.api.identifiers import router as identifiers_router
from app.api.password_exposure import router as password_exposure_router
from app.api.scans import router as scans_router
from app.db.database import SessionLocal
from app.db.init_db import init_db
from app.services.scan_recovery import recover_stale_scans

STALE_SCAN_TIMEOUT_MINUTES = 15


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create missing tables without deleting existing data.
    init_db()
    # Recover scans left running by a previous interruption.
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(
            minutes=STALE_SCAN_TIMEOUT_MINUTES
        )
        recover_stale_scans(db, cutoff)
    finally:
        db.close()
    yield


app = FastAPI(
    title="Digital Footprint Exposure Scanner",
    version="0.1.0",
    description="Privacy-first digital exposure assessment and cleanup assistant.",
    lifespan=lifespan,
)


app.include_router(auth_router)
app.include_router(identifiers_router)
app.include_router(password_exposure_router)
app.include_router(scans_router)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "digital-footprint-scanner",
        "version": "0.1.0",
    }
