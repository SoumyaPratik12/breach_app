from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.api.identifiers import router as identifiers_router
from app.api.scans import router as scans_router
from app.db.init_db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Creates missing tables without deleting existing data.
    init_db()
    yield


app = FastAPI(
    title="Digital Footprint Exposure Scanner",
    version="0.1.0",
    description="Privacy-first digital exposure assessment and cleanup assistant.",
    lifespan=lifespan,
)


app.include_router(auth_router)
app.include_router(identifiers_router)
app.include_router(scans_router)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "digital-footprint-scanner",
        "version": "0.1.0",
    }
