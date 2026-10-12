from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.api.identifiers import router as identifiers_router


app = FastAPI(
    title="Digital Footprint Exposure Scanner",
    version="0.1.0",
    description="Privacy-first digital exposure assessment and cleanup assistant.",
)


app.include_router(auth_router)
app.include_router(identifiers_router)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "digital-footprint-scanner",
        "version": "0.1.0",
    }
