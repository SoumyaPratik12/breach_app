from fastapi import FastAPI

from app.config.settings import settings


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "environment": settings.environment,
    }
