from fastapi import FastAPI


app = FastAPI(
    title="Digital Footprint Exposure Scanner",
    version="0.1.0",
    description="Privacy-first digital exposure assessment and cleanup assistant.",
)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "digital-footprint-scanner",
        "version": "0.1.0",
    }
