from fastapi import FastAPI


app = FastAPI(
    title="ScamShield API",
    description="AI-powered digital scam detection and risk analysis platform.",
    version="0.1.0",
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "scamshield-api",
        "version": "0.1.0",
    }