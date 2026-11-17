from fastapi import FastAPI
from sqlalchemy import text

from app.db.session import AsyncSessionLocal


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


@app.get("/health/database")
async def database_health_check() -> dict[str, str]:
    async with AsyncSessionLocal() as session:
        await session.execute(text("SELECT 1"))

    return {
        "status": "healthy",
        "database": "connected",
    }