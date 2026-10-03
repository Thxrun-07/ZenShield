"""ZenShield FastAPI application entry point.

Collaborative cybersecurity platform for detecting malicious URLs, phishing,
and impersonation campaigns.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from zenshield.api.v1.router import api_v1_router
from zenshield.config import settings
from zenshield.services.reputation.local_sqlite import SQLiteReputationProvider


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure local SQLite database and seed IOCs are ready
    reputation_repo = SQLiteReputationProvider()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Community-focused cybersecurity platform: URL Detection & Centralized Risk Engine",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check
@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


# Include API v1 router (/api/v1)
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("zenshield.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
