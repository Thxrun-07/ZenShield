"""Main FastAPI application entry point for ZenShield."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import text

from zenshield.api.v1.router import api_v1_router
from zenshield.core.config import PROJECT_ROOT, settings
from zenshield.core.errors import register_exception_handlers
from zenshield.core.logging import audit_logger, setup_logging
from zenshield.core.middleware import setup_middlewares
from zenshield.db.database import SessionLocal, init_db

# Shared global HTTP client for outbound requests
shared_http_client: httpx.AsyncClient | None = None


def get_shared_http_client() -> httpx.AsyncClient:
    global shared_http_client
    if shared_http_client is None or shared_http_client.is_closed:
        shared_http_client = httpx.AsyncClient(timeout=10.0)
    return shared_http_client


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Single application lifespan managing database initialization and shared HTTP client."""
    audit_logger.info("Starting ZenShield backend %s...", settings.APP_VERSION)
    # 1. Initialize unified DB tables and default seed data
    init_db()

    # 2. Initialize shared HTTP client
    global shared_http_client
    shared_http_client = httpx.AsyncClient(timeout=10.0)
    app.state.http_client = shared_http_client

    audit_logger.info("ZenShield backend initialized successfully.")
    yield

    # 3. Shutdown cleanup
    if shared_http_client and not shared_http_client.is_closed:
        await shared_http_client.aclose()
    audit_logger.info("ZenShield backend shut down cleanly.")


def create_app() -> FastAPI:
    """Application factory for ZenShield."""
    setup_logging()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Unified Cyber-Fraud, Threat Intelligence, and Verification Platform",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Configure middleware stack
    setup_middlewares(app)

    # Configure error handling
    register_exception_handlers(app)

    # System Root & Health check
    @app.get("/", tags=["system"])
    async def root_endpoint(request: Request) -> Any:
        """Root status endpoint. Returns interactive UI for browser requests, JSON for API clients."""
        accept = request.headers.get("accept", "")
        if "text/html" in accept and not (accept.startswith("application/json") or accept == "*/*"):
            frontend_path = PROJECT_ROOT / "frontend" / "index.html"
            if frontend_path.exists():
                return HTMLResponse(content=frontend_path.read_text(encoding="utf-8"))
        return {
            "service": f"{settings.APP_NAME} Backend API",
            "status": "online",
            "ui": "/ui",
            "documentation": "/docs",
            "version": settings.APP_VERSION,
        }

    @app.get("/ui", response_class=HTMLResponse, tags=["system"], include_in_schema=False)
    async def serve_ui() -> HTMLResponse:
        """Serve ZenShield interactive frontend."""
        frontend_path = PROJECT_ROOT / "frontend" / "index.html"
        if frontend_path.exists():
            return HTMLResponse(content=frontend_path.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>ZenShield Frontend Not Found</h1>", status_code=404)

    @app.get("/health", tags=["system"])
    async def health_check() -> dict:
        """Health check endpoint reporting overall system, DB, and engine readiness."""
        db_status = "healthy"
        try:
            with SessionLocal() as session:
                session.execute(text("SELECT 1"))
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"

        return {
            "status": "healthy" if "unhealthy" not in db_status else "degraded",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "database": db_status,
            "engines": {
                "url": "ready",
                "message": "ready",
                "intelligence": "ready",
            },
        }

    # Mount API v1 router
    app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("zenshield.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
