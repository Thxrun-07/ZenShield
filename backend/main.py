"""Main application entry point for Zenshield.

Sets up:
- FastAPI app with zero-leakage security posture
- Middleware for request ID tracking, body-size enforcement, and structured audit logs
- Custom RequestValidationError handler that scrubs raw input from 422 responses
"""

import logging
import time
import uuid
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.api.routes import close_shared_http_client, router
from backend.config import settings

# Configure safe structured logger (no message body or PII in format)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [req_id=%(name)s] %(message)s",
)
logger = logging.getLogger("zenshield.audit")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info("Zenshield Message Verification Engine initialized.")
    yield
    await close_shared_http_client()
    logger.info("Zenshield Message Verification Engine shut down.")


app = FastAPI(
    title="Zenshield Message Verification API",
    description="Privacy-preserving, multilingual SMS and message phishing verification engine.",
    version="2.0.0",
    lifespan=lifespan,
)

# Include API routes
app.include_router(router)


@app.middleware("http")
async def security_and_audit_middleware(
    request: Request,
    call_next: Callable[[Request], Any],
) -> Response:
    """Enforce body-size limits and inject request IDs without logging payloads."""
    # 1. Enforce body size limit before consuming request stream
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "error": {
                    "code": "PAYLOAD_TOO_LARGE",
                    "message": f"Request body exceeds maximum allowed size ({settings.MAX_REQUEST_BODY_BYTES} bytes).",
                }
            },
        )

    # 2. Extract or generate Request ID
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    start_time = time.perf_counter()

    # 3. Process Request
    try:
        response: Response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        logger.error(
            "Unhandled exception: status=500, duration_ms=%.2f, path=%s",
            duration_ms,
            request.url.path,
            extra={"req_id": request_id},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected error occurred during message verification.",
                }
            },
        )

    duration_ms = (time.perf_counter() - start_time) * 1000.0
    response.headers["X-Request-ID"] = request_id

    # Safe log: records only metadata, never query or body
    logger.info(
        "Request processed: method=%s, path=%s, status=%d, duration_ms=%.2f",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
        extra={"req_id": request_id},
    )

    return response


@app.exception_handler(RequestValidationError)
async def custom_validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Sanitize validation errors: never echo user input or raw payloads in 422 responses."""
    sanitized_errors = []
    for err in exc.errors():
        field_name = str(err["loc"][-1]) if err.get("loc") else "unknown"
        sanitized_errors.append(
            {
                "field": field_name,
                "code": err.get("type", "invalid_value"),
            }
        )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "INVALID_REQUEST",
                "message": "One or more request parameters failed validation.",
                "details": sanitized_errors,
            }
        },
    )


@app.exception_handler(ValueError)
async def custom_value_error_handler(
    request: Request,
    exc: ValueError,
) -> JSONResponse:
    """Handle custom value and sanitization errors safely."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": {
                "code": "BAD_REQUEST",
                "message": str(exc),
            }
        },
    )


@app.get("/health", tags=["system"])
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "zenshield"}
