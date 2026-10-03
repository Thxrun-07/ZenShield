import os
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from starlette.middleware.base import BaseHTTPMiddleware

# Configure application logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("redflag.backend")

# Load environment variables from .env file
load_dotenv()

# Import API routers
from api import verify, qr, ocr, report, campaign


class LimitRequestSizeMiddleware(BaseHTTPMiddleware):
    """
    Middleware enforcing a maximum HTTP request body size limit (default 10 MB)
    to protect against Denial of Service (DoS) oversized request payloads.
    """
    def __init__(self, app, max_upload_size: int = 10 * 1024 * 1024):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > self.max_upload_size:
                        return JSONResponse(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            content={"detail": "File size exceeds maximum allowed limit of 10 MB."}
                        )
                except ValueError:
                    pass
        return await call_next(request)


# Initialize FastAPI application
app = FastAPI(
    title="RedFlag - Cyber-Fraud & Phishing Alert Platform",
    description="Backend foundation and integration layer for RedFlag. Handles verification routing, QR processing, OCR, request validation, and service adapters.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Register Request Size Limit Middleware
app.add_middleware(LimitRequestSizeMiddleware, max_upload_size=10 * 1024 * 1024)

# Configure Environment-Based CORS Middleware
raw_allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000")
allowed_origins = [origin.strip() for origin in raw_allowed_origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Global Exception Handler for Uncaught Server Errors
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catches all unhandled server exceptions.
    Logs detailed stack traces internally on server side while returning clean,
    sanitized generic JSON responses to clients (preventing stack trace / credential leaks).
    """
    logger.error(
        f"Unhandled exception during {request.method} {request.url.path}: {exc}",
        exc_info=True
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred while processing your request."}
    )


# Custom Exception Handler for Validation Errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Standardized handler for request validation failures (422).
    Uses jsonable_encoder to ensure complex exception context objects serialize cleanly.
    """
    logger.warning(f"Request validation failure on {request.method} {request.url.path}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Invalid request parameters or payload format.",
            "errors": jsonable_encoder(exc.errors())
        }
    )


# Register API Routers under /api/v1 prefix
app.include_router(verify.router, prefix="/api/v1")
app.include_router(qr.router, prefix="/api/v1")
app.include_router(ocr.router, prefix="/api/v1")
app.include_router(report.router, prefix="/api/v1")
app.include_router(campaign.router, prefix="/api/v1")


@app.get("/", summary="Root Endpoint")
async def root():
    """
    Root endpoint returning service metadata and operational status.
    """
    return {
        "service": "RedFlag Backend API",
        "status": "online",
        "version": "1.0.0",
        "documentation": "/docs"
    }


@app.get("/health", summary="Health Check Endpoint")
async def health_check():
    """
    Health check endpoint for service monitoring and deployment probes.
    """
    return {
        "status": "healthy"
    }


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=True)
