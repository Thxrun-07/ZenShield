"""Unified error handling and domain exceptions for ZenShield.

Provides:
- One consistent error response envelope across all API endpoints:
  {
      "error": {
          "code": "ERROR_CODE",
          "message": "Human readable message",
          "details": [...]
      },
      "detail": "Human readable message",
      "request_id": "uuid"
  }
- Domain-specific exceptions that avoid swallowing errors via generic ValueError
- Sanitized validation handlers that NEVER echo user input / canary tokens in 422 responses
- Zero stack-trace / credential leakage on unhandled 500 exceptions
"""

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger("zenshield.audit")


class ZenShieldError(Exception):
    """Base domain exception for ZenShield."""

    def __init__(self, message: str, code: str = "ZENSHIELD_ERROR", status_code: int = 400, details: Any = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details


class InvalidRequestError(ZenShieldError):
    def __init__(self, message: str, details: Any = None):
        super().__init__(message, code="INVALID_REQUEST", status_code=status.HTTP_400_BAD_REQUEST, details=details)


class PayloadTooLargeError(ZenShieldError):
    def __init__(self, message: str = "Request body exceeds maximum allowed limit."):
        super().__init__(message, code="PAYLOAD_TOO_LARGE", status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)


class NotFoundError(ZenShieldError):
    def __init__(self, message: str = "Requested resource not found."):
        super().__init__(message, code="NOT_FOUND", status_code=status.HTTP_404_NOT_FOUND)


class RateLimitExceededError(ZenShieldError):
    def __init__(self, message: str = "Rate limit exceeded. Please retry later."):
        super().__init__(message, code="RATE_LIMIT_EXCEEDED", status_code=status.HTTP_429_TOO_MANY_REQUESTS)


class EngineUnavailableError(ZenShieldError):
    def __init__(self, message: str = "Detection engine is temporarily unavailable."):
        super().__init__(message, code="ENGINE_UNAVAILABLE", status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


class SecurityValidationError(ZenShieldError):
    def __init__(self, message: str):
        super().__init__(message, code="SECURITY_VALIDATION_FAILED", status_code=status.HTTP_400_BAD_REQUEST)


def create_error_response(
    status_code: int,
    code: str,
    message: str,
    details: Any = None,
    request_id: str | None = None,
) -> JSONResponse:
    """Builds the standardized error response envelope."""
    error_obj: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if details is not None:
        error_obj["details"] = details

    content: dict[str, Any] = {
        "error": error_obj,
        "detail": message,  # Backward compatibility for legacy clients/tests
    }
    if request_id:
        content["request_id"] = request_id

    headers = {}
    if request_id:
        headers["X-Request-ID"] = request_id

    return JSONResponse(
        status_code=status_code,
        content=content,
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Registers all global exception handlers on the FastAPI app."""

    @app.exception_handler(ZenShieldError)
    async def zenshield_exception_handler(request: Request, exc: ZenShieldError) -> JSONResponse:
        req_id = getattr(request.state, "request_id", None)
        return create_error_response(
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            details=exc.details,
            request_id=req_id,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Sanitizes validation errors: NEVER echoes user input, body, or canary tokens."""
        req_id = getattr(request.state, "request_id", None)
        sanitized_errors = []
        for err in exc.errors():
            field_name = str(err["loc"][-1]) if err.get("loc") else "unknown"
            sanitized_errors.append(
                {
                    "field": field_name,
                    "code": err.get("type", "invalid_value"),
                }
            )

        logger.warning(
            "Request validation failed: path=%s",
            request.url.path,
            extra={"req_id": req_id or "unknown"},
        )

        return create_error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code="INVALID_REQUEST",
            message="One or more request parameters failed validation.",
            details=sanitized_errors,
            request_id=req_id,
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        req_id = getattr(request.state, "request_id", None)
        code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            413: "PAYLOAD_TOO_LARGE",
            422: "UNPROCESSABLE_ENTITY",
            429: "RATE_LIMITED",
            500: "INTERNAL_SERVER_ERROR",
            501: "NOT_IMPLEMENTED",
            503: "SERVICE_UNAVAILABLE",
        }
        error_code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")
        message = str(exc.detail) if exc.detail else "An HTTP error occurred."
        return create_error_response(
            status_code=exc.status_code,
            code=error_code,
            message=message,
            request_id=req_id,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catches unhandled exceptions without leaking stack trace or secrets."""
        req_id = getattr(request.state, "request_id", None)
        logger.error(
            "Unhandled exception during %s %s: %s",
            request.method,
            request.url.path,
            exc,
            exc_info=True,
            extra={"req_id": req_id or "unknown"},
        )
        return create_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="INTERNAL_SERVER_ERROR",
            message="An internal server error occurred while processing your request.",
            request_id=req_id,
        )
