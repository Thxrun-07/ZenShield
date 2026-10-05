"""Middleware stack for ZenShield.

Ordered execution stack:
1. Request ID injection (X-Request-ID header & request.state)
2. Route-aware body size limit (64 KB JSON, 10 MB uploads, enforced on actual bytes read)
3. Audit logging (duration, status, method, path, zero payload leakage)
"""

import logging
import time
import uuid

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from zenshield.core.config import settings

logger = logging.getLogger("zenshield.audit")


class RequestIdAndAuditMiddleware:
    """Pure ASGI middleware for Request ID tracing and zero-leakage audit logging."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. Extract or generate Request ID
        headers = dict(scope.get("headers", []))
        req_id_header = headers.get(b"x-request-id")
        request_id = req_id_header.decode("latin1") if req_id_header else str(uuid.uuid4())

        # Store in state
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["request_id"] = request_id

        start_time = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
                # Ensure X-Request-ID header is present in response
                response_headers = list(message.get("headers", []))
                has_req_id = any(h[0].lower() == b"x-request-id" for h in response_headers)
                if not has_req_id:
                    response_headers.append((b"x-request-id", request_id.encode("latin1")))
                    message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.info(
                "Request processed: method=%s, path=%s, status=%d, duration_ms=%.2f",
                scope.get("method"),
                scope.get("path"),
                status_code,
                duration_ms,
                extra={"req_id": request_id},
            )


class BodySizeLimitMiddleware:
    """
    Pure ASGI middleware enforcing body size limits per route type.

    Protects against DoS:
    - Checks Content-Length header up front
    - Intercepts streamed / chunked body chunks as they are received
    - Limits: 10 MB for upload routes (/qr/scan, /ocr/analyze, multipart), 64 KB for JSON
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        headers = dict(scope.get("headers", []))
        content_type = headers.get(b"content-type", b"").decode("latin1").lower()
        content_length_header = headers.get(b"content-length")

        # Determine limit based on endpoint and content type
        is_upload = path.startswith(("/api/v1/qr/scan", "/api/v1/ocr/analyze")) or content_type.startswith(
            "multipart/form-data"
        )
        max_bytes = settings.MAX_UPLOAD_SIZE_BYTES if is_upload else settings.MAX_REQUEST_BODY_BYTES
        limit_desc = "10 MB" if is_upload else f"{max_bytes} bytes"

        # 1. Check Content-Length header upfront
        if content_length_header:
            try:
                cl = int(content_length_header.decode("latin1"))
                if cl > max_bytes:
                    await self._send_413(scope, send, limit_desc)
                    return
            except ValueError:
                pass

        # 2. Intercept streaming / chunked chunks
        bytes_received = 0

        async def receive_with_limit() -> Message:
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                bytes_received += len(body)
                if bytes_received > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Request body exceeds maximum allowed size ({limit_desc}).",
                    )
            return message

        try:
            await self.app(scope, receive_with_limit, send)
        except BodyTooLargeException as exc:
            await self._send_413(scope, send, str(exc))

    async def _send_413(self, scope: Scope, send: Send, limit_desc: str) -> None:
        req_id = scope.get("state", {}).get("request_id", str(uuid.uuid4()))
        message = (
            f"File size exceeds maximum allowed limit of {limit_desc}."
            if "MB" in limit_desc
            else f"Request body exceeds maximum allowed size ({limit_desc})."
        )

        # Build unified 413 response
        import json

        payload = {
            "error": {
                "code": "PAYLOAD_TOO_LARGE",
                "message": message,
            },
            "detail": message,
            "request_id": req_id,
        }
        body_bytes = json.dumps(payload).encode("utf-8")

        await send(
            {
                "type": "http.response.start",
                "status": status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body_bytes)).encode("latin1")),
                    (b"x-request-id", req_id.encode("latin1")),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body_bytes,
            }
        )


class BodyTooLargeException(Exception):
    pass


def setup_middlewares(app: FastAPI) -> None:
    """Configures the unified middleware stack on FastAPI in correct order."""
    # Innermost: Audit & Request ID
    app.add_middleware(RequestIdAndAuditMiddleware)

    # Body Size Limit (evaluates after CORS / Request ID)
    app.add_middleware(BodySizeLimitMiddleware)

    # CORS Middleware: validate no wildcard origins if allow_credentials=True
    cors_origins = [o.strip() for o in settings.ALLOWED_ORIGINS if o.strip()]
    has_wildcard = "*" in cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=not has_wildcard,  # Secure: False if wildcard
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
