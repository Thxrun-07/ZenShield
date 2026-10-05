"""Security utilities, input validation, and rate limiting for ZenShield."""

import os
import time
from collections import defaultdict
from threading import Lock

from fastapi import Request

from zenshield.core.config import settings
from zenshield.core.errors import RateLimitExceededError, SecurityValidationError

ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}


def is_valid_image_header(header_bytes: bytes) -> bool:
    """Validates magic bytes of image file buffer (PNG, JPEG, WebP) to prevent MIME spoofing."""
    if len(header_bytes) < 12:
        return False
    # PNG: \x89PNG\r\n\x1a\n
    if header_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    # JPEG: \xff\xd8\xff
    if header_bytes.startswith(b"\xff\xd8\xff"):
        return True
    # WebP: RIFF....WEBP
    return bool(header_bytes.startswith(b"RIFF") and header_bytes[8:12] == b"WEBP")


def sanitize_filename(filename: str | None) -> str:
    """Sanitizes uploaded filename against path traversal attacks."""
    if not filename:
        raise SecurityValidationError("Uploaded file must have a valid filename.")
    clean = os.path.basename(filename).strip()
    if not clean or clean in (".", ".."):
        raise SecurityValidationError("Uploaded filename is invalid.")
    return clean


def validate_image_dimensions(width: int, height: int) -> None:
    """Validates image pixel dimensions to prevent decompression bomb DoS attacks."""
    max_dim = settings.MAX_IMAGE_DIMENSION
    if width > max_dim or height > max_dim:
        raise SecurityValidationError(
            f"Image dimensions ({width}x{height}) exceed maximum allowed limit of {max_dim}x{max_dim}."
        )


class InMemoryRateLimiter:
    """Thread-safe in-memory sliding window rate limiter."""

    def __init__(self, requests_per_minute: int = 120):
        self.rpm = requests_per_minute
        self.window_seconds = 60.0
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check_rate_limit(self, client_key: str) -> None:
        """Raises RateLimitExceededError if client exceeded requests per minute."""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._requests[client_key]
            # Prune old timestamps
            self._requests[client_key] = [t for t in timestamps if t > cutoff]
            if len(self._requests[client_key]) >= self.rpm:
                raise RateLimitExceededError()
            self._requests[client_key].append(now)


# Global rate limiter instance
rate_limiter = InMemoryRateLimiter(requests_per_minute=240)


def rate_limit_dependency(request: Request) -> None:
    """FastAPI dependency for rate limiting sensitive endpoints."""
    # Identify client by IP or forwarded IP
    forwarded = request.headers.get("x-forwarded-for")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    rate_limiter.check_rate_limit(client_ip)
