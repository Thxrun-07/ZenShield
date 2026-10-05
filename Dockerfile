# ==============================================================================
# ZenShield Unified Backend Production Dockerfile
# Python 3.11 with OpenCV & Tesseract OCR dependencies
# ==============================================================================

FROM python:3.11-slim as base

# Set environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system dependencies for OpenCV and Tesseract-OCR
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libgl1 \
    libglib2.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    mkdir -p /app/data /app/logs && \
    chown -R appuser:appuser /app

# Install Python dependencies
COPY pyproject.toml /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy application source code and configurations
COPY --chown=appuser:appuser src /app/src
COPY --chown=appuser:appuser .env.example /app/.env.example

# Switch to non-root user
USER appuser

# Expose standard FastAPI application port
EXPOSE 8000

# Healthcheck checking internal endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production server entrypoint
CMD ["uvicorn", "zenshield.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--access-log"]
