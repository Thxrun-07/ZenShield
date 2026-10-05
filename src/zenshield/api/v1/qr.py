"""QR code verification endpoint: POST /api/v1/qr/scan."""

import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from zenshield.adapters.url_adapter import URLAdapter
from zenshield.api.v1.verify import get_url_adapter
from zenshield.core.config import settings
from zenshield.core.security import (
    is_valid_image_header,
    rate_limit_dependency,
    sanitize_filename,
)
from zenshield.schemas.verification import QRScanResponse
from zenshield.services.qr_service import QRService

logger = logging.getLogger("zenshield.audit")

router = APIRouter(prefix="/qr", tags=["QR Scanning"])

ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}


def get_qr_service(url_adapter: URLAdapter = Depends(get_url_adapter)) -> QRService:
    return QRService(url_adapter=url_adapter)


@router.post(
    "/scan",
    response_model=QRScanResponse,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Scan QR Code from Uploaded Image",
    description="Decodes QR payload locally using OpenCV and passes URLs to URLAdapter without network visits.",
)
async def scan_qr_code(
    file: UploadFile = File(...),
    qr_service: QRService = Depends(get_qr_service),
) -> QRScanResponse:
    # 1. Path traversal protection on filename
    try:
        sanitize_filename(file.filename)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    # 2. MIME type check
    if file.content_type:
        content_type_clean = file.content_type.lower()
        if content_type_clean not in ALLOWED_IMAGE_TYPES and not content_type_clean.startswith("image/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type '{file.content_type}'. Must be a valid image (PNG, JPEG, JPG, WebP).",
            )

    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty.",
            )

        if len(contents) > settings.MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File size exceeds maximum allowed limit of 10 MB.",
            )

        # 3. Magic bytes check
        if not is_valid_image_header(contents[:12]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid image format or header signature. File provided is not a valid PNG, JPEG, or WebP image.",
            )

        scan_result = qr_service.scan_qr_image(contents)
        return QRScanResponse(**scan_result)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except HTTPException:
        raise
    except Exception as e:
        logger.error("QR processing error: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing the QR code.",
        ) from e
