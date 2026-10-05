"""OCR text verification endpoint: POST /api/v1/ocr/analyze."""

import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from zenshield.adapters.message_adapter import MessageAdapter
from zenshield.api.v1.verify import get_message_adapter
from zenshield.core.config import settings
from zenshield.core.security import (
    is_valid_image_header,
    rate_limit_dependency,
    sanitize_filename,
)
from zenshield.schemas.verification import OCRAnalyzeResponse
from zenshield.services.ocr_service import OCRService

logger = logging.getLogger("zenshield.audit")

router = APIRouter(prefix="/ocr", tags=["OCR Processing"])

ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}


def get_ocr_service(message_adapter: MessageAdapter = Depends(get_message_adapter)) -> OCRService:
    return OCRService(message_adapter=message_adapter)


@router.post(
    "/analyze",
    response_model=OCRAnalyzeResponse,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Perform OCR on Image and Forward Extracted Text to Message Detection Engine",
    description=(
        "Extracts text from screenshots using local OpenCV preprocessing and Tesseract OCR, "
        "then forwards extracted text to MessageAdapter."
    ),
)
async def analyze_ocr_image(
    file: UploadFile = File(...),
    ocr_service: OCRService = Depends(get_ocr_service),
) -> OCRAnalyzeResponse:
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

        result = ocr_service.analyze_ocr_image(contents)
        return OCRAnalyzeResponse(**result)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except RuntimeError as e:
        logger.error("OCR configuration error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        ) from e
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Unexpected error during OCR processing: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred during OCR image processing.",
        ) from e
