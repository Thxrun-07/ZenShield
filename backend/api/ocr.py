import os
import logging
from fastapi import APIRouter, File, UploadFile, HTTPException, status, Depends
from schemas.verification import OCRAnalyzeResponse
from services.ocr_service import OCRService
from services.message_adapter import MessageAdapter
from api.verify import get_message_adapter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ocr", tags=["OCR Processing"])

# Maximum allowed file upload size: 10 MB
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}


def is_valid_image_header(header_bytes: bytes) -> bool:
    """
    Validates magic bytes of image file buffer (PNG, JPEG, WebP) to prevent content-type spoofing.
    """
    if len(header_bytes) < 12:
        return False
    if header_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if header_bytes.startswith(b"\xff\xd8\xff"):
        return True
    if header_bytes.startswith(b"RIFF") and header_bytes[8:12] == b"WEBP":
        return True
    return False


def get_ocr_service(message_adapter: MessageAdapter = Depends(get_message_adapter)) -> OCRService:
    """Dependency provider for OCRService."""
    return OCRService(message_adapter=message_adapter)


@router.post(
    "/analyze",
    response_model=OCRAnalyzeResponse,
    summary="Perform OCR on Image and Forward Extracted Text to Message Detection Engine",
    description=(
        "Extracts text from screenshots using local OpenCV preprocessing and Tesseract OCR, "
        "then forwards extracted text to MessageAdapter."
    )
)
async def analyze_ocr_image(
    file: UploadFile = File(...),
    ocr_service: OCRService = Depends(get_ocr_service)
):
    """
    POST /api/v1/ocr/analyze

    Security Hardening:
    - Path traversal protection on filename.
    - Size limit validation (10 MB).
    - MIME type & Magic bytes validation.
    - Safe in-memory OpenCV decoding.
    """
    filename_clean = os.path.basename(file.filename) if file.filename else ""
    if not filename_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a valid filename."
        )

    if file.content_type:
        content_type_clean = file.content_type.lower()
        if content_type_clean not in ALLOWED_IMAGE_TYPES and not content_type_clean.startswith("image/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type '{file.content_type}'. Must be a valid image (PNG, JPEG, JPG, WebP)."
            )

    try:
        contents = await file.read()

        if not contents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty."
            )

        if len(contents) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File size exceeds maximum allowed limit of 10 MB."
            )

        # Deep magic byte check for image header signature
        if not is_valid_image_header(contents[:12]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid image format or header signature. File provided is not a valid PNG, JPEG, or WebP image."
            )

        result = ocr_service.analyze_ocr_image(contents)
        return OCRAnalyzeResponse(**result)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except RuntimeError as e:
        logger.error(f"OCR Configuration Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during OCR processing: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred during OCR image processing."
        )
