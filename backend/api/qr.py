import os
import logging
from fastapi import APIRouter, File, UploadFile, HTTPException, status, Depends
from schemas.verification import QRScanResponse
from services.qr_service import QRService
from services.url_adapter import URLAdapter
from api.verify import get_url_adapter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/qr", tags=["QR Scanning"])

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


def get_qr_service(url_adapter: URLAdapter = Depends(get_url_adapter)) -> QRService:
    """Dependency provider for QRService."""
    return QRService(url_adapter=url_adapter)


@router.post(
    "/scan",
    response_model=QRScanResponse,
    summary="Scan QR Code from Uploaded Image",
    description=(
        "Decodes QR payload locally using OpenCV. "
        "If payload is a URL, passes it to URLAdapter without visiting or fetching the URL."
    )
)
async def scan_qr_code(
    file: UploadFile = File(...),
    qr_service: QRService = Depends(get_qr_service)
):
    """
    POST /api/v1/qr/scan

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

        scan_result = qr_service.scan_qr_image(contents)
        return QRScanResponse(**scan_result)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during QR code scanning: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred during QR code scanning."
        )
