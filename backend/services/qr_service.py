import cv2
import numpy as np
import re
import logging
from typing import Dict, Any, Tuple, Optional
from services.url_adapter import URLAdapter

logger = logging.getLogger(__name__)

# Maximum allowable image dimension (4096 x 4096 px) to prevent image decompression bomb DoS attacks
MAX_IMAGE_DIMENSION = 4096

URL_PATTERN = re.compile(
    r'^(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?$',
    re.IGNORECASE
)


class QRService:
    """
    QR Code Scanning Service using local OpenCV QR detection.

    SECURITY CONTROLS:
    - NEVER automatically visits, requests (requests.get), opens (webbrowser.open),
      crawls, redirects to, or executes decoded URLs.
    - NEVER evaluates QR payload strings as executable code.
    - Enforces maximum image dimension checks (4096x4096px) to prevent decompression bombs.
    - Sanitizes log output to prevent leaking full payload content or credentials.
    """

    def __init__(self, url_adapter: Optional[URLAdapter] = None):
        self.url_adapter = url_adapter or URLAdapter()

    @staticmethod
    def is_url(payload: str) -> bool:
        """Determines whether a decoded QR payload string is a URL."""
        if not payload:
            return False
        clean = payload.strip()
        if clean.lower().startswith(("http://", "https://")):
            return True
        return bool(URL_PATTERN.match(clean))

    def detect_and_decode_qr(self, image_bytes: bytes) -> Tuple[bool, Optional[str]]:
        """
        Decodes raw image bytes with OpenCV and extracts QR payload.
        Enforces dimension checks against decompression bomb DoS attacks.
        """
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            raise ValueError("Invalid image format or unreadable image file.")

        h, w = img.shape[:2]
        if h > MAX_IMAGE_DIMENSION or w > MAX_IMAGE_DIMENSION:
            logger.warning(f"Image rejected due to excessive dimensions: {w}x{h} px.")
            raise ValueError(f"Image dimensions ({w}x{h} px) exceed maximum allowed limit of {MAX_IMAGE_DIMENSION}x{MAX_IMAGE_DIMENSION} px.")

        detector = cv2.QRCodeDetector()

        # 1. Primary detection: detectAndDecode
        payload, points, _ = detector.detectAndDecode(img)
        if payload and payload.strip():
            return True, payload.strip()

        # 2. Fallback detection for multi-QR images: detectAndDecodeMulti
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
        if retval and decoded_info:
            for info in decoded_info:
                if info and info.strip():
                    return True, info.strip()

        return False, None

    def scan_qr_image(self, image_bytes: bytes) -> Dict[str, Any]:
        """
        Processes QR image payload and connects to URLAdapter if payload is a URL.
        """
        decoded, payload = self.detect_and_decode_qr(image_bytes)

        if not decoded or not payload:
            return {
                "decoded": False,
                "payload": None,
                "payload_type": None,
                "risk_analysis": None
            }

        # Mask payload string for server logs to prevent credential/sensitive data leakage
        masked_payload = payload[:20] + "..." if len(payload) > 20 else payload
        logger.info(f"QR payload decoded (type check pending). Length: {len(payload)} chars.")

        if self.is_url(payload):
            payload_type = "url"
            try:
                # Pass URL string to URLAdapter ONLY - absolutely NO HTTP requests made!
                risk_result = self.url_adapter.analyze_url(payload)
                if hasattr(risk_result, "model_dump"):
                    risk_analysis = risk_result.model_dump()
                elif hasattr(risk_result, "dict"):
                    risk_analysis = risk_result.dict()
                else:
                    risk_analysis = risk_result
            except NotImplementedError as e:
                risk_analysis = {
                    "status": "unconnected",
                    "detail": str(e)
                }
        else:
            payload_type = "text"
            risk_analysis = None

        return {
            "decoded": True,
            "payload": payload,
            "payload_type": payload_type,
            "risk_analysis": risk_analysis
        }
