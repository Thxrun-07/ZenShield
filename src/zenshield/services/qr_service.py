"""QR Code scanning and processing service using local OpenCV."""

import logging
import re
from typing import Any

import cv2
import numpy as np

from zenshield.adapters.url_adapter import URLAdapter

logger = logging.getLogger("zenshield.audit")

MAX_IMAGE_DIMENSION = 4096

URL_PATTERN = re.compile(
    r"^(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?$",
    re.IGNORECASE,
)


class QRService:
    """QR Code Scanning Service using local OpenCV QR detection."""

    def __init__(self, url_adapter: URLAdapter | None = None):
        self.url_adapter = url_adapter or URLAdapter()

    @staticmethod
    def is_url(payload: str) -> bool:
        if not payload:
            return False
        clean = payload.strip()
        if clean.lower().startswith(("http://", "https://")):
            return True
        return bool(URL_PATTERN.match(clean))

    def detect_and_decode_qr(self, image_bytes: bytes) -> tuple[bool, str | None]:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            raise ValueError("Invalid image format or unreadable image file.")

        h, w = img.shape[:2]
        if h > MAX_IMAGE_DIMENSION or w > MAX_IMAGE_DIMENSION:
            raise ValueError(
                f"Image dimensions ({w}x{h} px) exceed maximum allowed limit of {MAX_IMAGE_DIMENSION}x{MAX_IMAGE_DIMENSION} px."
            )

        detector = cv2.QRCodeDetector()
        payload, points, _ = detector.detectAndDecode(img)
        if payload and payload.strip():
            return True, payload.strip()

        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
        if retval and decoded_info:
            for info in decoded_info:
                if info and info.strip():
                    return True, info.strip()

        return False, None

    def scan_qr_image(self, image_bytes: bytes) -> dict[str, Any]:
        decoded, payload = self.detect_and_decode_qr(image_bytes)

        if not decoded or not payload:
            return {
                "decoded": False,
                "payload": None,
                "payload_type": None,
                "risk_analysis": None,
            }

        logger.info("QR payload decoded successfully. Length: %d chars.", len(payload))

        if self.is_url(payload):
            payload_type = "url"
            try:
                risk_result = self.url_adapter.analyze_url(payload)
                if hasattr(risk_result, "model_dump"):
                    risk_analysis = risk_result.model_dump()
                elif hasattr(risk_result, "dict"):
                    risk_analysis = risk_result.dict()
                elif isinstance(risk_result, dict):
                    risk_analysis = risk_result
                else:
                    risk_analysis = dict(risk_result)
            except NotImplementedError as e:
                risk_analysis = {
                    "status": "unconnected",
                    "detail": str(e),
                }
        else:
            payload_type = "text"
            risk_analysis = None

        return {
            "decoded": True,
            "payload": payload,
            "payload_type": payload_type,
            "risk_analysis": risk_analysis,
        }
