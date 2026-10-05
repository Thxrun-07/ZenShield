"""OCR processing service using OpenCV and Pytesseract."""

import logging
import os
from typing import Any

import cv2
import numpy as np
import pytesseract

from zenshield.adapters.message_adapter import MessageAdapter

logger = logging.getLogger("zenshield.audit")

MAX_IMAGE_DIMENSION = 4096


class OCRService:
    """Local OCR processing service using OpenCV and Pytesseract."""

    def __init__(self, message_adapter: MessageAdapter | None = None):
        self.message_adapter = message_adapter or MessageAdapter()

        tesseract_cmd = os.getenv("TESSERACT_CMD")
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

    @staticmethod
    def preprocess_image(img: np.ndarray) -> np.ndarray:
        if len(img.shape) == 3 and img.shape[2] == 3:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        elif len(img.shape) == 3 and img.shape[2] == 4:
            gray = cv2.cvtColor(img, cv2.COLOR_BGRA2GRAY)
        else:
            gray = img

        h, w = gray.shape[:2]
        if h < 300 or w < 300:
            scale = max(300 / h, 300 / w)
            gray = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)

        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        return thresh

    def extract_text_from_image(self, image_bytes: bytes) -> str:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            raise ValueError("Invalid image format or unreadable image file.")

        h, w = img.shape[:2]
        if h > MAX_IMAGE_DIMENSION or w > MAX_IMAGE_DIMENSION:
            raise ValueError(
                f"Image dimensions ({w}x{h} px) exceed maximum allowed limit of {MAX_IMAGE_DIMENSION}x{MAX_IMAGE_DIMENSION} px."
            )

        preprocessed = self.preprocess_image(img)
        raw_text = pytesseract.image_to_string(preprocessed)
        return raw_text.strip() if raw_text else ""

    def analyze_ocr_image(self, image_bytes: bytes) -> dict[str, Any]:
        try:
            extracted_text = self.extract_text_from_image(image_bytes)
        except pytesseract.TesseractNotFoundError as err:
            raise RuntimeError(
                "Tesseract-OCR executable was not found on system PATH. "
                "Please install Tesseract-OCR and configure TESSERACT_CMD in your .env file."
            ) from err

        logger.info("OCR text extraction completed. Length: %d chars.", len(extracted_text))

        if not extracted_text:
            return {
                "success": False,
                "extracted_text": "",
                "message": "No readable text detected",
                "risk_analysis": None,
            }

        try:
            risk_result = self.message_adapter.analyze_message(extracted_text)
            masked_text = getattr(risk_result, "_masked_message", None) or extracted_text
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
            masked_text = extracted_text

        return {
            "success": True,
            "extracted_text": masked_text,
            "risk_analysis": risk_analysis,
        }
