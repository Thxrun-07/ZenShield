import cv2
import numpy as np
import pytesseract
import os
import logging
from typing import Dict, Any, Optional
from services.message_adapter import MessageAdapter

logger = logging.getLogger(__name__)

# Maximum allowable image dimension (4096 x 4096 px) to prevent image decompression bomb DoS attacks
MAX_IMAGE_DIMENSION = 4096


class OCRService:
    """
    Local OCR processing service using OpenCV for preprocessing and Pytesseract for text extraction.

    SECURITY CONTROLS:
    - Enforces max image dimension checks (4096x4096px) against decompression bombs.
    - Sanitizes server logs (never logs private message text, credentials, or PII).
    - OCR processing remains 100% local. No external AI APIs invoked.
    """

    def __init__(self, message_adapter: Optional[MessageAdapter] = None):
        self.message_adapter = message_adapter or MessageAdapter()

        # Configure Tesseract binary path if provided in environment
        tesseract_cmd = os.getenv("TESSERACT_CMD")
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

    @staticmethod
    def preprocess_image(img: np.ndarray) -> np.ndarray:
        """
        Applies OpenCV image preprocessing (grayscale conversion, dimension scaling, thresholding).
        """
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
        """
        Decodes raw image bytes with OpenCV, enforces dimension bounds, and runs Pytesseract OCR.
        """
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            raise ValueError("Invalid image format or unreadable image file.")

        h, w = img.shape[:2]
        if h > MAX_IMAGE_DIMENSION or w > MAX_IMAGE_DIMENSION:
            logger.warning(f"OCR image rejected due to excessive dimensions: {w}x{h} px.")
            raise ValueError(f"Image dimensions ({w}x{h} px) exceed maximum allowed limit of {MAX_IMAGE_DIMENSION}x{MAX_IMAGE_DIMENSION} px.")

        preprocessed = self.preprocess_image(img)
        raw_text = pytesseract.image_to_string(preprocessed)
        return raw_text.strip() if raw_text else ""

    def analyze_ocr_image(self, image_bytes: bytes) -> Dict[str, Any]:
        """
        Executes local OCR on image bytes and forwards extracted text to MessageAdapter.
        """
        try:
            extracted_text = self.extract_text_from_image(image_bytes)
        except pytesseract.TesseractNotFoundError:
            raise RuntimeError(
                "Tesseract-OCR executable was not found on system PATH. "
                "Please install Tesseract-OCR and configure TESSERACT_CMD in your .env file."
            )

        # Log metrics ONLY - never log sensitive extracted text content
        logger.info(f"OCR text extraction completed. Length: {len(extracted_text)} chars.")

        if not extracted_text:
            return {
                "success": False,
                "extracted_text": "",
                "message": "No readable text detected",
                "risk_analysis": None
            }

        # Send extracted text to MessageAdapter for analysis
        try:
            risk_result = self.message_adapter.analyze_message(extracted_text)
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

        return {
            "success": True,
            "extracted_text": extracted_text,
            "risk_analysis": risk_analysis
        }
