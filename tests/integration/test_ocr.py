import io
from unittest.mock import patch

import cv2
import numpy as np
from fastapi.testclient import TestClient

from zenshield.api.v1.verify import get_message_adapter
from zenshield.main import app
from zenshield.schemas.verification import OCRAnalyzeResponse, RiskResult

client = TestClient(app, raise_server_exceptions=False)


def generate_sample_image_bytes(text: str = "") -> bytes:
    """
    Helper function to generate a PNG image in memory with optional text rendered via OpenCV.
    """
    img = np.ones((300, 600, 3), dtype=np.uint8) * 255
    if text:
        cv2.putText(img, text, (20, 150), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)
    success, encoded_img = cv2.imencode(".png", img)
    assert success, "Failed to encode PNG bytes"
    return encoded_img.tobytes()


class MockConnectedMessageAdapter:
    """Mock connected message adapter for testing."""

    def analyze_message(self, message: str) -> RiskResult:
        return RiskResult(
            is_risky=True,
            risk_score=0.88,
            risk_level="high",
            reasons=["Urgent action pattern detected"],
        )


class MockUnconnectedMessageAdapter:
    """Mock unconnected message adapter for testing."""

    def analyze_message(self, message: str) -> RiskResult:
        raise NotImplementedError("Message detection engine has not been connected yet.")


@patch("pytesseract.image_to_string")
def test_ocr_readable_screenshot_with_connected_engine(mock_tesseract):
    """
    1. Test readable screenshot containing text with connected message engine.
       Verifies HTTP 200 and OCRAnalyzeResponse schema compliance.
    """
    extracted_sample = "URGENT: Your bank account has been suspended. Click http://bank-update.com"
    mock_tesseract.return_value = extracted_sample

    app.dependency_overrides[get_message_adapter] = lambda: MockConnectedMessageAdapter()
    try:
        img_bytes = generate_sample_image_bytes(extracted_sample)
        files = {"file": ("screenshot.png", io.BytesIO(img_bytes), "image/png")}
        response = client.post("/api/v1/ocr/analyze", files=files)

        assert response.status_code == 200
        data = response.json()
        validated_response = OCRAnalyzeResponse(**data)
        assert validated_response.success is True
        assert validated_response.extracted_text == extracted_sample
        assert validated_response.risk_analysis["is_risky"] is True
        assert validated_response.risk_analysis["risk_score"] == 0.88
    finally:
        app.dependency_overrides.clear()


@patch("pytesseract.image_to_string")
def test_ocr_unreadable_image(mock_tesseract):
    """
    2. Test image without readable text (blank or noisy unreadable image).
       Verifies HTTP 200 and success=False.
    """
    mock_tesseract.return_value = ""

    img_bytes = generate_sample_image_bytes("")
    files = {"file": ("blank.png", io.BytesIO(img_bytes), "image/png")}
    response = client.post("/api/v1/ocr/analyze", files=files)

    assert response.status_code == 200
    data = response.json()
    validated_response = OCRAnalyzeResponse(**data)
    assert validated_response.success is False
    assert validated_response.extracted_text == ""
    assert validated_response.message == "No readable text detected"
    assert validated_response.risk_analysis is None


def test_ocr_invalid_image():
    """
    3. Test uploading invalid or corrupted file format.
    """
    invalid_bytes = b"Not a valid image file content"
    files = {"file": ("corrupted.png", io.BytesIO(invalid_bytes), "image/png")}
    response = client.post("/api/v1/ocr/analyze", files=files)

    assert response.status_code == 400
    assert "Invalid image format" in response.json()["detail"]


def test_ocr_oversized_image():
    """
    4. Test uploading an image exceeding the 10 MB limit.
    """
    oversized_bytes = b"Y" * (10 * 1024 * 1024 + 1024)
    files = {"file": ("huge.png", io.BytesIO(oversized_bytes), "image/png")}
    response = client.post("/api/v1/ocr/analyze", files=files)

    assert response.status_code == 413
    assert "File size exceeds maximum allowed limit" in response.json()["detail"]


@patch("pytesseract.image_to_string")
def test_ocr_succeeds_message_engine_unavailable(mock_tesseract):
    """
    5. Test OCR succeeds in extracting text, but the message engine is disconnected (raises NotImplementedError).
    """
    extracted_sample = "Your verification code is 123456"
    mock_tesseract.return_value = extracted_sample

    app.dependency_overrides[get_message_adapter] = lambda: MockUnconnectedMessageAdapter()
    try:
        img_bytes = generate_sample_image_bytes(extracted_sample)
        files = {"file": ("sms_screenshot.png", io.BytesIO(img_bytes), "image/png")}
        response = client.post("/api/v1/ocr/analyze", files=files)

        assert response.status_code == 200
        data = response.json()
        validated_response = OCRAnalyzeResponse(**data)
        assert validated_response.success is True
        assert validated_response.extracted_text == extracted_sample
        assert validated_response.risk_analysis["status"] == "unconnected"
    finally:
        app.dependency_overrides.clear()


@patch("pytesseract.image_to_string")
def test_unexpected_ocr_failure(mock_tesseract):
    """
    6. Test unexpected failure during OCR processing returns clean HTTP 500 without stack trace leakage.
    """
    mock_tesseract.side_effect = Exception("Pytesseract internal memory error")

    img_bytes = generate_sample_image_bytes("Test Text")
    files = {"file": ("screenshot.png", io.BytesIO(img_bytes), "image/png")}
    response = client.post("/api/v1/ocr/analyze", files=files)

    assert response.status_code == 500
    assert "An internal server error occurred" in response.json()["detail"]
