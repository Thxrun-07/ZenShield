import sys
import io
import cv2
import numpy as np
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

# Ensure backend root is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app
from api.verify import get_url_adapter
from schemas.verification import RiskResult, QRScanResponse

client = TestClient(app, raise_server_exceptions=False)


def generate_qr_code_image_bytes(content: str) -> bytes:
    """
    Helper function to generate a valid QR code image in PNG format locally using OpenCV.
    """
    encoder = cv2.QRCodeEncoder.create()
    qr_matrix = encoder.encode(content)
    img = cv2.resize(qr_matrix, (300, 300), interpolation=cv2.INTER_NEAREST)
    success, encoded_img = cv2.imencode(".png", img)
    assert success, "Failed to encode QR image bytes"
    return encoded_img.tobytes()


def generate_non_qr_image_bytes() -> bytes:
    """
    Helper function to generate a solid white PNG image (no QR code) locally using OpenCV.
    """
    img = np.ones((300, 300, 3), dtype=np.uint8) * 255
    success, encoded_img = cv2.imencode(".png", img)
    assert success, "Failed to encode blank image bytes"
    return encoded_img.tobytes()


class MockConnectedURLAdapter:
    """Mock connected URL adapter for testing."""
    def analyze_url(self, url: str) -> RiskResult:
        return RiskResult(
            is_risky=True,
            risk_score=0.92,
            risk_level="high",
            reasons=["Phishing pattern detected by URL engine"]
        )


def test_valid_url_qr_scan():
    """
    1. Test scanning a valid URL QR code image with connected URL engine.
       Verifies HTTP 200 and QRScanResponse schema compliance.
    """
    app.dependency_overrides[get_url_adapter] = lambda: MockConnectedURLAdapter()
    try:
        url_text = "https://phishing-site.example.com"
        qr_bytes = generate_qr_code_image_bytes(url_text)

        files = {"file": ("qr_url.png", io.BytesIO(qr_bytes), "image/png")}
        response = client.post("/api/v1/qr/scan", files=files)

        assert response.status_code == 200
        data = response.json()
        validated_response = QRScanResponse(**data)
        assert validated_response.decoded is True
        assert validated_response.payload == url_text
        assert validated_response.payload_type == "url"
        assert validated_response.risk_analysis is not None
        assert validated_response.risk_analysis["is_risky"] is True
        assert validated_response.risk_analysis["risk_score"] == 0.92
    finally:
        app.dependency_overrides.clear()


def test_valid_text_qr_scan():
    """
    2. Test scanning a valid text QR code image (non-URL payload).
       Verifies HTTP 200 and QRScanResponse schema compliance.
    """
    text_content = "Hello World! Wifi Password: Secret123"
    qr_bytes = generate_qr_code_image_bytes(text_content)

    files = {"file": ("qr_text.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)

    assert response.status_code == 200
    data = response.json()
    validated_response = QRScanResponse(**data)
    assert validated_response.decoded is True
    assert validated_response.payload == text_content
    assert validated_response.payload_type == "text"
    assert validated_response.risk_analysis is None


def test_image_without_qr():
    """
    3. Test scanning an image that contains no QR code.
    """
    blank_bytes = generate_non_qr_image_bytes()

    files = {"file": ("blank.png", io.BytesIO(blank_bytes), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)

    assert response.status_code == 200
    data = response.json()
    validated_response = QRScanResponse(**data)
    assert validated_response.decoded is False
    assert validated_response.payload is None
    assert validated_response.payload_type is None
    assert validated_response.risk_analysis is None


def test_invalid_image_upload():
    """
    4. Test uploading corrupted / non-image file.
    """
    invalid_bytes = b"This is plain text content, not an image file"

    files = {"file": ("corrupted.png", io.BytesIO(invalid_bytes), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)

    assert response.status_code == 400
    assert "Invalid image format" in response.json()["detail"]


def test_oversized_upload():
    """
    5. Test uploading a file that exceeds the 10 MB maximum limit.
    """
    oversized_bytes = b"X" * (10 * 1024 * 1024 + 1024)

    files = {"file": ("huge.png", io.BytesIO(oversized_bytes), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)

    assert response.status_code == 413
    assert "File size exceeds maximum allowed limit" in response.json()["detail"]


def test_url_qr_with_disconnected_url_engine():
    """
    6. Test scanning a URL QR code image when the URL engine is unconnected.
    """
    app.dependency_overrides.clear()

    url_text = "https://example.org"
    qr_bytes = generate_qr_code_image_bytes(url_text)

    files = {"file": ("qr_url.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)

    assert response.status_code == 200
    data = response.json()
    validated_response = QRScanResponse(**data)
    assert validated_response.decoded is True
    assert validated_response.payload == url_text
    assert validated_response.payload_type == "url"
    assert validated_response.risk_analysis["status"] == "unconnected"


def test_verify_decoded_urls_never_requested():
    """
    7. Test verifying that decoded QR URLs are NEVER automatically requested or fetched via HTTP.
    """
    app.dependency_overrides[get_url_adapter] = lambda: MockConnectedURLAdapter()
    try:
        with patch("requests.get") as mock_http_get, patch("requests.post") as mock_http_post:
            target_url = "https://suspicious-qr-target.com"
            qr_bytes = generate_qr_code_image_bytes(target_url)

            files = {"file": ("qr_target.png", io.BytesIO(qr_bytes), "image/png")}
            response = client.post("/api/v1/qr/scan", files=files)

            assert response.status_code == 200
            # Ensure requests.get was NEVER called to fetch the URL
            mock_http_get.assert_not_called()
            for call in mock_http_post.call_args_list:
                assert target_url not in str(call)
    finally:
        app.dependency_overrides.clear()
