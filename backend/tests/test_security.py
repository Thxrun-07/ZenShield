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

# Initialize TestClient with raise_server_exceptions=False to test generic 500 JSON responses
client = TestClient(app, raise_server_exceptions=False)


def test_oversized_payload_middleware():
    """
    1. Test that POST requests exceeding max body size limit (10MB) are rejected with HTTP 413.
    """
    huge_json_content = "a" * (10 * 1024 * 1024 + 1024)
    headers = {"Content-Length": str(len(huge_json_content))}
    response = client.post("/api/v1/verify", data=huge_json_content, headers=headers)

    assert response.status_code == 413
    assert "exceeds maximum allowed limit" in response.json()["detail"]


def test_magic_bytes_spoofing_prevention():
    """
    2. Test that uploading a file with valid image MIME type but invalid magic bytes (content spoofing) is rejected.
    """
    fake_png_content = b"THIS_IS_TEXT_NOT_A_PNG_FILE"
    files = {"file": ("malicious.png", io.BytesIO(fake_png_content), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)

    assert response.status_code == 400
    assert "Invalid image format" in response.json()["detail"]


def test_path_traversal_filename_handling():
    """
    3. Test that path traversal filenames (e.g. '../../../etc/passwd') are sanitized safely without error.
    """
    fake_png_content = b"THIS_IS_TEXT_NOT_A_PNG"
    files = {"file": ("../../../../etc/passwd", io.BytesIO(fake_png_content), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)

    # Should safely fail magic byte / image check (400), not path traversal / 500
    assert response.status_code == 400


def test_no_stack_trace_leakage_on_internal_error():
    """
    4. Test that unhandled internal server exceptions return generic 500 errors without leaking stack traces.
    """
    with patch("api.verify.URLAdapter.analyze_url", side_effect=Exception("Database secret credentials DB_PASS=secret123")):
        payload = {"type": "url", "content": "http://example.com"}
        response = client.post("/api/v1/verify", json=payload)

        assert response.status_code == 500
        data = response.json()
        assert data["detail"] == "An internal server error occurred while processing the verification request."
        # Verify secret / stack trace was NOT leaked in HTTP response
        assert "secret123" not in str(data)
        assert "Traceback" not in str(data)


def test_ssrf_prevention_no_http_requests_made():
    """
    5. Test that submitting a URL to /api/v1/verify or /api/v1/qr/scan does NOT issue any outgoing HTTP GET/POST requests.
    """
    with patch("requests.get") as mock_http_get, patch("requests.post") as mock_http_post:
        # Request url verification
        payload = {"type": "url", "content": "http://169.254.169.254/latest/meta-data/"}
        response = client.post("/api/v1/verify", json=payload)

        # Requests library must NEVER have been called to fetch the untrusted URL
        mock_http_get.assert_not_called()
        for call in mock_http_post.call_args_list:
            assert "169.254.169.254" not in str(call)


def test_decompression_bomb_prevention():
    """
    6. Test that images exceeding 4096x4096px dimensions are rejected to prevent image decompression bomb DoS attacks.
    """
    # Create an image header representing a 5000x5000 px image
    img_large = np.zeros((5000, 5000, 3), dtype=np.uint8)
    success, encoded_img = cv2.imencode(".png", img_large)
    assert success

    files = {"file": ("large_dim.png", io.BytesIO(encoded_img.tobytes()), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)

    assert response.status_code == 400
    assert "exceed maximum allowed limit" in response.json()["detail"]
