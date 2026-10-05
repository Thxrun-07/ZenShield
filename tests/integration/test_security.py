"""Security and hardening tests for ZenShield backend."""

import io
from unittest.mock import patch

import cv2
import numpy as np
import requests
from fastapi.testclient import TestClient

from zenshield.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_64kb_json_body_limit_returns_413():
    """POST request exceeding 64 KB JSON limit is rejected with HTTP 413."""
    oversized_text = "A" * (65 * 1024)  # 65 KB
    payload = {"type": "message", "content": oversized_text}
    headers = {"Content-Type": "application/json"}
    response = client.post("/api/v1/verify", json=payload, headers=headers)

    assert response.status_code == 413
    assert "exceeds maximum allowed size" in response.text or "413" in str(response.status_code)


def test_10mb_image_upload_under_and_over_limit():
    """10 MB image limit allows valid uploads and blocks files exceeding 10 MB."""
    # Under limit: valid small image
    small_img = np.ones((100, 100, 3), dtype=np.uint8) * 255
    _, enc_small = cv2.imencode(".png", small_img)
    files_ok = {"file": ("valid.png", io.BytesIO(enc_small.tobytes()), "image/png")}
    res_ok = client.post("/api/v1/qr/scan", files=files_ok)
    assert res_ok.status_code == 200

    # Over limit: 10 MB + 1 KB
    huge_bytes = b"\x89PNG\r\n\x1a\n" + (b"0" * (10 * 1024 * 1024 + 1024))
    files_over = {"file": ("huge.png", io.BytesIO(huge_bytes), "image/png")}
    res_over = client.post("/api/v1/qr/scan", files=files_over)
    assert res_over.status_code == 413
    assert "exceeds maximum allowed limit" in res_over.text


def test_chunked_streaming_oversize_rejected():
    """Streaming / chunked transfers without Content-Length cannot bypass size limit."""
    chunk_size = 8192
    num_chunks = 10  # 80 KB > 64 KB limit

    def stream_generator():
        for _ in range(num_chunks):
            yield b"x" * chunk_size

    # Omit Content-Length header to simulate chunked transfer
    response = client.post(
        "/api/v1/verify",
        content=stream_generator(),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_mime_spoofing_rejected():
    """Uploading plain text masquerading as PNG is rejected based on magic byte check."""
    fake_png = b"This is plain text with a fraudulent mime type."
    files = {"file": ("exploit.png", io.BytesIO(fake_png), "image/png")}

    res_qr = client.post("/api/v1/qr/scan", files=files)
    assert res_qr.status_code == 400
    assert "Invalid image format" in res_qr.text

    files_ocr = {"file": ("exploit.png", io.BytesIO(fake_png), "image/png")}
    res_ocr = client.post("/api/v1/ocr/analyze", files=files_ocr)
    assert res_ocr.status_code == 400
    assert "Invalid image format" in res_ocr.text


def test_zero_leakage_no_raw_pii_in_response():
    """Zero leakage: Raw sensitive PII and private message text must NEVER appear in response content."""
    secret_card = "4111222233334444"
    secret_phone = "9876543210"
    msg = f"My card is {secret_card} and phone is {secret_phone}. Please reset my account."

    response = client.post("/api/v1/verify", json={"type": "message", "content": msg})
    assert response.status_code == 200
    data = response.json()

    # Raw credit card and phone number must NOT be in returned content
    assert secret_card not in data["content"]
    assert secret_phone not in data["content"]
    assert secret_card not in response.text
    assert secret_phone not in response.text


def test_validation_error_does_not_echo_canary():
    """Unparseable input (422) does not echo user input or canary tokens in error detail."""
    canary = "CANARY_TOKEN_TOP_SECRET_12345"
    payload = {"type": canary, "content": "valid text"}

    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 422
    assert canary not in response.text


def test_ssrf_prevention_no_outbound_calls_to_target():
    """Verify that verifying an untrusted URL never initiates network requests to that URL."""
    target_url = "http://169.254.169.254/latest/meta-data/"
    with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
        response = client.post("/api/v1/verify", json={"type": "url", "content": target_url})
        assert response.status_code == 200

        # No request was made to target URL
        for call in mock_get.call_args_list:
            assert "169.254.169.254" not in str(call)
        for call in mock_post.call_args_list:
            assert "169.254.169.254" not in str(call)


def test_external_provider_failure_graceful_degradation():
    """External provider timeout or 500 server error does not crash the verification pipeline."""
    with patch("requests.get", side_effect=requests.exceptions.Timeout("VirusTotal timed out")):
        response = client.post("/api/v1/verify", json={"type": "url", "content": "https://example.com/test"})
        assert response.status_code == 200
        data = response.json()
        assert data["result"] is not None
        assert data["result"]["is_risky"] is False


def test_path_traversal_filename_handling():
    """Path traversal filenames (../../etc/passwd) are safely handled without crash."""
    fake_png = b"NOT_VALID_IMAGE"
    files = {"file": ("../../../../etc/passwd", io.BytesIO(fake_png), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)
    assert response.status_code == 400


def test_decompression_bomb_prevention():
    """Images exceeding maximum dimension limits (>4096px) are rejected to prevent DoS."""
    img_large = np.zeros((5000, 5000, 3), dtype=np.uint8)
    success, encoded = cv2.imencode(".png", img_large)
    assert success

    files = {"file": ("large.png", io.BytesIO(encoded.tobytes()), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)
    assert response.status_code == 400
    assert "exceed maximum allowed limit" in response.text
