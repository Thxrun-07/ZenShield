"""Full-app unified verification integration tests covering all engine pipelines."""

import io
from unittest.mock import patch

import cv2
import numpy as np
from fastapi.testclient import TestClient


def generate_qr_image(url: str) -> bytes:
    encoder = cv2.QRCodeEncoder.create()
    matrix = encoder.encode(url)
    img = cv2.resize(matrix, (300, 300), interpolation=cv2.INTER_NEAREST)
    _, encoded = cv2.imencode(".png", img)
    return encoded.tobytes()


def generate_sample_image(text: str) -> bytes:
    img = np.ones((300, 600, 3), dtype=np.uint8) * 255
    cv2.putText(img, text, (20, 150), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)
    _, encoded = cv2.imencode(".png", img)
    return encoded.tobytes()


def test_verify_clean_url(client: TestClient):
    """Clean legitimate URL evaluation."""
    payload = {"type": "url", "content": "https://google.com"}
    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Unified contract
    assert data["type"] == "url"
    assert data["result"]["known_ioc"] is False
    assert data["result"]["score"] < 25
    assert data["result"]["level"] in ("LOW", "low")

    # Backward compatibility fields
    assert data["result"]["is_risky"] is False
    assert data["result"]["risk_score"] < 0.25
    assert data["result"]["risk_level"] == "low"
    assert isinstance(data["result"]["reasons"], list)


def test_verify_known_bad_url(client: TestClient):
    """Known malicious URL present in IOC registry."""
    payload = {"type": "url", "content": "https://evil-example.com/steal"}
    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["result"]["known_ioc"] is True
    assert data["result"]["score"] >= 80
    assert data["result"]["level"] in ("HIGH", "CRITICAL")
    assert data["result"]["is_risky"] is True


def test_verify_typosquatting_url(client: TestClient):
    """Typosquatting and homoglyph URL detection."""
    payload = {"type": "url", "content": "https://paypa1.com/login"}
    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["result"]["score"] >= 25
    assert any(
        "typosquat" in s["name"].lower() or "typosquat" in s["evidence"].lower() for s in data["result"]["signals"]
    )


def test_verify_english_phishing_message(client: TestClient):
    """English language phishing SMS message."""
    payload = {
        "type": "message",
        "content": "URGENT: Your SBI bank account will be blocked today due to pending KYC. Click http://sbi-kyc-update.com/login",
    }
    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["result"]["score"] >= 50
    assert data["result"]["is_risky"] is True


def test_verify_tamil_tanglish_message(client: TestClient):
    """Tamil / Tanglish urgent extortion phishing message."""
    payload = {
        "type": "message",
        "content": "Ungal account block aagum. Ippove OTP kuduthu KYC verify pannunga. Call 9876543210.",
    }
    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["result"]["score"] >= 50
    assert data["result"]["is_risky"] is True


def test_verify_message_with_embedded_malicious_url(client: TestClient):
    """Message containing an embedded known-bad URL elevates overall risk and flags known_ioc."""
    payload = {
        "type": "message",
        "content": "Alert: Unusual sign-in attempt detected. Verify at https://evil-example.com/steal immediately.",
    }
    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["result"]["known_ioc"] is True
    assert data["result"]["score"] >= 80
    assert data["result"]["is_risky"] is True


def test_community_report_elevates_subsequent_verify(client: TestClient):
    """Submitting a community report dynamically elevates the risk score of that URL in subsequent /verify requests."""
    fresh_url = "https://freshly-reported-fraud-portal.com/login"

    # 1. Verify before report (unknown URL, no IOC flag)
    pre_res = client.post("/api/v1/verify", json={"type": "url", "content": fresh_url})
    assert pre_res.status_code == 200
    assert pre_res.json()["result"]["known_ioc"] is False

    # 2. Submit community fraud report
    report_payload = {
        "indicator": fresh_url,
        "indicator_type": "url",
        "threat_type": "phishing",
        "description": "Fake credential harvesting page posing as income tax refund portal",
        "evidence": "Fake form asking for OTP and CVV",
        "location": "Chennai",
    }
    rep_res = client.post("/api/v1/intelligence/report", json=report_payload)
    assert rep_res.status_code == 201

    # 3. Verify after report (must elevate risk score and flag known_ioc)
    post_res = client.post("/api/v1/verify", json={"type": "url", "content": fresh_url})
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert post_data["result"]["known_ioc"] is True
    assert post_data["result"]["score"] >= 75
    assert post_data["result"]["level"] in ("HIGH", "CRITICAL")
    assert post_data["result"]["is_risky"] is True


def test_verify_qr_end_to_end(client: TestClient):
    """QR scan end-to-end flow routing decoded URL through URL risk pipeline."""
    target_url = "https://evil-example.com/steal"
    qr_bytes = generate_qr_image(target_url)

    files = {"file": ("test_qr.png", io.BytesIO(qr_bytes), "image/png")}
    response = client.post("/api/v1/qr/scan", files=files)
    assert response.status_code == 200
    data = response.json()

    assert data["decoded"] is True
    assert data["payload"] == target_url
    assert data["payload_type"] == "url"
    assert data["risk_analysis"] is not None
    assert data["risk_analysis"]["known_ioc"] is True
    assert data["risk_analysis"]["is_risky"] is True


@patch("pytesseract.image_to_string")
def test_verify_ocr_end_to_end(mock_tesseract, client: TestClient):
    """OCR analyze end-to-end flow forwarding extracted text to message pipeline."""
    extracted_text = "URGENT: Your SBI account is blocked. Verify at http://fake-sbi.com"
    mock_tesseract.return_value = extracted_text

    img_bytes = generate_sample_image(extracted_text)
    files = {"file": ("screenshot.png", io.BytesIO(img_bytes), "image/png")}
    response = client.post("/api/v1/ocr/analyze", files=files)
    assert response.status_code == 200
    data = response.json()

    assert data["success"] is True
    assert data["risk_analysis"] is not None
    assert data["risk_analysis"]["is_risky"] is True


def test_verify_validation_errors(client: TestClient):
    """Request validation errors return HTTP 422."""
    # Empty content
    assert client.post("/api/v1/verify", json={"type": "url", "content": ""}).status_code == 422
    # Whitespace content
    assert client.post("/api/v1/verify", json={"type": "message", "content": "   "}).status_code == 422
    # Invalid type
    assert client.post("/api/v1/verify", json={"type": "email", "content": "test"}).status_code == 422
    # Missing content
    assert client.post("/api/v1/verify", json={"type": "url"}).status_code == 422
