import sys
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

# Ensure backend root is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app
from api.verify import get_url_adapter, get_message_adapter
from schemas.verification import RiskResult, VerifyResponse

client = TestClient(app, raise_server_exceptions=False)


class MockConnectedURLAdapter:
    """Mock URL adapter returning a realistic RiskResult for testing."""
    def analyze_url(self, url: str) -> RiskResult:
        return RiskResult(
            is_risky=True,
            risk_score=0.85,
            risk_level="high",
            reasons=["Detected suspicious domain pattern"]
        )


class MockConnectedMessageAdapter:
    """Mock Message adapter returning a realistic RiskResult for testing."""
    def analyze_message(self, message: str) -> RiskResult:
        return RiskResult(
            is_risky=False,
            risk_score=0.10,
            risk_level="low",
            reasons=["No spam or phishing indicators found"]
        )


def test_valid_url_request():
    """
    Test valid URL verification request with connected URL engine adapter.
    Verifies HTTP 200 response and schema compliance.
    """
    app.dependency_overrides[get_url_adapter] = lambda: MockConnectedURLAdapter()
    try:
        payload = {"type": "url", "content": "http://suspicious-bank-login.com"}
        response = client.post("/api/v1/verify", json=payload)
        assert response.status_code == 200
        
        # Verify response schema contract
        data = response.json()
        validated_response = VerifyResponse(**data)
        assert validated_response.type == "url"
        assert validated_response.content == "http://suspicious-bank-login.com"
        assert validated_response.result.is_risky is True
        assert validated_response.result.risk_score == 0.85
        assert validated_response.result.risk_level == "high"
    finally:
        app.dependency_overrides.clear()


def test_valid_message_request():
    """
    Test valid message verification request with connected Message engine adapter.
    Verifies HTTP 200 response and schema compliance.
    """
    app.dependency_overrides[get_message_adapter] = lambda: MockConnectedMessageAdapter()
    try:
        payload = {"type": "message", "content": "Your account has been locked. Verify immediately."}
        response = client.post("/api/v1/verify", json=payload)
        assert response.status_code == 200

        # Verify response schema contract
        data = response.json()
        validated_response = VerifyResponse(**data)
        assert validated_response.type == "message"
        assert validated_response.content == "Your account has been locked. Verify immediately."
        assert validated_response.result.is_risky is False
        assert validated_response.result.risk_score == 0.10
        assert validated_response.result.risk_level == "low"
    finally:
        app.dependency_overrides.clear()


def test_empty_content_rejected():
    """
    Test that empty content strings are rejected with HTTP 422.
    """
    payload_empty = {"type": "url", "content": ""}
    response_empty = client.post("/api/v1/verify", json=payload_empty)
    assert response_empty.status_code == 422


def test_whitespace_only_content_rejected():
    """
    Test that whitespace-only content strings are rejected with HTTP 422.
    """
    payload_blank = {"type": "message", "content": "   \n\t  "}
    response_blank = client.post("/api/v1/verify", json=payload_blank)
    assert response_blank.status_code == 422


def test_invalid_type_rejected():
    """
    Test that unsupported verification types (e.g. 'qr', 'email') are rejected with HTTP 422.
    """
    payload_invalid = {"type": "invalid_type", "content": "http://example.com"}
    response_invalid = client.post("/api/v1/verify", json=payload_invalid)
    assert response_invalid.status_code == 422


def test_malformed_request_json():
    """
    Test that malformed JSON payloads (missing required fields) are rejected with HTTP 422.
    """
    payload_missing_content = {"type": "url"}
    response = client.post("/api/v1/verify", json=payload_missing_content)
    assert response.status_code == 422


def test_url_engine_unavailable():
    """
    Test URL verification when Person 1's URL engine is unconnected (raises NotImplementedError).
    Verifies HTTP 501 Not Implemented response.
    """
    app.dependency_overrides.clear()
    payload = {"type": "url", "content": "http://example.com"}
    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 501
    assert "URL detection engine has not been connected yet" in response.json()["detail"]


def test_message_engine_unavailable():
    """
    Test Message verification when Person 2's Message engine is unconnected (raises NotImplementedError).
    Verifies HTTP 501 Not Implemented response.
    """
    app.dependency_overrides.clear()
    payload = {"type": "message", "content": "Sample SMS message text"}
    response = client.post("/api/v1/verify", json=payload)
    assert response.status_code == 501
    assert "Message detection engine has not been connected yet" in response.json()["detail"]


def test_unexpected_service_error():
    """
    Test unexpected adapter service failure returns generic HTTP 500 without stack trace leakage.
    """
    with patch("api.verify.URLAdapter.analyze_url", side_effect=Exception("Database connection failed")):
        payload = {"type": "url", "content": "http://example.com"}
        response = client.post("/api/v1/verify", json=payload)
        assert response.status_code == 500
        assert response.json()["detail"] == "An internal server error occurred while processing the verification request."
