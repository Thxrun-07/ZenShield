"""Tests for FastAPI endpoints and JSON schema contract."""

from fastapi.testclient import TestClient


def test_api_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "ZenShield" in data["service"]


def test_api_openapi_docs(client: TestClient):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "paths" in schema
    assert "/api/v1/verify/url" in schema["paths"]


def test_api_verify_contract_keys(client: TestClient):
    """Ensure response follows exact contract required by all teammates."""
    payload = {"url": "https://example.com/login"}
    response = client.post("/api/v1/verify/url", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Exact required keys
    required_keys = {
        "risk_score",
        "risk_level",
        "classification",
        "confidence",
        "known_ioc",
        "signals",
        "recommendation",
    }
    assert required_keys.issubset(set(data.keys()))

    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in ("LOW", "CAUTION", "HIGH", "CRITICAL")
    assert data["classification"] in ("Safe", "Low Risk", "Suspicious", "Potential Phishing", "Known Malicious")
    assert isinstance(data["confidence"], (int, float))
    assert 0.0 <= data["confidence"] <= 1.0
    assert isinstance(data["known_ioc"], bool)
    assert isinstance(data["signals"], list)
    assert isinstance(data["recommendation"], str)


def test_api_verify_legitimate_url(client: TestClient):
    response = client.post("/api/v1/verify/url", json={"url": "https://google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 0
    assert data["risk_level"] == "LOW"
    assert data["classification"] == "Safe"
    assert data["known_ioc"] is False


def test_api_verify_typosquatting(client: TestClient):
    response = client.post("/api/v1/verify/url", json={"url": "https://paypa1.com/login"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 25
    assert any(s["name"] == "Typosquatting" for s in data["signals"])


def test_api_verify_known_ioc(client: TestClient):
    response = client.post("/api/v1/verify/url", json={"url": "https://evil-example.com/steal"})
    assert response.status_code == 200
    data = response.json()
    assert data["known_ioc"] is True
    assert data["classification"] == "Known Malicious"
    assert data["risk_level"] == "CRITICAL"


def test_api_verify_raw_ip(client: TestClient):
    response = client.post("/api/v1/verify/url", json={"url": "http://192.168.1.1/login"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 25
    assert any(s["name"] == "Raw IP address hostname" for s in data["signals"])


def test_api_malformed_empty_url(client: TestClient):
    # Empty string should fail schema validation with 422, not crash 500
    response = client.post("/api/v1/verify/url", json={"url": ""})
    assert response.status_code == 422
