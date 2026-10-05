"""FastAPI endpoint and security tests for Zenshield."""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.asyncio
async def test_health_check_endpoint():
    """Verify health endpoint."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "healthy")
        assert "zenshield" in data["service"].lower()


@pytest.mark.asyncio
async def test_verify_message_success():
    """Verify valid request returns 200 with complete AnalysisResult schema."""
    payload = {
        "message": "Hi Ravi, your OTP is 482931. Call 9876543210 immediately to verify your KYC.",
        "country": "IN",
        "channel": "sms",
        "enable_llm": False,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/v1/verify/message", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert "request_id" in data
        assert "score" in data
        assert "risk_level" in data
        assert "classification" in data
        assert "intents" in data
        assert "signals" in data
        assert "breakdown" in data
        assert "privacy" in data
        assert data["privacy"]["pii_detected"] is True

        # Assert no raw PII in public response
        assert "482931" not in data["privacy"]["masked_message"]
        assert "9876543210" not in data["privacy"]["masked_message"]


@pytest.mark.asyncio
async def test_reject_empty_message():
    """Empty message is rejected with 422."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/v1/verify/message", json={"message": ""})
        assert resp.status_code == 422
        data = resp.json()
        assert "error" in data
        assert data["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_reject_unknown_fields():
    """Unknown fields are strictly forbidden."""
    payload = {
        "message": "Hello world",
        "attacker_injected_field": "exploit",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/v1/verify/message", json=payload)
        assert resp.status_code == 422
        data = resp.json()
        assert data["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.asyncio
async def test_422_response_never_echoes_canary_input():
    """Privacy guarantee: 422 validation errors never leak input tokens."""
    canary = "SECRET_CANARY_TOKEN_99999"
    payload = {
        "message": "Valid text",
        "country": f"TOO_LONG_{canary}",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/api/v1/verify/message", json=payload)
        assert resp.status_code == 422
        raw_resp = resp.text
        # Canary token MUST NOT be present in response
        assert canary not in raw_resp


@pytest.mark.asyncio
async def test_reject_payload_too_large():
    """Payloads exceeding body size limit are rejected with 413."""
    huge_message = "A" * 70_000
    headers = {"Content-Length": str(len(huge_message) + 100)}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/verify/message",
            content=huge_message,
            headers=headers,
        )
        assert resp.status_code == 413
        assert resp.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
