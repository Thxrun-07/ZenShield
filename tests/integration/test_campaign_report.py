"""Integration tests for community reporting and campaign analytics."""

from fastapi.testclient import TestClient


def test_submit_phishing_report_url(client: TestClient):
    payload = {
        "target_url": "https://fake-login-update.com",
        "category": "phishing",
        "description": "Fake credentials harvesting form targeting SBI customers",
    }
    response = client.post("/api/v1/report/phishing", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert data["category"] == "phishing"
    assert "report_id" in data
    assert data["report_id"] is not None


def test_submit_phishing_report_message(client: TestClient):
    payload = {
        "message_content": "Your electricity connection will be disconnected today. Call 9876543210 immediately.",
        "category": "electricity_scam",
        "description": "TNEB bill scam SMS",
    }
    response = client.post("/api/v1/report/phishing", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert data["category"] == "electricity_scam"


def test_submit_phishing_report_empty(client: TestClient):
    payload = {
        "category": "phishing",
        "description": "Missing both URL and message",
    }
    response = client.post("/api/v1/report/phishing", json=payload)
    assert response.status_code == 400
    assert "Report must contain either a target_url or message_content" in response.text


def test_get_campaign_stats(client: TestClient):
    response = client.get("/api/v1/campaign/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "active"
    assert "active_campaigns_monitored" in data
    assert "total_iocs_monitored" in data
    assert "total_reports_processed" in data
