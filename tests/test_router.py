"""
FastAPI Router Integration Tests for Final Endpoints:
- GET  /api/v1/intelligence/check
- POST /api/v1/intelligence/report
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.intelligence.database import Base, get_db
from app.intelligence.router import router


@pytest.fixture
def test_client():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client


def test_check_unknown_indicator(test_client):
    res = test_client.get("/api/v1/intelligence/check?indicator=unknown-site.example&indicator_type=domain")
    assert res.status_code == 200
    data = res.json()
    assert data["known"] is False
    assert "safe" not in data  # Unknown does NOT mean safe
    assert "message" in data


def test_submit_report_and_check_indicator(test_client):
    # 1. Submit report
    payload = {
        "indicator": "fake-bank-a.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Deceptive verification portal targeting OTP 482931",
        "evidence": "Requests account credentials",
        "location": "Chennai"
    }
    post_res = test_client.post("/api/v1/intelligence/report", json=payload)
    assert post_res.status_code == 201
    post_data = post_res.json()
    assert post_data["new_ioc"] is True
    assert post_data["report_count"] == 1

    # 2. Check indicator
    check_res = test_client.get("/api/v1/intelligence/check?indicator=fake-bank-a.example&indicator_type=domain")
    assert check_res.status_code == 200
    check_data = check_res.json()
    assert check_data["known"] is True
    assert check_data["indicator"] == "fake-bank-a.example"
    assert check_data["indicator_type"] == "domain"
    assert check_data["threat_type"] == "phishing"
    assert check_data["status"] == "active"
    assert check_data["confidence"] >= 0.5
    assert check_data["report_count"] == 1
    assert "safe" not in check_data
