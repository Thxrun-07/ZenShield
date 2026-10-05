"""
Tests for Community Fraud Reporting Module (Part 2).

Validates all 12 required behaviors:
1. New community report
2. Existing IOC report
3. Report count increment
4. Multiple reports for same IOC
5. IOC creation through report
6. Privacy masking
7. Phone masking
8. Email masking
9. OTP masking
10. Ensure actual IOC is not masked
11. Invalid indicator type
12. Invalid threat type
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.intelligence.database import Base, get_db
from app.intelligence.masking import mask_sensitive_data
from app.intelligence.models import IOCRecord, Report
from app.intelligence.report_service import create_report
from app.intelligence.router import router
from app.intelligence.schemas import ReportCreateRequest


@pytest.fixture
def db_session():
    """Isolated in-memory database for direct service tests."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_client(db_session):
    """FastAPI TestClient with overridden database session."""
    app = FastAPI()
    app.include_router(router)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client


# ==============================================================================
# 1-5. Core Workflow & IOC Association Tests
# ==============================================================================


def test_new_community_report(db_session):
    """1. New community report creates report and new IOC."""
    payload = {
        "indicator": "fake-bank-a.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Fake banking verification page",
        "evidence": "Requests account credentials",
        "location": "Chennai",
    }

    result = create_report(payload, db=db_session)
    assert result.report_id is not None
    assert result.ioc_id is not None
    assert result.new_ioc is True
    assert result.report_count == 1


def test_existing_ioc_report(db_session):
    """2. Reporting an existing IOC reuses IOC and marks new_ioc=False."""
    # Pre-populate an IOC
    ioc = IOCRecord(
        indicator_value="scam-lottery.example",
        raw_value="scam-lottery.example",
        indicator_type="domain",
        threat_category="scam",
        report_count=1,
    )
    db_session.add(ioc)
    db_session.commit()
    initial_ioc_id = ioc.id

    payload = {
        "indicator": "scam-lottery.example",
        "indicator_type": "domain",
        "threat_type": "scam",
        "description": "Won a fake lucky draw prize",
        "evidence": "Received deceptive text message",
        "location": "Coimbatore",
    }

    result = create_report(payload, db=db_session)
    assert result.new_ioc is False
    assert result.ioc_id == initial_ioc_id
    assert result.report_count == 2


def test_report_count_increment(db_session):
    """3. Report count increments sequentially with each submission."""
    indicator = "fraud-telecom.example"

    r1 = create_report(
        {
            "indicator": indicator,
            "indicator_type": "domain",
            "threat_type": "phishing",
            "description": "Report 1 from resident A",
            "location": "Chennai",
        },
        db=db_session,
    )
    assert r1.report_count == 1

    r2 = create_report(
        {
            "indicator": indicator,
            "indicator_type": "domain",
            "threat_type": "phishing",
            "description": "Report 2 from resident B",
            "location": "Chennai",
        },
        db=db_session,
    )
    assert r2.report_count == 2
    assert r2.ioc_id == r1.ioc_id


def test_multiple_reports_for_same_ioc(db_session):
    """4. Multiple reports for the same IOC all link to the same parent IOC record."""
    indicator = "mule-collector@ybl"

    for i in range(3):
        create_report(
            {
                "indicator": indicator,
                "indicator_type": "upi_id",
                "threat_type": "fraud",
                "description": f"Incident {i + 1}: Demanded advance transfer",
                "location": "Madurai",
            },
            db=db_session,
        )

    reports = db_session.query(Report).all()
    assert len(reports) == 3

    # All reports must share the exact same ioc_id
    ioc_ids = {r.ioc_id for r in reports}
    assert len(ioc_ids) == 1

    # Associated IOC must have report_count == 3
    ioc = db_session.query(IOCRecord).filter(IOCRecord.id == list(ioc_ids)[0]).first()
    assert ioc.report_count == 3


def test_ioc_creation_through_report(db_session):
    """5. IOC creation through report verifies all fields in threat_iocs table."""
    payload = {
        "indicator": "http://kyc-urgent-update.com/verify",
        "indicator_type": "url",
        "threat_type": "kyc_scam",
        "description": "SMS link asking for KYC",
        "location": "Tiruchirappalli",
    }

    result = create_report(payload, db=db_session)
    ioc = db_session.query(IOCRecord).filter(IOCRecord.id == result.ioc_id).first()

    assert ioc is not None
    assert ioc.indicator_value == "http://kyc-urgent-update.com/verify"
    assert ioc.indicator_type == "url"
    assert ioc.threat_category == "kyc_scam"
    assert ioc.report_count == 1
    assert ioc.last_seen is not None


# ==============================================================================
# 6-10. Privacy Masking Tests
# ==============================================================================


def test_privacy_masking_general():
    """6. Privacy masking masks cards and bank accounts."""
    text = "Entered card 4111-2222-3333-4444 and money taken from account: 987654321098."
    masked = mask_sensitive_data(text)
    assert "[CARD_REDACTED]" in masked
    assert "4111-2222-3333-4444" not in masked
    assert "[ACCOUNT_REDACTED]" in masked
    assert "987654321098" not in masked


def test_phone_masking():
    """7. Phone masking transforms numbers to [PHONE_REDACTED]."""
    text = "Scammer asked me to call 9876543210 immediately."
    masked = mask_sensitive_data(text)
    assert "[PHONE_REDACTED]" in masked
    assert "9876543210" not in masked


def test_email_masking():
    """8. Email masking transforms emails to [EMAIL_REDACTED]."""
    text = "Sent complaint to customer support at test@gmail.com for refund."
    masked = mask_sensitive_data(text)
    assert "[EMAIL_REDACTED]" in masked
    assert "test@gmail.com" not in masked


def test_otp_masking():
    """9. OTP masking converts 'OTP 482931' to 'OTP [OTP_REDACTED]'."""
    text = "Caller asked for verification code. I shared OTP 482931."
    masked = mask_sensitive_data(text)
    assert "OTP [OTP_REDACTED]" in masked
    assert "482931" not in masked


def test_ensure_actual_ioc_is_not_masked():
    """10. Actual IOC being reported is NOT masked in description or evidence."""
    # Domain indicator
    desc = "User visited fake-bank-a.example which cloned the real bank."
    masked = mask_sensitive_data(desc, preserve_indicator="fake-bank-a.example")
    assert "fake-bank-a.example" in masked

    # Phone indicator: when the scammer phone IS the IOC, it is kept searchable
    scammer_phone = "9876543210"
    victim_phone = "9123456789"
    narrative = f"Scammer called from {scammer_phone} to my phone {victim_phone}."
    masked_narrative = mask_sensitive_data(narrative, preserve_indicator=scammer_phone)

    assert scammer_phone in masked_narrative  # Scammer IOC preserved
    assert "[PHONE_REDACTED]" in masked_narrative  # Victim phone redacted
    assert victim_phone not in masked_narrative


# ==============================================================================
# 11-12. Input Validation Tests
# ==============================================================================


def test_invalid_indicator_type():
    """11. Invalid indicator type raises validation error."""
    with pytest.raises(ValidationError) as exc_info:
        ReportCreateRequest(
            indicator="unknown-target",
            indicator_type="satellite",  # Invalid type
            threat_type="phishing",
            description="Sample description",
        )
    assert "Invalid indicator_type 'satellite'" in str(exc_info.value)


def test_invalid_threat_type():
    """12. Invalid threat type raises validation error."""
    with pytest.raises(ValidationError) as exc_info:
        ReportCreateRequest(
            indicator="evil-target.example",
            indicator_type="domain",
            threat_type="super_threat",  # Invalid threat type
            description="Sample description",
        )
    assert "Invalid threat_type 'super_threat'" in str(exc_info.value)


# ==============================================================================
# 13. API Endpoint Tests
# ==============================================================================


def test_api_create_report_endpoint(test_client, db_session):
    """POST /api/v1/intelligence/report contract test."""
    payload = {
        "indicator": "fake-bank-a.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Fake banking verification page with OTP 482931",
        "evidence": "Requests personal credentials and phone 9876543210",
        "location": "Chennai",
    }

    response = test_client.post("/api/v1/intelligence/report", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert "report_id" in data
    assert "ioc_id" in data
    assert data["new_ioc"] is True
    assert data["report_count"] == 1

    # Verify report in database has masked sensitive details
    rep_id = data["report_id"]
    from app.intelligence.report_service import get_report_by_id

    rep = get_report_by_id(rep_id, db=db_session)
    assert rep is not None
    assert "[OTP_REDACTED]" in rep.description
    assert "[PHONE_REDACTED]" in rep.evidence
    assert "fake-bank-a.example" in payload["indicator"]


def test_api_invalid_request_handling(test_client):
    """Invalid payload returns HTTP 422 with validation errors."""
    payload = {
        "indicator": "bad-request.example",
        "indicator_type": "unsupported_type",
        "threat_type": "phishing",
        "description": "Test",
    }
    response = test_client.post("/api/v1/intelligence/report", json=payload)
    assert response.status_code in [400, 422]
