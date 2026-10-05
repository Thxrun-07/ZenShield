"""
Unit and Integration Tests for RedFlag Intelligence Service Layer.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.intelligence import service
from app.intelligence.database import Base
from app.intelligence.schemas import (
    CommunityReportCreate,
    IOCCreate,
    ReportConfirmationCreate,
)


@pytest.fixture
def db_session():
    """
    Creates an isolated in-memory SQLite database for testing service methods.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_lookup_unknown_ioc(db_session):
    resp = service.lookup_ioc_reputation("https://innocent-site.com", db=db_session)
    assert resp.is_known_threat is False
    assert resp.threat_level == "safe"
    assert resp.risk_score == 0.0
    assert resp.report_count == 0


def test_submit_report_and_lookup(db_session):
    # Submit a community report about a fake electricity bill scam
    report_in = CommunityReportCreate(
        indicator_value="9876543210",
        indicator_type="phone",
        title="TNEB Electricity Bill Phishing",
        description="Caller claiming power will be cut tonight unless I send money to electricity bill link. My OTP was 123456.",
        region="Tamil Nadu",
        fraud_category="Electricity Bill Scam",
        amount_lost=1500.0,
    )

    created_report = service.submit_community_report(report_in, db=db_session)
    assert created_report.id is not None
    assert created_report.indicator_value == "+919876543210"
    assert "[OTP_MASKED]" in created_report.description
    assert "123456" not in created_report.description
    assert created_report.raw_description_had_pii is True

    # Now look up reputation using raw or unformatted phone number
    reputation = service.lookup_ioc_reputation("9876543210", db=db_session)
    assert reputation.is_known_threat is True
    assert reputation.indicator_value == "+919876543210"
    assert reputation.threat_level in ["medium", "high", "critical"]
    assert reputation.report_count == 1
    assert "Electricity Bill Scam" in reputation.categories
    assert "Tamil Nadu" in reputation.regions_affected
    assert len(reputation.recent_incidents) == 1


def test_confirm_community_report(db_session):
    report_in = CommunityReportCreate(
        indicator_value="scammer@okhdfcbank",
        title="Fake Job Offer Registration Fee",
        description="Asked for 5000 INR registration fee on Telegram.",
        region="Chennai",
        fraud_category="Part-Time Job Scam",
        amount_lost=5000.0,
    )
    report = service.submit_community_report(report_in, db=db_session)

    # Confirm report
    conf_in = ReportConfirmationCreate(comment="Same happened to my friend yesterday in Chennai.", region="Chennai")
    conf_resp = service.confirm_community_report(report.id, conf_in, db=db_session)
    assert conf_resp.new_confirmation_count == 1

    # Verify updated reputation score
    reputation = service.lookup_ioc_reputation("scammer@okhdfcbank", db=db_session)
    assert reputation.confirmation_count == 1
    assert reputation.risk_score > 30.0


def test_direct_ioc_registration(db_session):
    ioc_in = IOCCreate(
        indicator_value="sbi-kyc-verify-alert.com",
        indicator_type="domain",
        threat_category="KYC Phishing",
        threat_level="high",
        notes="Reported by CERT-In advisory",
    )
    ioc = service.register_or_update_ioc(ioc_in, db=db_session)
    assert ioc.id is not None
    assert ioc.indicator_value == "sbi-kyc-verify-alert.com"
    assert ioc.threat_level == "high"

    # URL matching root domain fallback
    rep = service.lookup_ioc_reputation("http://sbi-kyc-verify-alert.com/login.php", db=db_session)
    assert rep.is_known_threat is True
    assert "sbi-kyc-verify-alert.com" in rep.indicator_value or rep.threat_level == "high"


def test_regional_alerts(db_session):
    # Add reports in Tamil Nadu
    service.submit_community_report(
        CommunityReportCreate(
            indicator_value="9191919191",
            title="Loan App Harassment",
            description="Fake instantaneous loan app asking for contacts.",
            region="Tamil Nadu",
            fraud_category="Instant Loan Scam",
            amount_lost=20000.0,
        ),
        db=db_session,
    )
    service.submit_community_report(
        CommunityReportCreate(
            indicator_value="fraud@ybl",
            title="Electricity Payment Fraud",
            description="Fake bill notice in Tamil.",
            region="Tamil Nadu",
            fraud_category="Electricity Bill Scam",
            amount_lost=4000.0,
        ),
        db=db_session,
    )

    alerts = service.get_regional_alerts(region="Tamil Nadu", db=db_session)
    assert alerts.total_reports == 2
    assert alerts.total_financial_loss == 24000.0
    assert len(alerts.top_categories) >= 1
    assert len(alerts.trending_iocs) == 2
