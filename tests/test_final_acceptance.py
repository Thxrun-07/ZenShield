"""
Final Acceptance Test for RedFlag Intelligence Module (Part 3).

Executes the exact required acceptance workflow:
1. Submit a report for fake-bank-a.example
2. Use synthetic phone +91-9000000001
3. Submit another report for fake-bank-b.example
4. Check fake-bank-a.example -> known=True, report_count >= 1
5. Check an unknown domain unknown-example.example -> known=False, response must NOT say safe=True
6. Submit another report for fake-bank-a.example -> report_count increases
7. Verify all intelligence responses conform to integration contracts
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.intelligence.database import Base, get_db
from app.intelligence.router import router
from app.intelligence.reputation_service import (
    check_indicator,
    check_ioc,
    find_ioc,
    get_ioc,
    create_ioc,
)
from app.intelligence.report_service import create_report


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_client(db_session):
    app = FastAPI()
    app.include_router(router)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client


def test_final_acceptance_workflow_service(db_session):
    """Workflow execution via direct Python service functions."""

    # 1 & 2. Submit a report for fake-bank-a.example using synthetic phone +91-9000000001
    r1 = create_report({
        "indicator": "fake-bank-a.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Phishing portal pretending to be bank; asked to verify with synthetic caller +91-9000000001 and OTP 123456",
        "evidence": "Fake domain registered recently",
        "location": "Chennai"
    }, db=db_session)

    assert r1.new_ioc is True
    assert r1.report_count == 1

    # 3. Submit another report for fake-bank-b.example
    r2 = create_report({
        "indicator": "fake-bank-b.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Another fraudulent banking mirror",
        "evidence": "Cloned CSS and logos",
        "location": "Coimbatore"
    }, db=db_session)

    assert r2.new_ioc is True
    assert r2.report_count == 1

    # 4. Check fake-bank-a.example -> Expected: known=True, report_count >= 1
    chk_a = check_indicator(
        indicator="fake-bank-a.example",
        indicator_type="domain",
        db=db_session
    )
    assert chk_a.known is True
    assert chk_a.report_count >= 1
    assert chk_a.threat_type == "phishing"
    assert chk_a.confidence > 0.0

    # 5. Check an unknown domain: unknown-example.example -> Expected: known=False, NOT safe=True
    chk_unknown = check_indicator(
        indicator="unknown-example.example",
        indicator_type="domain",
        db=db_session
    )
    assert chk_unknown.known is False
    chk_dict = chk_unknown.model_dump()
    assert "safe" not in chk_dict  # CRITICAL: Never return safe=True

    # 6. Submit another report for fake-bank-a.example -> Expected: report_count increases
    r3 = create_report({
        "indicator": "fake-bank-a.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Additional complaint regarding same domain from another resident",
        "evidence": "URL received via SMS",
        "location": "Madurai"
    }, db=db_session)

    assert r3.new_ioc is False
    assert r3.report_count == 2

    # Verify updated check
    chk_a_updated = check_indicator(
        indicator="fake-bank-a.example",
        indicator_type="domain",
        db=db_session
    )
    assert chk_a_updated.known is True
    assert chk_a_updated.report_count == 2


def test_final_acceptance_workflow_api(test_client):
    """Workflow execution via HTTP API endpoints."""

    # 1 & 2. Submit report for fake-bank-a.example with synthetic phone
    res1 = test_client.post("/api/v1/intelligence/report", json={
        "indicator": "fake-bank-a.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Caller from +91-9000000001 instructed me to login and share OTP 987654",
        "evidence": "Credential harvesting form",
        "location": "Chennai"
    })
    assert res1.status_code == 201
    d1 = res1.json()
    assert d1["new_ioc"] is True
    assert d1["report_count"] == 1

    # 3. Submit report for fake-bank-b.example
    res2 = test_client.post("/api/v1/intelligence/report", json={
        "indicator": "fake-bank-b.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Another malicious clone",
        "evidence": "Fake login",
        "location": "Bengaluru"
    })
    assert res2.status_code == 201
    d2 = res2.json()
    assert d2["new_ioc"] is True
    assert d2["report_count"] == 1

    # 4. Check fake-bank-a.example -> known=True, report_count >= 1
    chk1 = test_client.get("/api/v1/intelligence/check?indicator=fake-bank-a.example&indicator_type=domain")
    assert chk1.status_code == 200
    chk1_data = chk1.json()
    assert chk1_data["known"] is True
    assert chk1_data["report_count"] >= 1
    assert "safe" not in chk1_data

    # 5. Check unknown domain -> known=False, does NOT say safe=True
    chk_unk = test_client.get("/api/v1/intelligence/check?indicator=unknown-example.example&indicator_type=domain")
    assert chk_unk.status_code == 200
    unk_data = chk_unk.json()
    assert unk_data["known"] is False
    assert "safe" not in unk_data
    assert "message" in unk_data

    # 6. Submit another report for fake-bank-a.example -> report_count increases
    res3 = test_client.post("/api/v1/intelligence/report", json={
        "indicator": "fake-bank-a.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Second report from another resident",
        "location": "Chennai"
    })
    assert res3.status_code == 201
    d3 = res3.json()
    assert d3["new_ioc"] is False
    assert d3["report_count"] == 2

    # Check again via API
    chk2 = test_client.get("/api/v1/intelligence/check?indicator=fake-bank-a.example&indicator_type=domain")
    assert chk2.status_code == 200
    assert chk2.json()["report_count"] == 2


def test_stable_service_functions(db_session):
    """Validates the stability of all required service functions."""
    # create_ioc()
    ioc = create_ioc(
        indicator="test-threat.example",
        indicator_type="domain",
        threat_type="phishing",
        db=db_session
    )
    assert ioc.id is not None

    # find_ioc()
    found = find_ioc("test-threat.example", "domain", db=db_session)
    assert found is not None
    assert found.id == ioc.id

    # get_ioc()
    by_id = get_ioc(ioc.id, db=db_session)
    assert by_id is not None
    assert by_id.indicator_value == "test-threat.example"

    # check_ioc() / check_indicator()
    checked = check_ioc("test-threat.example", "domain", db=db_session)
    assert checked.known is True

    # create_report()
    rep = create_report({
        "indicator": "test-threat.example",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "description": "Validating stable create_report function",
        "location": "Chennai"
    }, db=db_session)
    assert rep.new_ioc is False
    assert rep.report_count == 2
