"""Pytest configuration and shared test fixtures."""

import pytest
from fastapi.testclient import TestClient

from zenshield.api.v1.endpoints.url_verify import get_risk_engine
from zenshield.main import app
from zenshield.services.reputation.local_sqlite import SQLiteReputationProvider
from zenshield.services.risk_engine import RiskEngine


@pytest.fixture
def memory_reputation_provider():
    """In-memory SQLite reputation provider for fast, isolated tests."""
    return SQLiteReputationProvider(db_path=":memory:")


@pytest.fixture
def test_risk_engine(memory_reputation_provider):
    """RiskEngine configured with in-memory SQLite reputation database."""
    return RiskEngine(reputation_provider=memory_reputation_provider)


@pytest.fixture
def client(test_risk_engine):
    """TestClient with overridden risk engine dependency."""
    app.dependency_overrides[get_risk_engine] = lambda: test_risk_engine
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
