"""Shared pytest fixtures for ZenShield integration and unit test suites."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import zenshield.db.database as db_module
from zenshield.db.database import Base, seed_default_iocs
from zenshield.main import app

# In-memory test SQLite engine using StaticPool so all connections share the same memory DB
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Rebind global SessionLocal to test_engine so all components (e.g. DatabaseReputationProvider) use test DB
db_module.engine = test_engine
db_module.SessionLocal.configure(bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create all database tables and seed default indicators for the test session."""
    Base.metadata.create_all(bind=test_engine)
    with TestingSessionLocal() as session:
        seed_default_iocs(session)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    """Provides a database session for direct test queries."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    """TestClient configured for integration tests."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
