"""Tests for the Central Risk Engine, scoring, classification, and safety."""

from unittest.mock import patch

import pytest

from zenshield.models.schemas import Classification, RiskLevel
from zenshield.services.reputation.local_sqlite import SQLiteReputationProvider
from zenshield.services.risk_engine import RiskEngine


@pytest.fixture
def risk_engine():
    provider = SQLiteReputationProvider(db_path=":memory:")
    return RiskEngine(reputation_provider=provider)


def test_engine_legitimate_urls(risk_engine):
    legitimate_urls = [
        "https://google.com",
        "https://github.com",
    ]
    for url in legitimate_urls:
        res = risk_engine.analyze(url)
        assert res.risk_score == 0
        assert res.risk_level == RiskLevel.LOW
        assert res.classification == Classification.SAFE
        assert res.confidence >= 0.90
        assert res.known_ioc is False
        assert len(res.signals) == 0
        assert res.recommendation == "No significant suspicious indicators were detected."


def test_engine_typosquatting_url(risk_engine):
    res = risk_engine.analyze("https://paypa1.com")
    assert res.risk_score >= 15
    assert res.known_ioc is False
    assert any(s.name == "Typosquatting" for s in res.signals)
    assert res.classification in (Classification.SUSPICIOUS, Classification.POTENTIAL_PHISHING)


def test_engine_punycode_url(risk_engine):
    res = risk_engine.analyze("http://xn--pple-43d.com")
    assert res.risk_score >= 25
    assert any("Punycode" in s.name or "Homoglyph" in s.name or "Mixed-script" in s.name for s in res.signals)
    assert res.classification in (Classification.SUSPICIOUS, Classification.POTENTIAL_PHISHING)


def test_engine_ip_url_with_login(risk_engine):
    res = risk_engine.analyze("http://192.168.1.1/login")
    assert res.risk_score >= 30
    assert res.risk_level == RiskLevel.CAUTION
    assert res.classification == Classification.SUSPICIOUS
    assert any(s.name == "Raw IP address hostname" for s in res.signals)
    assert any(s.name == "Credential-related path" for s in res.signals)


def test_engine_weak_isolated_signal_not_critical(risk_engine):
    # An isolated /login on an ordinary benign domain must NOT produce HIGH or CRITICAL
    res = risk_engine.analyze("https://example.com/login")
    assert res.risk_level == RiskLevel.LOW
    assert res.classification == Classification.LOW_RISK
    assert res.risk_score < 25
    assert res.recommendation == "Proceed with normal caution and verify the destination."


def test_engine_high_entropy_hostname(risk_engine):
    res = risk_engine.analyze("https://xkj19f8q2pmvz09a.com/dashboard")
    assert any(s.name == "High entropy hostname" for s in res.signals)
    # Entropy alone must never produce HIGH or CRITICAL
    assert res.risk_level == RiskLevel.LOW


def test_engine_unusually_long_url(risk_engine):
    long_path = "a" * 200
    res = risk_engine.analyze(f"https://example.com/{long_path}")
    assert any(s.name == "Unusually long URL" for s in res.signals)
    assert res.risk_level == RiskLevel.LOW


def test_engine_known_ioc(risk_engine):
    # evil-example.com is in seeded IOC database
    res = risk_engine.analyze("https://evil-example.com/login")
    assert res.known_ioc is True
    assert res.risk_score >= 75
    assert res.risk_level == RiskLevel.CRITICAL
    assert res.classification == Classification.KNOWN_MALICIOUS
    assert res.confidence >= 0.95
    assert "Do not open this link" in res.recommendation


def test_engine_unknown_ioc_still_analyzed_with_heuristics(risk_engine):
    # Not in IOC database, but contains suspicious heuristics
    url = "http://10.0.0.1/verify?token=xyz"
    res = risk_engine.analyze(url)
    assert res.known_ioc is False
    # Heuristics still ran!
    assert any(s.name == "Raw IP address hostname" for s in res.signals)
    assert any(s.name == "Credential-related path" for s in res.signals)
    assert res.classification == Classification.SUSPICIOUS


def test_engine_malformed_url_no_crash(risk_engine):
    res = risk_engine.analyze("http://[invalid:host")
    assert res.risk_score <= 10
    assert res.risk_level == RiskLevel.LOW
    assert res.known_ioc is False


def test_engine_url_without_scheme(risk_engine):
    res = risk_engine.analyze("paypa1.com/login")
    assert res.risk_score >= 25
    assert any(s.name == "Typosquatting" for s in res.signals)


def test_engine_static_safety_guarantee_never_fetches_url(risk_engine):
    """Verify that analyzing a URL NEVER opens a socket or HTTP connection to it."""
    with patch("socket.socket.connect") as mock_connect, patch("urllib.request.urlopen") as mock_urlopen:
        # Analyze a variety of URLs
        risk_engine.analyze("https://evil-example.com/malicious")
        risk_engine.analyze("http://192.168.1.1/exploit")
        risk_engine.analyze("https://paypa1.com/steal")

        # Verify no network connections were attempted
        mock_connect.assert_not_called()
        mock_urlopen.assert_not_called()
