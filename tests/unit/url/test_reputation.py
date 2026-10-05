"""Tests for SQLite reputation provider and IOC management."""

from zenshield.models.schemas import SignalSeverity
from zenshield.services.reputation.local_sqlite import SQLiteReputationProvider
from zenshield.services.url_normalizer import normalize_url


def test_reputation_default_seeded_iocs():
    provider = SQLiteReputationProvider(db_path=":memory:")
    # evil-example.com is seeded by default
    norm = normalize_url("https://evil-example.com/login")
    result = provider.check(norm)
    assert result.is_known_ioc is True
    assert result.indicator == "evil-example.com"
    assert result.source == "community"
    assert result.severity == SignalSeverity.CRITICAL


def test_reputation_add_and_query_custom_ioc():
    provider = SQLiteReputationProvider(db_path=":memory:")
    # Add new domain indicator
    provider.add_ioc(
        indicator="phishing-attack-domain.test",
        indicator_type="domain",
        source="internal_cert",
        severity="high",
        description="Targeted credential phishing",
    )

    norm = normalize_url("http://sub.phishing-attack-domain.test/auth")
    result = provider.check(norm)
    assert result.is_known_ioc is True
    assert result.indicator == "phishing-attack-domain.test"
    assert result.source == "internal_cert"
    assert result.severity == SignalSeverity.HIGH


def test_reputation_unknown_domain_returns_not_ioc():
    provider = SQLiteReputationProvider(db_path=":memory:")
    norm = normalize_url("https://safe-domain.example.com")
    result = provider.check(norm)
    assert result.is_known_ioc is False
    assert result.indicator is None


def test_reputation_url_specific_ioc():
    provider = SQLiteReputationProvider(db_path=":memory:")
    target_url = "http://bad-host.test/stealer.bin"
    provider.add_ioc(
        indicator=target_url,
        indicator_type="url",
        source="abuse_ch",
        severity="critical",
        description="Malware executable payload",
    )

    norm = normalize_url(target_url)
    result = provider.check(norm)
    assert result.is_known_ioc is True
    assert result.indicator_type == "url"
    assert result.severity == SignalSeverity.CRITICAL
