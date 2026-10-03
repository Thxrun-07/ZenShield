"""Tests for Shannon entropy calculation and randomized string detection."""

import pytest
from zenshield.services.entropy import EntropyAnalyzer, calculate_shannon_entropy
from zenshield.services.url_normalizer import normalize_url


def test_shannon_entropy_calculation():
    # Empty string
    assert calculate_shannon_entropy("") == 0.0
    # Single character (all identical -> 0 entropy)
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # High randomness
    assert calculate_shannon_entropy("1a2b3c4d5e6f7g8h") > 3.5


def test_high_entropy_randomized_domain():
    analyzer = EntropyAnalyzer(hostname_threshold=3.5, min_length=8)
    url = "https://xkj19f8q2pmvz09a.com/login"
    norm = normalize_url(url)
    signals = analyzer.detect(norm)
    assert any(s.name == "High entropy hostname" for s in signals)
    target = next(s for s in signals if s.name == "High entropy hostname")
    assert "entropy" in target.evidence.lower()


def test_normal_domains_have_low_entropy():
    analyzer = EntropyAnalyzer(hostname_threshold=3.8, min_length=8)
    urls = [
        "https://google.com",
        "https://github.com",
        "https://paypal.com",
        "https://microsoft.com",
    ]
    for u in urls:
        norm = normalize_url(u)
        signals = analyzer.detect(norm)
        assert len(signals) == 0, f"Expected 0 entropy signals for normal domain {u}"
