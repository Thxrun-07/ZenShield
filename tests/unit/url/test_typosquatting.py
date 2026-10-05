"""Tests for typosquatting detection and Damerau-Levenshtein distance."""

from zenshield.services.typosquatting import (
    TyposquattingDetector,
    damerau_levenshtein_distance,
    normalize_leetspeak,
)
from zenshield.services.url_normalizer import normalize_url


def test_damerau_levenshtein_distance_operations():
    # Substitution
    assert damerau_levenshtein_distance("paypa1", "paypal") == 1
    # Insertion
    assert damerau_levenshtein_distance("gooogle", "google") == 1
    # Deletion
    assert damerau_levenshtein_distance("gogle", "google") == 1
    # Transposition
    assert damerau_levenshtein_distance("goolge", "google") == 1
    # Exact match
    assert damerau_levenshtein_distance("microsoft", "microsoft") == 0


def test_normalize_leetspeak():
    assert normalize_leetspeak("micros0ft") == "microsoft"
    assert normalize_leetspeak("p@yp@1") == "paypal"
    assert normalize_leetspeak("g00gle") == "google"


def test_typosquatting_detected_examples():
    detector = TyposquattingDetector()
    cases = [
        ("https://paypa1.com", "paypal.com"),
        ("https://micros0ft-login.com", "microsoft.com"),
        ("https://g00gle-security.com", "google.com"),
        ("https://app1e.com", "apple.com"),
    ]
    for url, trusted in cases:
        norm = normalize_url(url)
        signals = detector.detect(norm)
        assert len(signals) > 0, f"Expected typosquatting signal for {url}"
        assert signals[0].name == "Typosquatting"
        assert trusted in signals[0].evidence


def test_legitimate_domains_not_flagged_as_typosquatting():
    detector = TyposquattingDetector()
    legitimate = [
        "https://google.com",
        "https://microsoft.com",
        "https://apple.com",
        "https://paypal.com",
        "https://github.com",
        "https://amazon.com",
        "https://netflix.com",
    ]
    for url in legitimate:
        norm = normalize_url(url)
        signals = detector.detect(norm)
        assert len(signals) == 0, f"Legitimate domain {url} was incorrectly flagged: {signals}"


def test_typosquatting_configurable_trusted_domains():
    custom_trusted = ["mycompany.internal"]
    detector = TyposquattingDetector(trusted_domains=custom_trusted)
    norm = normalize_url("https://myc0mpany.internal")
    signals = detector.detect(norm)
    assert len(signals) > 0
    assert "mycompany.internal" in signals[0].evidence
