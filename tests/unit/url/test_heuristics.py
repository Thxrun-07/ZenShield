"""Tests for static structural URL heuristics."""

from zenshield.services.heuristics import HeuristicDetector
from zenshield.services.url_normalizer import normalize_url


def test_heuristic_raw_ip_address():
    detector = HeuristicDetector()
    url = "http://192.168.1.1/login"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any(s.name == "Raw IP address hostname" for s in signals)
    assert any(s.name == "Credential-related path" for s in signals)


def test_heuristic_suspicious_tld():
    detector = HeuristicDetector(suspicious_tlds={".zip", ".top", ".xyz"})
    url = "https://security-update.zip/download"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any(s.name == "Suspicious TLD" for s in signals)


def test_heuristic_credential_path_intent():
    detector = HeuristicDetector()
    credential_paths = [
        "https://example.com/login",
        "https://example.com/signin",
        "https://example.com/verify",
        "https://example.com/verification",
        "https://example.com/account",
        "https://example.com/secure",
        "https://example.com/update",
        "https://example.com/kyc",
        "https://example.com/password",
        "https://example.com/otp",
    ]
    for u in credential_paths:
        norm = normalize_url(u)
        signals = detector.detect(norm)
        assert any(s.name == "Credential-related path" for s in signals), f"Failed for {u}"


def test_heuristic_financial_path_intent():
    detector = HeuristicDetector()
    financial_paths = [
        "https://example.com/payment",
        "https://example.com/refund",
        "https://example.com/wallet",
        "https://example.com/checkout",
    ]
    for u in financial_paths:
        norm = normalize_url(u)
        signals = detector.detect(norm)
        assert any(s.name == "Financial/payment intent" for s in signals), f"Failed for {u}"


def test_heuristic_excessive_subdomains():
    detector = HeuristicDetector()
    url = "https://a.b.c.d.example.com/path"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any(s.name == "Excessive subdomains" for s in signals)


def test_heuristic_excessive_hyphens():
    detector = HeuristicDetector()
    url = "https://my-secure-login-account-update.com"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any(s.name == "Excessive hyphens in hostname" for s in signals)


def test_heuristic_obfuscated_authority():
    detector = HeuristicDetector()
    url = "http://google.com@evil-phishing.com/login"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any(s.name == "Obfuscated URL with authority delimiter" for s in signals)


def test_heuristic_non_standard_port():
    detector = HeuristicDetector()
    url = "http://example.com:4444/admin"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any(s.name == "Non-standard port" for s in signals)
