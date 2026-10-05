"""Tests for brand and domain impersonation detection."""

from zenshield.services.brand_impersonation import BrandImpersonationDetector
from zenshield.services.url_normalizer import normalize_url


def test_brand_in_subdomain_of_unrelated_domain():
    detector = BrandImpersonationDetector()
    url = "https://paypal.security-example.com/login"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any(s.name == "Brand impersonation in subdomain" for s in signals)
    target = next(s for s in signals if s.name == "Brand impersonation in subdomain")
    assert "paypal" in target.evidence.lower()
    assert "security-example.com" in target.evidence.lower()


def test_brand_combined_with_lure_in_registered_domain():
    detector = BrandImpersonationDetector()
    url = "https://apple-support-recovery.com/verify"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any("Brand impersonation" in s.name for s in signals)


def test_legitimate_brand_domains_not_flagged():
    detector = BrandImpersonationDetector()
    legitimate_urls = [
        "https://www.paypal.com/signin",
        "https://login.microsoft.com",
        "https://support.apple.com/kb",
        "https://accounts.google.com/signin",
        "https://aws.amazon.com/console",
    ]
    for u in legitimate_urls:
        norm = normalize_url(u)
        signals = detector.detect(norm)
        assert len(signals) == 0, f"Legitimate brand URL {u} was flagged: {signals}"


def test_brand_keyword_in_path_not_flagged_as_impersonation():
    detector = BrandImpersonationDetector()
    # Brand appears in path or query on benign website
    url = "https://techblog.com/articles/how-to-use-paypal-safely?ref=google"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert len(signals) == 0, f"Path keyword caused false positive on {url}: {signals}"
