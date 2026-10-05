"""Tests for Punycode and homoglyph / mixed-script detection."""

from zenshield.models.schemas import SignalSeverity
from zenshield.services.punycode_homoglyph import PunycodeHomoglyphDetector, normalize_homoglyphs
from zenshield.services.url_normalizer import normalize_url


def test_normalize_homoglyphs():
    # Cyrillic 'а', 'е', 'о', 'р'
    cyrillic_str = "\u0430\u0440\u0440l\u0435"
    assert normalize_homoglyphs(cyrillic_str) == "apple"


def test_punycode_domain_detected():
    detector = PunycodeHomoglyphDetector()
    url = "http://xn--pple-43d.com"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any(s.name == "Punycode domain detected" for s in signals)


def test_mixed_script_domain_detected():
    detector = PunycodeHomoglyphDetector()
    # Cyrillic 'а' mixed with Latin 'pple.com'
    url = "http://\u0430pple.com"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any("Mixed-script" in s.name or "Homoglyph" in s.name for s in signals)


def test_homoglyph_brand_impersonation():
    detector = PunycodeHomoglyphDetector()
    # Cyrillic 'а' in apple
    url = "http://\u0430pple.com"
    norm = normalize_url(url)
    signals = detector.detect(norm)
    assert any("Homoglyph brand impersonation" in s.name for s in signals)
    target_sig = next(s for s in signals if "Homoglyph brand impersonation" in s.name)
    assert target_sig.severity == SignalSeverity.HIGH


def test_unicode_non_phishing_is_not_classified_as_malicious():
    detector = PunycodeHomoglyphDetector()
    # Legitimate German umlaut domain
    url = "http://xn--mchen-kva.de"  # müchen.de
    norm = normalize_url(url)
    signals = detector.detect(norm)
    # May produce Punycode signal (medium/low supporting info), but NO mixed-script or brand impersonation
    assert not any("brand impersonation" in s.name.lower() for s in signals)
    assert not any("mixed-script" in s.name.lower() for s in signals)
