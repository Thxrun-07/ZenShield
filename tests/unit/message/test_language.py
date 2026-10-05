"""Unit tests for Multilingual and Tanglish language detection."""

import pytest

from backend.message.language import LanguageDetector, canonicalize_tanglish_token


@pytest.fixture
def language_detector():
    return LanguageDetector()


def test_canonicalize_tanglish_token():
    """Verify algorithmic canonicalization collapses digraphs, repeats, and terminal noise."""
    assert canonicalize_tanglish_token("pannunga") == "panunga"
    assert canonicalize_tanglish_token("panunga") == "panunga"
    assert canonicalize_tanglish_token("seekiram") == "sikiram"
    assert canonicalize_tanglish_token("seiyavum") == "seiyavum"
    assert canonicalize_tanglish_token("kooda") == "kuda"


def test_detect_pure_english(language_detector):
    """Detect predominantly English text."""
    msg = "Your account will be blocked. Verify now to prevent disruption."
    res = language_detector.detect(msg)
    assert res.language == "English"
    assert res.script == "Latin"
    assert res.is_mixed is False
    assert res.confidence >= 0.90


def test_detect_pure_tamil_unicode(language_detector):
    """Detect Tamil Unicode script."""
    msg = "உங்கள் கணக்கு முடக்கப்படும். உடனே சரிபார்க்கவும்."
    res = language_detector.detect(msg)
    assert res.language == "Tamil"
    assert res.script == "Tamil"
    assert res.is_mixed is False
    assert res.confidence >= 0.85


def test_detect_tanglish(language_detector):
    """Detect Tanglish text with characteristic Tamil verbs and nouns in Latin script."""
    msg = "Ungal account block aagum. Ippove verify pannunga."
    res = language_detector.detect(msg)
    assert res.language == "Tanglish"
    assert res.script == "Latin"
    assert res.is_mixed is False
    assert res.confidence >= 0.70
    assert any("panunga" in ind for ind in res.indicators)


def test_detect_tanglish_spelling_variants(language_detector):
    """Test resilience against colloquial Tanglish spelling variations."""
    # panunga instead of pannunga, udane instead of ippove, kudunga instead of kuduthu
    msg = "Unga OTP udane anuppunga, illana account block aagidum."
    res = language_detector.detect(msg)
    assert res.language == "Tanglish"
    assert res.script == "Latin"


def test_detect_mixed_script(language_detector):
    """Detect mixed text where Tamil Unicode and English/Latin meaningfully co-occur."""
    msg = "உங்கள் account block ஆகும். Verify now."
    res = language_detector.detect(msg)
    assert res.language == "Mixed"
    assert res.script == "Mixed"
    assert res.is_mixed is True


def test_empty_and_numeric_text(language_detector):
    """Detect unknown for empty or non-alphabetic strings."""
    assert language_detector.detect("").language == "Unknown"
    assert language_detector.detect("   ").language == "Unknown"
    assert language_detector.detect("1234567890 9876543210").language == "Unknown"
