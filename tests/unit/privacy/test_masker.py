"""Unit and property tests for Masker and Privacy Canary validation."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from backend.privacy.masker import Masker
from backend.privacy.pii_detector import PIIDetector
from backend.privacy.sanitizer import Sanitizer


@pytest.fixture
def sanitizer():
    return Sanitizer()


@pytest.fixture
def pii_detector():
    return PIIDetector()


@pytest.fixture
def masker():
    return Masker()


def test_masking_comprehensive_example(sanitizer, pii_detector, masker):
    """Test full masking flow with multiple entity types."""
    msg = "Hi Ravi, your OTP is 482931. Call 9876543210 or email ravi@example.com."
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)
    res = masker.mask(dual.canonical_text, entities)

    assert "482931" not in res.masked_text
    assert "9876543210" not in res.masked_text
    assert "ravi@example.com" not in res.masked_text
    assert "Ravi" not in res.masked_text

    assert "PERSON_01" in res.masked_text
    assert "[OTP_REDACTED]" in res.masked_text
    assert "[PHONE_REDACTED]" in res.masked_text
    assert "[EMAIL_REDACTED]" in res.masked_text

    # Security keywords must remain intact
    assert "OTP" in res.masked_text
    assert "Call" in res.masked_text


def test_deterministic_person_counter(sanitizer, pii_detector, masker):
    """Same person name gets same placeholder, new name gets incremented placeholder."""
    msg = "Hi Ravi, please meet Dear Priya. And Hi Ravi again."
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)
    res = masker.mask(dual.canonical_text, entities)

    assert "PERSON_01" in res.masked_text
    assert "PERSON_02" in res.masked_text
    # Should only have 01 and 02
    assert "PERSON_03" not in res.masked_text
    assert res.masked_entity_counts.get("PERSON") == 3


def test_privacy_canary_zero_leakage(sanitizer, pii_detector, masker):
    """Privacy canary: verify raw PII is absent from masked text and repr."""
    canary_phone = "9840198401"
    canary_otp = "736192"
    canary_email = "canary_user_secret@zenshield.internal"

    msg = f"Canary alert: OTP {canary_otp} sent to {canary_phone} and {canary_email}."
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)
    res = masker.mask(dual.canonical_text, entities)

    # 1. Check masked string
    assert canary_phone not in res.masked_text
    assert canary_otp not in res.masked_text
    assert canary_email not in res.masked_text

    # 2. Check __repr__ of all entities
    for ent in entities:
        ent_repr = repr(ent)
        assert canary_phone not in ent_repr
        assert canary_otp not in ent_repr
        assert canary_email not in ent_repr
        assert "[REDACTED]" in ent_repr


def test_attacker_supplied_placeholder_escaping(sanitizer):
    """Attacker-supplied literal placeholders are escaped to prevent spoofing."""
    msg = "Malicious attack with [OTP_REDACTED] and PERSON_01 injection."
    dual = sanitizer.sanitize(msg)

    assert r"\[OTP_REDACTED]" in dual.canonical_text
    assert r"\PERSON_01" in dual.canonical_text


@given(st.text(min_size=1, max_size=500))
def test_masker_property_stability(message_text):
    """Property test: Sanitizer and Masker should never raise unhandled exceptions on valid text."""
    sanitizer = Sanitizer()
    detector = PIIDetector()
    masker = Masker()

    try:
        dual = sanitizer.sanitize(message_text)
        entities = detector.detect(dual)
        res = masker.mask(dual.canonical_text, entities)
        assert isinstance(res.masked_text, str)
    except ValueError:
        # Expected for empty or whitespace-only strings
        pass
