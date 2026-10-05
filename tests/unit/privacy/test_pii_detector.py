"""Unit tests for PII Detector and URL Extractor."""

import pytest

from backend.privacy.pii_detector import PIIDetector, validate_verhoeff
from backend.privacy.sanitizer import Sanitizer
from backend.privacy.url_extractor import URLExtractor


@pytest.fixture
def sanitizer():
    return Sanitizer()


@pytest.fixture
def pii_detector():
    return PIIDetector()


def test_verhoeff_checksum():
    """Verify Verhoeff checksum algorithm correctness."""
    # Valid Aadhaar example (Verhoeff valid)
    assert validate_verhoeff("219356178946") is True
    # Invalid checksum
    assert validate_verhoeff("219356178941") is False


def test_detect_phone_numbers_india_and_intl(sanitizer, pii_detector):
    """Test standard Indian mobile, landline, toll-free, and international phone detection."""
    msg = (
        "Call +91 9876543210 or 08765432109 or bare 9123456789. Toll-free 1800-123-4567. International +1-415-555-2671."
    )
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)
    phones = [e for e in entities if e.entity_type == "PHONE"]

    assert len(phones) >= 5
    # Verify toll-free metadata
    toll_free = [p for p in phones if p.metadata.get("is_toll_free") is True]
    assert len(toll_free) == 1
    assert "1800" in toll_free[0].original_value


def test_detect_email_vs_upi(sanitizer, pii_detector):
    """Distinguish UPI VPAs from normal email addresses."""
    msg = "Send money to rahul@okhdfcbank or 9876543210@paytm, or contact support@example.com."
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)

    upis = [e for e in entities if e.entity_type == "UPI"]
    emails = [e for e in entities if e.entity_type == "EMAIL"]

    assert len(upis) == 2
    assert any("okhdfcbank" in u.original_value for u in upis)
    assert any("paytm" in u.original_value for u in upis)
    assert len(emails) == 1
    assert "support@example.com" in emails[0].original_value


def test_detect_ifsc_and_pan(sanitizer, pii_detector):
    """Detect valid Indian IFSC codes and PAN numbers."""
    msg = "My IFSC is SBIN0001234 and PAN is ABCDE1234F."
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)

    ifscs = [e for e in entities if e.entity_type == "IFSC"]
    pans = [e for e in entities if e.entity_type == "PAN"]

    assert len(ifscs) == 1
    assert ifscs[0].original_value == "SBIN0001234"
    assert len(pans) == 1
    assert pans[0].original_value == "ABCDE1234F"


def test_detect_account_and_aadhaar(sanitizer, pii_detector):
    """Detect bank account numbers and Aadhaar cards with context."""
    msg = "Account number is 123456789012. Aadhaar card 2193 5617 8940 is linked."
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)

    accounts = [e for e in entities if e.entity_type == "ACCOUNT"]
    aadhaars = [e for e in entities if e.entity_type == "AADHAAR"]

    assert len(accounts) == 1
    assert accounts[0].original_value == "123456789012"
    assert len(aadhaars) == 1


def test_detect_otp_near_keyword(sanitizer, pii_detector):
    """Detect OTP digits near OTP keywords without falsely masking unrelated numbers."""
    msg = "Your OTP for login is 482931. Pay ₹500 before 10 PM."
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)

    otps = [e for e in entities if e.entity_type == "OTP"]
    assert len(otps) == 1
    assert otps[0].original_value == "482931"
    # Ensure ₹500 and 10 PM are not masked as OTP
    assert not any(e.original_value in ("500", "10") for e in entities)


def test_detect_person_name_with_denylist(sanitizer, pii_detector):
    """Identify real person names while honoring non-person denylist."""
    msg1 = "Hi Ravi, your order is ready."
    msg2 = "Dear Customer, please be advised."
    msg3 = "Hello Team, meeting at 3 PM."

    dual1 = sanitizer.sanitize(msg1)
    dual2 = sanitizer.sanitize(msg2)
    dual3 = sanitizer.sanitize(msg3)

    ent1 = pii_detector.detect(dual1)
    ent2 = pii_detector.detect(dual2)
    ent3 = pii_detector.detect(dual3)

    assert any(e.entity_type == "PERSON" and e.original_value == "Ravi" for e in ent1)
    assert not any(e.entity_type == "PERSON" for e in ent2)
    assert not any(e.entity_type == "PERSON" for e in ent3)


def test_url_extractor_security_heuristics():
    """Test URL extractor defanging, punycode, shorteners, and brand lookalikes."""
    extractor = URLExtractor()

    # 1. Official domain - not lookalike
    urls1 = extractor.extract_urls("Visit https://www.hdfcbank.com/login for details.")
    assert len(urls1) == 1
    meta1 = urls1[0][3]
    assert meta1.registrable_domain == "hdfcbank.com"
    assert meta1.brand_lookalike is False
    assert meta1.is_suspicious is False

    # 2. Brand lookalike with suspicious TLD
    urls2 = extractor.extract_urls("Click http://sbi-kyc-verify.top/update immediately.")
    assert len(urls2) == 1
    meta2 = urls2[0][3]
    assert meta2.brand_lookalike is True
    assert meta2.suspicious_tld is True
    assert meta2.is_suspicious is True

    # 3. Scheme-less shortener
    urls3 = extractor.extract_urls("Check bit.ly/3xY9kL today.")
    assert len(urls3) == 1
    meta3 = urls3[0][3]
    assert meta3.is_shortener is True
    assert meta3.is_suspicious is True

    # 4. Defanged hxxp and [.]
    urls4 = extractor.extract_urls("Download from hxxp://evil[.]com/app.apk now.")
    assert len(urls4) == 1
    meta4 = urls4[0][3]
    assert meta4.registrable_domain == "evil.com"


def test_priority_overlap_resolution(sanitizer, pii_detector):
    """Ensure URL wins over phone/token/email embedded in query string."""
    msg = "Visit https://fakebank.com/verify?phone=9876543210&user=ravi@gmail.com now."
    dual = sanitizer.sanitize(msg)
    entities = pii_detector.detect(dual)

    # The entire URL should be matched as URL, not broken into inner phone/email
    assert len(entities) == 1
    assert entities[0].entity_type == "URL"
