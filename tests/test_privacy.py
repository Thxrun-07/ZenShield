"""
Tests for RedFlag Privacy Masking Module.
"""

from app.intelligence.privacy import mask_report_text


def test_mask_aadhaar():
    text = "The fraudster asked for my Aadhaar number 4589 1234 5678 to update KYC."
    masked, counts = mask_report_text(text)
    assert "[AADHAAR_MASKED]" in masked
    assert "4589 1234 5678" not in masked
    assert counts.get("aadhaar") == 1


def test_mask_card_number():
    text = "I entered my debit card 4111 2222 3333 4444 on the phishing website."
    masked, counts = mask_report_text(text)
    assert "[CARD_MASKED]" in masked
    assert "4111 2222 3333 4444" not in masked
    assert counts.get("card") == 1


def test_mask_pan_card():
    text = "They claimed my account will freeze without PAN ABCDE1234F update."
    masked, counts = mask_report_text(text)
    assert "[PAN_MASKED]" in masked
    assert "ABCDE1234F" not in masked
    assert counts.get("pan") == 1


def test_mask_otp():
    text = "A caller told me to share the OTP. My OTP was 482910."
    masked, counts = mask_report_text(text)
    assert "[OTP_MASKED]" in masked
    assert "482910" not in masked
    assert counts.get("otp") == 1


def test_mask_account_number():
    text = "Money was siphoned from my account no: 987654321098."
    masked, counts = mask_report_text(text)
    assert "[ACCOUNT_MASKED]" in masked
    assert "987654321098" not in masked
    assert counts.get("account") == 1


def test_preserve_scammer_indicator():
    # In this scenario:
    # 9876543210 is the scammer phone number to preserve
    # 9123456780 is the victim phone number that should be masked
    text = "Scammer called from 9876543210. They reached my personal number 9123456780."
    masked, counts = mask_report_text(text, preserve_values=["9876543210"])

    assert "9876543210" in masked  # Preserved!
    assert "[PHONE_MASKED]" in masked  # Victim's personal number masked
    assert "9123456780" not in masked
    assert counts.get("phone") == 1
