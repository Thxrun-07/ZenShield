"""
Privacy Masking Module for RedFlag Cybersecurity Platform.

Scrubs sensitive Personally Identifiable Information (PII) from user-submitted
fraud reports before storage or public community broadcast.

Detects and masks:
- Aadhaar Numbers (12-digit format, spaced or unspaced)
- Credit / Debit Card Numbers (16-digit format with spaces/dashes)
- Indian PAN Cards (e.g., ABCDE1234F)
- OTPs / Verification Codes (4-6 digits in context)
- Bank Account Numbers (in victim context)
- Phone Numbers (while preserving known scammer indicators if specified)
- Email Addresses (while preserving known scammer indicators if specified)
"""

from __future__ import annotations

import re

# Regex patterns
RE_AADHAAR = re.compile(
    r"\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b"
)

RE_CARD = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
)

RE_PAN = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    re.IGNORECASE
)

RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

RE_PHONE = re.compile(
    r"(?:\+91[-\s]?)?[6-9]\d{9}\b|\b0[6-9]\d{9}\b"
)

# OTP context: 4-6 digit numeric code near words like otp, code, pin, verify, etc.
RE_OTP = re.compile(
    r"(?i)\b(?:otp|one[-\s]time[-\s]password|pin|verification\s*code|code)\s*(?:is|was|:|-)?\s*([0-9]{4,6})\b"
)

# Bank account context: digits preceded by words like "account", "a/c", "acct"
RE_ACCOUNT_CONTEXT = re.compile(
    r"(?i)\b(?:account(?:\s*no|\s*number)?|a/c(?:\s*no)?|acct(?:\s*no)?)\s*(?:is|was|:|-)?\s*([0-9]{9,18})\b"
)


def mask_report_text(
    text: str,
    preserve_values: list[str] | None = None
) -> tuple[str, dict[str, int]]:
    """
    Masks victim PII from text narrative while preserving specified scammer indicators.

    Args:
        text: Raw narrative description submitted by the user.
        preserve_values: List of indicator strings (e.g. suspect phone, suspect UPI)
                         that should NOT be masked because they represent the threat.

    Returns:
        tuple[masked_text, pii_detected_counts]
    """
    if not text:
        return "", {}

    counts: dict[str, int] = {
        "aadhaar": 0,
        "card": 0,
        "pan": 0,
        "otp": 0,
        "account": 0,
        "email": 0,
        "phone": 0,
    }

    # Normalize preserve_values for case-insensitive and stripped matching
    preserves = set()
    if preserve_values:
        for val in preserve_values:
            if val:
                val_clean = val.strip()
                preserves.add(val_clean.lower())
                # Also add digits-only for phone preservation
                digits = re.sub(r"[^\d]", "", val_clean)
                if len(digits) >= 10:
                    preserves.add(digits[-10:])

    masked = text

    # 1. Mask OTPs (contextual)
    def _mask_otp(match: re.Match) -> str:
        counts["otp"] += 1
        full_match = match.group(0)
        otp_digits = match.group(1)
        return full_match.replace(otp_digits, "[OTP_MASKED]")

    masked = RE_OTP.sub(_mask_otp, masked)

    # 2. Mask Bank Accounts in context
    def _mask_account(match: re.Match) -> str:
        acc_digits = match.group(1)
        if acc_digits.lower() in preserves:
            return match.group(0)
        counts["account"] += 1
        return match.group(0).replace(acc_digits, "[ACCOUNT_MASKED]")

    masked = RE_ACCOUNT_CONTEXT.sub(_mask_account, masked)

    # 3. Mask Debit/Credit Cards (16 digits, matched before 12-digit Aadhaar)
    def _mask_card(match: re.Match) -> str:
        val = match.group(0)
        digits = re.sub(r"[^\d]", "", val)
        if digits in preserves:
            return val
        counts["card"] += 1
        return "[CARD_MASKED]"

    masked = RE_CARD.sub(_mask_card, masked)

    # 4. Mask Aadhaar numbers (12 digits)
    def _mask_aadhaar(match: re.Match) -> str:
        val = match.group(0)
        digits = re.sub(r"[^\d]", "", val)
        if digits in preserves:
            return val
        counts["aadhaar"] += 1
        return "[AADHAAR_MASKED]"

    masked = RE_AADHAAR.sub(_mask_aadhaar, masked)

    # 5. Mask Indian PAN Cards
    def _mask_pan(match: re.Match) -> str:
        val = match.group(0)
        if val.lower() in preserves:
            return val
        counts["pan"] += 1
        return "[PAN_MASKED]"

    masked = RE_PAN.sub(_mask_pan, masked)

    # 6. Mask Email Addresses (if not in preserves)
    def _mask_email(match: re.Match) -> str:
        val = match.group(0)
        if val.lower() in preserves:
            return val
        counts["email"] += 1
        return "[EMAIL_MASKED]"

    masked = RE_EMAIL.sub(_mask_email, masked)

    # 7. Mask Phone numbers (if not in preserves)
    def _mask_phone(match: re.Match) -> str:
        val = match.group(0)
        digits = re.sub(r"[^\d]", "", val)
        last_10 = digits[-10:] if len(digits) >= 10 else digits
        if last_10 in preserves or val.lower() in preserves:
            return val
        counts["phone"] += 1
        return "[PHONE_MASKED]"

    masked = RE_PHONE.sub(_mask_phone, masked)

    # Clean zero counts for concise response
    detected = {k: v for k, v in counts.items() if v > 0}

    return masked, detected
