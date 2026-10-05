"""
Privacy Masking Module for Community Fraud Reporting.

Scrubs sensitive personal information from descriptions and evidence:
- Phone numbers -> [PHONE_REDACTED]
- Email addresses -> [EMAIL_REDACTED]
- OTP codes -> [OTP_REDACTED] (e.g. "OTP 482931" -> "OTP [OTP_REDACTED]")
- Card numbers -> [CARD_REDACTED]
- Bank account numbers -> [ACCOUNT_REDACTED]

IMPORTANT:
The actual IOC being reported (passed in preserve_indicator) is preserved
and NOT redacted, ensuring indicators remain searchable in threat intelligence.
"""

from __future__ import annotations

import re

# Regex patterns
RE_CARD = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")

# Contextual OTP: e.g. "OTP 482931", "code: 123456", "PIN 4455"
RE_OTP = re.compile(
    r"(?i)\b(otp|one[-\s]time[-\s]password|pin|verification\s*code|code)\s*(?:is|was|:|-)?\s*([0-9]{4,8})\b"
)

# Bank account in context: "account no: 123456789012", "a/c: 987654321"
RE_ACCOUNT_CONTEXT = re.compile(
    r"(?i)\b(account(?:\s*no|\s*number)?|a/c(?:\s*no)?|acct(?:\s*no)?)\s*(?:is|was|:|-)?\s*([0-9]{9,18})\b"
)

# Email pattern
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Phone pattern: 10 digits starting with 6-9, or +91 / 0 prefixed
RE_PHONE = re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b|\b0[6-9]\d{9}\b|\b[6-9]\d{9}\b")


def _build_preserves(preserve_indicator: str | None) -> set[str]:
    """Helper to build lowercase and digit-only variants of indicator to protect from masking."""
    preserves = set()
    if preserve_indicator:
        clean = preserve_indicator.strip().lower()
        if clean:
            preserves.add(clean)
            digits = re.sub(r"[^\d]", "", clean)
            if len(digits) >= 10:
                preserves.add(digits[-10:])
                preserves.add(digits)
    return preserves


def mask_sensitive_data(text: str | None, preserve_indicator: str | None = None) -> str:
    """
    Detects and masks obvious sensitive information from description and evidence.

    Args:
        text: Input string (e.g., report description or evidence text).
        preserve_indicator: The target threat indicator that must remain intact.

    Returns:
        Redacted string with sensitive information masked.
    """
    if not text:
        return ""

    preserves = _build_preserves(preserve_indicator)
    masked = text

    # 1. Mask OTP (preserves the prefix keyword and redacts the numeric code)
    def _mask_otp_match(m: re.Match) -> str:
        m.group(1)
        code = m.group(2)
        if code in preserves:
            return m.group(0)
        # Check original match to see whether separator was present
        matched_str = m.group(0)
        # Replace the numeric code with [OTP_REDACTED]
        return matched_str.replace(code, "[OTP_REDACTED]")

    masked = RE_OTP.sub(_mask_otp_match, masked)

    # 2. Mask Bank Account numbers in context
    def _mask_account_match(m: re.Match) -> str:
        acc_digits = m.group(2)
        if acc_digits in preserves:
            return m.group(0)
        matched_str = m.group(0)
        return matched_str.replace(acc_digits, "[ACCOUNT_REDACTED]")

    masked = RE_ACCOUNT_CONTEXT.sub(_mask_account_match, masked)

    # 3. Mask Credit/Debit Card numbers (16 digits)
    def _mask_card_match(m: re.Match) -> str:
        val = m.group(0)
        digits = re.sub(r"[^\d]", "", val)
        if digits in preserves:
            return val
        return "[CARD_REDACTED]"

    masked = RE_CARD.sub(_mask_card_match, masked)

    # 4. Mask Email addresses (unless it is the reported IOC)
    def _mask_email_match(m: re.Match) -> str:
        val = m.group(0)
        if val.lower() in preserves:
            return val
        return "[EMAIL_REDACTED]"

    masked = RE_EMAIL.sub(_mask_email_match, masked)

    # 5. Mask Phone numbers (unless it is the reported IOC)
    def _mask_phone_match(m: re.Match) -> str:
        val = m.group(0)
        digits = re.sub(r"[^\d]", "", val)
        last_10 = digits[-10:] if len(digits) >= 10 else digits
        if last_10 in preserves or val.lower() in preserves:
            return val
        return "[PHONE_REDACTED]"

    masked = RE_PHONE.sub(_mask_phone_match, masked)

    return masked
