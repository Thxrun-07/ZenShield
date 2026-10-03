"""
Indicator Normalization Module for RedFlag Cybersecurity Platform.

Standardizes indicators of compromise (IOCs) such as:
- URLs
- Domains
- Phone numbers (Indian & International)
- UPI IDs (Google Pay, PhonePe, Paytm, BHIM, etc.)
- Email addresses
- Bank account numbers

Ensures that indicators reported in different formats (e.g., +91 98765 43210 vs 09876543210)
map to the same canonical indicator in the IOC registry.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Common tracking parameters to strip during URL normalization
TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "msclkid",
    "ref",
    "source",
}

# Regex for common indicator types
RE_EMAIL = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)
RE_UPI = re.compile(
    r"^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9]{2,}$"
)
RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
RE_IFSC = re.compile(
    r"^[A-Z]{4}0[A-Z0-9]{6}$"
)


def detect_indicator_type(raw_value: str) -> str:
    """
    Intelligently infer indicator type from the raw string.
    Returns one of: 'phone', 'upi_id', 'email', 'url', 'domain', 'bank_account', 'other'.
    """
    if not raw_value or not isinstance(raw_value, str):
        return "other"

    val = raw_value.strip()

    # 1. URL with explicit protocol
    if val.lower().startswith(("http://", "https://", "ftp://")):
        return "url"

    # 2. Contains @ -> could be Email or UPI ID
    if "@" in val:
        domain_part = val.split("@")[-1].strip()
        if "." in domain_part:
            return "email"
        else:
            return "upi_id"

    # 3. Clean numeric check for Phone or Bank Account
    cleaned_digits = re.sub(r"[^\d]", "", val)
    has_plus = val.startswith("+")

    # Indian phone number patterns (10 digits starting with 6-9, or +91/0 prefixed)
    if has_plus:
        if 10 <= len(cleaned_digits) <= 15:
            return "phone"

    if val.startswith("0") and len(cleaned_digits) == 11 and cleaned_digits[1] in "6789":
        return "phone"

    if len(cleaned_digits) == 12 and cleaned_digits.startswith("91") and cleaned_digits[2] in "6789":
        return "phone"

    if len(cleaned_digits) == 10 and cleaned_digits[0] in "6789":
        return "phone"

    # Bank account format: account:IFSC or pure account digits (9-18 digits not matching phone)
    if ":" in val:
        parts = val.split(":")
        if len(parts) == 2 and RE_IFSC.match(parts[1].upper()):
            return "bank_account"

    if cleaned_digits.isdigit() and 9 <= len(cleaned_digits) <= 18:
        # If it wasn't caught as phone above, treat as bank account
        return "bank_account"

    # 4. Domain or URL without protocol
    if "/" in val:
        # Has slashes -> likely URL without scheme
        first_part = val.split("/")[0].split(":")[0]
        if RE_DOMAIN.match(first_part.lower()):
            return "url"

    # Pure domain check
    val_clean = val.lower().rstrip("/")
    if val_clean.startswith("www."):
        val_clean = val_clean[4:]
    if RE_DOMAIN.match(val_clean):
        return "domain"

    return "other"


def normalize_phone(val: str) -> str:
    """
    Normalizes Indian and international phone numbers to E.164-like standard (+91XXXXXXXXXX).
    """
    raw = val.strip()
    digits = re.sub(r"[^\d]", "", raw)

    # 10 digits starting with 6-9 -> assume Indian mobile (+91)
    if len(digits) == 10 and digits[0] in "6789":
        return f"+91{digits}"

    # 11 digits starting with 0 followed by 6-9 -> Indian mobile (+91)
    if len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
        return f"+91{digits[1:]}"

    # 12 digits starting with 91 followed by 6-9 -> Indian mobile (+91)
    if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
        return f"+{digits}"

    # Already has leading + in original string
    if raw.startswith("+"):
        return f"+{digits}"

    # Default fallback
    return f"+{digits}" if digits else raw


def normalize_upi(val: str) -> str:
    """
    Normalizes UPI handles (e.g. 'Scammer@OkHdfcBank ' -> 'scammer@okhdfcbank').
    """
    return val.strip().lower()


def normalize_email(val: str) -> str:
    """
    Normalizes email addresses to lowercase without whitespace.
    """
    return val.strip().lower()


def normalize_domain(val: str) -> str:
    """
    Normalizes domain names:
    - strips protocol if mistakenly provided
    - strips 'www.'
    - removes path, query, and ports
    - converts to lowercase
    """
    d = val.strip().lower()
    if d.startswith("http://"):
        d = d[7:]
    elif d.startswith("https://"):
        d = d[8:]

    # Remove port or path if present
    d = d.split("/")[0]
    d = d.split(":")[0]

    if d.startswith("www."):
        d = d[4:]

    return d.rstrip(".")


def normalize_url(val: str, strip_tracking: bool = True) -> str:
    """
    Normalizes URLs:
    - ensures http/https scheme
    - lowercases scheme and netloc
    - strips default ports
    - removes trailing slash if path is only '/'
    - strips marketing/tracking query parameters (utm_*, gclid, fbclid, etc.)
    """
    u = val.strip()
    u_lower = u.lower()
    if not (u_lower.startswith("http://") or u_lower.startswith("https://") or u_lower.startswith("ftp://")):
        u = "http://" + u

    parsed = urlparse(u)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    path = parsed.path
    if path == "/":
        path = ""
    elif path.endswith("/") and len(path) > 1:
        path = path.rstrip("/")

    # Filter query parameters
    query_str = ""
    if parsed.query:
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        if strip_tracking:
            filtered = [
                (k, v) for k, v in query_items
                if k.lower() not in TRACKING_PARAMS
            ]
        else:
            filtered = query_items

        if filtered:
            # Sort query params for consistent canonicalization
            filtered.sort(key=lambda x: x[0])
            query_str = urlencode(filtered)

    normalized = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        query_str,
        ""  # fragments usually discarded for IOC comparison
    ))

    return normalized


def normalize_bank_account(val: str) -> str:
    """
    Normalizes bank account numbers or account:IFSC combinations.
    """
    val = val.strip()
    if ":" in val:
        parts = val.split(":", 1)
        acc = re.sub(r"[^\d]", "", parts[0])
        ifsc = parts[1].strip().upper()
        return f"{acc}:{ifsc}"
    return re.sub(r"[^\d]", "", val)


def normalize_indicator(raw_value: str, indicator_type: str | None = None) -> tuple[str, str]:
    """
    Main normalization entry point.

    Args:
        raw_value: The raw string indicator input.
        indicator_type: Optional explicit type ('url', 'domain', 'phone', 'upi_id', 'email', 'bank_account', 'other').
                        If None or 'auto', type will be auto-detected.

    Returns:
        tuple[normalized_value, resolved_indicator_type]
    """
    if not raw_value:
        return "", indicator_type or "other"

    raw_clean = raw_value.strip()

    if not indicator_type or indicator_type.lower() == "auto":
        resolved_type = detect_indicator_type(raw_clean)
    else:
        resolved_type = indicator_type.lower().strip()

    if resolved_type == "url":
        normalized = normalize_url(raw_clean)
    elif resolved_type == "domain":
        normalized = normalize_domain(raw_clean)
    elif resolved_type == "phone":
        normalized = normalize_phone(raw_clean)
    elif resolved_type == "upi_id":
        normalized = normalize_upi(raw_clean)
    elif resolved_type == "email":
        normalized = normalize_email(raw_clean)
    elif resolved_type == "bank_account":
        normalized = normalize_bank_account(raw_clean)
    else:
        normalized = raw_clean.lower() if "@" in raw_clean else raw_clean

    return normalized, resolved_type
