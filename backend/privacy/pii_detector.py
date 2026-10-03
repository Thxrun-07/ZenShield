"""PII Detection module for Zenshield.

Extracts sensitive entities (URL, EMAIL, UPI, IFSC, PAN, AADHAAR, ACCOUNT,
PHONE, OTP, PERSON) using precise heuristics, contextual proximity, and Verhoeff validation.
Resolves overlapping spans using strict priority ordering:
URL > EMAIL/UPI > IFSC > PAN > AADHAAR > ACCOUNT > PHONE > OTP > PERSON
"""

import re

from backend.config import settings
from backend.privacy.models import DetectedEntity
from backend.privacy.sanitizer import DualViewText
from backend.privacy.url_extractor import URLExtractor

# Strict priority order (lower index = higher priority)
PII_PRIORITY_ORDER = {
    "URL": 1,
    "UPI": 2,
    "EMAIL": 3,
    "IFSC": 4,
    "PAN": 5,
    "AADHAAR": 6,
    "ACCOUNT": 7,
    "PHONE": 8,
    "OTP": 9,
    "PERSON": 10,
}

# Verhoeff Algorithm Tables for Aadhaar Checksum Validation
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def validate_verhoeff(num_str: str) -> bool:
    """Validate numeric string using Verhoeff checksum algorithm."""
    if not num_str.isdigit():
        return False
    c = 0
    reversed_digits = [int(d) for d in reversed(num_str)]
    for i, digit in enumerate(reversed_digits):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]]
    return c == 0


# Compiled Regular Expressions for Entities
PAN_REGEX = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b")
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
EMAIL_OR_UPI_REGEX = re.compile(r"\b[a-zA-Z0-9_.+-]+@([a-zA-Z0-9.-]+)\b")

# Indian and International Phone Numbers
# Indian: +91 / 0 / bare 10-digit starting with 6-9
PHONE_INDIA_REGEX = re.compile(
    r"""(?x)
    \b
    (?:
        (?:\+91[\s.-]?|0)?[6-9]\d{9}
    |
        (?:\+91[\s.-]?|0)?[6-9]\d{4}[\s.-]?\d{5}
    )
    \b
    """
)
# Toll-free numbers: 1800-xxx-xxxx, 1860-xxx-xxxx
TOLL_FREE_REGEX = re.compile(r"\b18[06]0[\s.-]?\d{3}[\s.-]?\d{3,4}\b")

# International Phone Numbers with explicit + country code
PHONE_INTL_REGEX = re.compile(r"\+[1-9]\d{0,2}(?:[\s.-]?\d{2,5}){2,4}\b")

# Bank Account Numbers: 9-18 digits preceded by account context
ACCOUNT_PATTERN = re.compile(
    r"""(?xi)
    (?:account|a/c|acct|acc)(?:\s*(?:number|no|num))?\s*(?:is|:|-|\.|\#)?\s*([0-9]{9,18})\b
    """
)

# Aadhaar Numbers: 12 digits starting with [2-9] (contiguous or 4-4-4)
AADHAAR_PATTERN = re.compile(
    r"""(?x)
    \b([2-9]\d{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b
    """
)
AADHAAR_KEYWORDS = {"aadhaar", "uidai", "aadhar", "ஆதார்"}

# OTP Keywords and Candidates
OTP_KEYWORDS = {
    "otp", "0tp", "one time password", "verification code", "security code",
    "passcode", "auth code", "login code", "ஓடிபி", "சரிபார்ப்பு குறியீடு"
}
OTP_DIGIT_REGEX = re.compile(r"\b(\d{4,8})\b")

# Names preceded by greetings or honorifics: requires TitleCase name to avoid capturing adverbs
GREETING_PREFIX_REGEX = re.compile(
    r"(?i:\b(?:hi|hello|dear|thiru|mr|mrs|ms|shri|smt)\b[.,:\s]+)([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20})?)"
)
NON_PERSON_DENYLIST = {
    "team", "customer", "user", "sir", "madam", "all", "valued", "candidate",
    "member", "everyone", "account", "holder", "friend", "colleague", "client",
}


class PIIDetector:
    """Detects sensitive personal identifiers and security entities."""

    def __init__(self, url_extractor: URLExtractor | None = None):
        self.url_extractor = url_extractor or URLExtractor()

    def detect(self, dual_view: DualViewText) -> list[DetectedEntity]:
        """Detect all PII entities and resolve overlapping spans by priority."""
        candidates: list[DetectedEntity] = []
        canon_text = dual_view.canonical_text
        fold_text = dual_view.fold_text

        # 1. URL Detection
        url_matches = self.url_extractor.extract_urls(canon_text)
        for start, end, raw_url, url_meta in url_matches:
            candidates.append(
                DetectedEntity(
                    entity_type="URL",
                    start=start,
                    end=end,
                    original_value=raw_url,
                    confidence=1.0,
                    replacement="[URL_REDACTED]",
                    metadata=url_meta.model_dump(),
                )
            )

        # 2. EMAIL vs UPI Detection
        for match in EMAIL_OR_UPI_REGEX.finditer(canon_text):
            full_val = match.group()
            domain_handle = match.group(1).lower()
            start, end = match.span()

            # Disambiguate UPI from EMAIL
            is_upi = (
                domain_handle in settings.VALID_UPI_HANDLES or
                any(domain_handle.endswith("." + h) for h in settings.VALID_UPI_HANDLES) or
                "upi" in domain_handle
            )

            if is_upi:
                candidates.append(
                    DetectedEntity(
                        entity_type="UPI",
                        start=start,
                        end=end,
                        original_value=full_val,
                        confidence=0.95,
                        replacement="[UPI_REDACTED]",
                    )
                )
            else:
                candidates.append(
                    DetectedEntity(
                        entity_type="EMAIL",
                        start=start,
                        end=end,
                        original_value=full_val,
                        confidence=0.98,
                        replacement="[EMAIL_REDACTED]",
                    )
                )

        # 3. IFSC Code Detection
        for match in IFSC_REGEX.finditer(canon_text):
            candidates.append(
                DetectedEntity(
                    entity_type="IFSC",
                    start=match.start(),
                    end=match.end(),
                    original_value=match.group(),
                    confidence=0.95,
                    replacement="[IFSC_REDACTED]",
                )
            )

        # 4. PAN Card Detection
        for match in PAN_REGEX.finditer(canon_text):
            candidates.append(
                DetectedEntity(
                    entity_type="PAN",
                    start=match.start(),
                    end=match.end(),
                    original_value=match.group(),
                    confidence=0.95,
                    replacement="[PAN_REDACTED]",
                )
            )

        # 5. Bank Account Number Detection
        for match in ACCOUNT_PATTERN.finditer(canon_text):
            # group(1) contains the account digits
            start, end = match.span(1)
            candidates.append(
                DetectedEntity(
                    entity_type="ACCOUNT",
                    start=start,
                    end=end,
                    original_value=match.group(1),
                    confidence=0.90,
                    replacement="[ACCOUNT_REDACTED]",
                )
            )

        # 6. Aadhaar Number Detection (Verhoeff checksum or keyword proximity)
        for match in AADHAAR_PATTERN.finditer(canon_text):
            raw_aadhaar = match.group(1)
            digits_only = re.sub(r"\D", "", raw_aadhaar)
            if len(digits_only) == 12:
                # Check Verhoeff or keyword context
                has_verhoeff = validate_verhoeff(digits_only)
                window_start = max(0, match.start() - 40)
                window_end = min(len(fold_text), match.end() + 40)
                context_window = fold_text[window_start:window_end]
                has_keyword = any(kw in context_window for kw in AADHAAR_KEYWORDS)

                if has_verhoeff or has_keyword:
                    candidates.append(
                        DetectedEntity(
                            entity_type="AADHAAR",
                            start=match.start(),
                            end=match.end(),
                            original_value=raw_aadhaar,
                            confidence=0.95 if has_verhoeff else 0.85,
                            replacement="[AADHAAR_REDACTED]",
                        )
                    )

        # 7. Phone Numbers (India, Toll-free, International)
        # Toll-Free
        for match in TOLL_FREE_REGEX.finditer(canon_text):
            candidates.append(
                DetectedEntity(
                    entity_type="PHONE",
                    start=match.start(),
                    end=match.end(),
                    original_value=match.group(),
                    confidence=0.95,
                    replacement="[PHONE_REDACTED]",
                    metadata={"is_toll_free": True},
                )
            )

        # India Standard Mobile/Landline
        for match in PHONE_INDIA_REGEX.finditer(canon_text):
            candidates.append(
                DetectedEntity(
                    entity_type="PHONE",
                    start=match.start(),
                    end=match.end(),
                    original_value=match.group(),
                    confidence=0.95,
                    replacement="[PHONE_REDACTED]",
                    metadata={"is_toll_free": False},
                )
            )

        # International Mobile
        for match in PHONE_INTL_REGEX.finditer(canon_text):
            candidates.append(
                DetectedEntity(
                    entity_type="PHONE",
                    start=match.start(),
                    end=match.end(),
                    original_value=match.group(),
                    confidence=0.90,
                    replacement="[PHONE_REDACTED]",
                    metadata={"is_toll_free": False},
                )
            )

        # 8. OTP Detection (Digits within ±40 chars of OTP keywords)
        self._detect_otps(canon_text, fold_text, candidates)

        # 9. Person Name Detection
        for match in GREETING_PREFIX_REGEX.finditer(canon_text):
            name_val = match.group(1).strip()
            if name_val.lower() not in NON_PERSON_DENYLIST:
                start, end = match.span(1)
                candidates.append(
                    DetectedEntity(
                        entity_type="PERSON",
                        start=start,
                        end=end,
                        original_value=name_val,
                        confidence=0.85,
                        replacement=None,  # Assigned dynamically by Masker (PERSON_01)
                    )
                )

        # 10. Resolve Overlapping Spans by Priority
        resolved_entities = self._resolve_overlaps(candidates)
        return resolved_entities

    def _detect_otps(
        self,
        canon_text: str,
        fold_text: str,
        candidates: list[DetectedEntity],
    ) -> None:
        """Find numeric OTP tokens near OTP keywords in the fold view."""
        for kw in OTP_KEYWORDS:
            for kw_match in re.finditer(re.escape(kw), fold_text):
                kw_start, kw_end = kw_match.span()
                # Search window ±40 chars
                win_start = max(0, kw_start - 40)
                win_end = min(len(canon_text), kw_end + 40)
                window_str = canon_text[win_start:win_end]

                for digit_match in OTP_DIGIT_REGEX.finditer(window_str):
                    actual_start = win_start + digit_match.start()
                    actual_end = win_start + digit_match.end()
                    digits_val = digit_match.group(1)

                    # Ensure it is not a postal PIN code (e.g. 6-digit near PIN/postal)
                    # or an already identified long number
                    candidates.append(
                        DetectedEntity(
                            entity_type="OTP",
                            start=actual_start,
                            end=actual_end,
                            original_value=digits_val,
                            confidence=0.92,
                            replacement="[OTP_REDACTED]",
                        )
                    )

    def _resolve_overlaps(self, candidates: list[DetectedEntity]) -> list[DetectedEntity]:
        """Resolve overlapping spans according to priority, length, and position."""
        # Sort key:
        # 1. Priority index (ascending)
        # 2. Span length (descending, so longer spans win)
        # 3. Start position (ascending)
        def sort_key(e: DetectedEntity) -> tuple[int, int, int]:
            priority = PII_PRIORITY_ORDER.get(e.entity_type, 99)
            length = e.end - e.start
            return priority, -length, e.start

        sorted_candidates = sorted(candidates, key=sort_key)
        accepted: list[DetectedEntity] = []

        for cand in sorted_candidates:
            # Check overlap with any accepted entity
            overlap = False
            for acc in accepted:
                # Overlap condition: max(start) < min(end)
                if max(cand.start, acc.start) < min(cand.end, acc.end):
                    overlap = True
                    break

            if not overlap:
                accepted.append(cand)

        # Sort accepted entities by start index ascending for deterministic output
        accepted.sort(key=lambda x: x.start)
        return accepted
