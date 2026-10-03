"""Sanitizer module for Zenshield.

Implements Stage 0 of the verification pipeline:
- Raw length bounds enforcement
- Invisible character and bidi control stripping
- NFKC Unicode normalization
- Indic-digit to ASCII digit mapping
- Placeholder lookalike escaping
- Construction of DualViewText (Canonical View vs. Fold View with offset map)
"""

import re
import unicodedata
from dataclasses import dataclass

from backend.config import settings

# Pre-defined Indic to ASCII digit translation table
INDIC_DIGITS_MAP = {
    # Tamil digits U+0BE6 - U+0BEF
    0x0BE6: "0", 0x0BE7: "1", 0x0BE8: "2", 0x0BE9: "3", 0x0BEA: "4",
    0x0BEB: "5", 0x0BEC: "6", 0x0BED: "7", 0x0BEE: "8", 0x0BEF: "9",
    # Devanagari digits U+0966 - U+096F
    0x0966: "0", 0x0967: "1", 0x0968: "2", 0x0969: "3", 0x096A: "4",
    0x096B: "5", 0x096C: "6", 0x096D: "7", 0x096E: "8", 0x096F: "9",
    # Arabic-Indic digits U+0660 - U+0669
    0x0660: "0", 0x0661: "1", 0x0662: "2", 0x0663: "3", 0x0664: "4",
    0x0665: "5", 0x0666: "6", 0x0667: "7", 0x0668: "8", 0x0669: "9",
    # Eastern Arabic-Indic / Persian digits U+06F0 - U+06F9
    0x06F0: "0", 0x06F1: "1", 0x06F2: "2", 0x06F3: "3", 0x06F4: "4",
    0x06F5: "5", 0x06F6: "6", 0x06F7: "7", 0x06F8: "8", 0x06F9: "9",
}

# Invisible / Zero-width / Bi-directional control characters to strip
STRIP_CHARS = {
    0x200B,  # Zero-width space
    0x200C,  # Zero-width non-joiner
    0x200D,  # Zero-width joiner
    0x2060,  # Word joiner
    0xFEFF,  # Zero-width no-break space (BOM)
    0x00AD,  # Soft hyphen
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # Bidi overrides
    0x2066, 0x2067, 0x2068, 0x2069,          # Bidi isolates
}

# Cyrillic and Greek homoglyphs to Latin lowercase mapping
HOMOGLYPH_MAP = {
    # Cyrillic lowercase
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c",
    0x0443: "y", 0x0445: "x", 0x0456: "i", 0x0458: "j", 0x0432: "b",
    0x043A: "k", 0x043C: "m", 0x043D: "h", 0x0442: "t",
    # Cyrillic uppercase
    0x0410: "a", 0x0412: "b", 0x0415: "e", 0x041A: "k", 0x041C: "m",
    0x041D: "h", 0x041E: "o", 0x0420: "p", 0x0421: "c", 0x0422: "t",
    0x0423: "y", 0x0425: "x",
    # Greek
    0x03B1: "a", 0x03B5: "e", 0x03BF: "o", 0x03C1: "p",
}

# Placeholder lookalike pattern in untrusted user input
PLACEHOLDER_LOOKALIKE_REGEX = re.compile(
    r"(\[(?:PHONE|EMAIL|OTP|CARD|UPI|ACCOUNT|IFSC|AADHAAR|PAN|URL|IP|PASSWORD|CVV|PIN)_REDACTED\]|PERSON_\d+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DualViewText:
    """Encapsulates Canonical Text for PII spans and Fold Text for keyword matching."""

    canonical_text: str
    fold_text: str
    fold_to_canon_map: list[int]

    def map_fold_span_to_canon(self, start: int, end: int) -> tuple[int, int]:
        """Convert a match span in fold_text to its corresponding span in canonical_text."""
        if not self.fold_to_canon_map:
            return 0, 0
        clamped_start = min(max(0, start), len(self.fold_to_canon_map) - 1)
        clamped_end = min(max(0, end - 1), len(self.fold_to_canon_map) - 1)
        canon_start = self.fold_to_canon_map[clamped_start]
        canon_end = self.fold_to_canon_map[clamped_end] + 1
        return canon_start, canon_end


class Sanitizer:
    """Sanitizes raw text, removes evasive obfuscations, and builds dual text views."""

    def sanitize(self, raw_message: str) -> DualViewText:
        """Sanitize raw message into canonical and folded views.

        Raises:
            ValueError: If message is empty or exceeds character limits.
        """
        if not raw_message or not raw_message.strip():
            raise ValueError("Message cannot be empty or whitespace only.")

        raw_len = len(raw_message)
        if raw_len > settings.MAX_RAW_MESSAGE_LENGTH:
            raise ValueError(
                f"Message length ({raw_len}) exceeds maximum allowed ({settings.MAX_RAW_MESSAGE_LENGTH})."
            )

        # 1. Strip invisible / zero-width / bidi control characters
        cleaned_chars = [ch for ch in raw_message if ord(ch) not in STRIP_CHARS]
        cleaned_text = "".join(cleaned_chars)

        # 2. Unicode NFKC normalization
        normalized_text = unicodedata.normalize("NFKC", cleaned_text)

        # 3. Indic-digit to ASCII digit normalization
        ascii_digit_text = normalized_text.translate(INDIC_DIGITS_MAP)

        # 4. Remove unprintable control characters (preserving \n, \r, \t)
        printable_chars = [
            ch for ch in ascii_digit_text
            if ch in ("\n", "\r", "\t") or unicodedata.category(ch)[0] != "C"
        ]
        canonical_raw = "".join(printable_chars)

        # 5. Length re-check after normalization
        if len(canonical_raw) > settings.MAX_POST_NORMALIZATION_LENGTH:
            raise ValueError("Normalized message exceeds post-normalization size limits.")

        # 6. Escape any user-supplied placeholder lookalikes to prevent injection
        canonical_text = PLACEHOLDER_LOOKALIKE_REGEX.sub(r"\\\1", canonical_raw)

        # 7. Build Fold View and offset map
        fold_text, fold_to_canon_map = self._build_fold_view(canonical_text)

        return DualViewText(
            canonical_text=canonical_text,
            fold_text=fold_text,
            fold_to_canon_map=fold_to_canon_map,
        )

    def _build_fold_view(self, canonical_text: str) -> tuple[str, list[int]]:
        """Construct the lowercased, homoglyph-folded view with an exact offset map."""
        fold_chars: list[str] = []
        offset_map: list[int] = []

        i = 0
        n = len(canonical_text)

        while i < n:
            ch = canonical_text[i]
            code = ord(ch)

            # Map homoglyphs
            mapped_ch = HOMOGLYPH_MAP[code] if code in HOMOGLYPH_MAP else ch.lower()

            # Handle leetspeak in word context (@ -> a, $ -> s, etc.)
            # Careful not to corrupt digits when part of numbers
            if mapped_ch == "@":
                mapped_ch = "a"
            elif mapped_ch == "$":
                mapped_ch = "s"

            fold_chars.append(mapped_ch)
            offset_map.append(i)
            i += 1

        fold_str = "".join(fold_chars)
        return fold_str, offset_map
