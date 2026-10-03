"""Punycode and homoglyph / mixed-script detection service.

Detects:
- Punycode domains (xn--)
- Homoglyph characters (e.g. Cyrillic/Greek characters visually identical to Latin)
- Mixed-script domain spoofing (mixing Latin with Cyrillic, Greek, etc.)
- Impersonation of trusted brands via homoglyph replacement (e.g. Cyrillic 'а' in apple.com)

NOTE: Unicode domains are not automatically classified as malicious.
Signals are supporting evidence and categorized by severity.
"""

import unicodedata
from typing import Dict, List, Optional, Set
import idna

from zenshield.config import settings
from zenshield.models.schemas import NormalizedURL, Signal, SignalSeverity

# Common homoglyph mappings (Cyrillic/Greek/symbols -> Latin character)
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic lower
    "\u0430": "a",  # Cyrillic small letter a
    "\u0441": "c",  # Cyrillic small letter es
    "\u0435": "e",  # Cyrillic small letter ie
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er
    "\u0455": "s",  # Cyrillic small letter dze
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u0443": "y",  # Cyrillic small letter u
    "\u0445": "x",  # Cyrillic small letter ha
    "\u04bb": "h",  # Cyrillic small letter shha
    "\u045d": "i",  # Cyrillic small letter i with grave
    # Cyrillic upper
    "\u0410": "A",
    "\u0412": "B",
    "\u0421": "C",
    "\u0415": "E",
    "\u041d": "H",
    "\u0406": "I",
    "\u0408": "J",
    "\u041a": "K",
    "\u041c": "M",
    "\u041e": "O",
    "\u0420": "P",
    "\u0422": "T",
    "\u0425": "X",
    # Greek
    "\u03b1": "a",  # alpha
    "\u03bf": "o",  # omicron
    "\u03bd": "v",  # nu
    "\u03c1": "p",  # rho
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
}


def get_character_script(ch: str) -> str:
    """Identify the script name for a Unicode character."""
    name = unicodedata.name(ch, "")
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "HAN", "HIRAGANA", "KATAKANA", "HANGUL"):
        if script in name:
            return script
    return "OTHER"


def normalize_homoglyphs(text: str) -> str:
    """Translate homoglyph characters into their Latin visual equivalents."""
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


class PunycodeHomoglyphDetector:
    """Detects punycode encoded domains, homoglyph lookalikes, and mixed-script spoofing."""

    def __init__(self, trusted_domains: Optional[List[str]] = None):
        self.trusted_domains = trusted_domains or settings.TRUSTED_DOMAINS

    def detect(self, norm_url: NormalizedURL) -> List[Signal]:
        signals: List[Signal] = []

        if not norm_url.is_valid or norm_url.is_ip or not norm_url.hostname:
            return signals

        hostname = norm_url.hostname.lower()
        reg_domain = norm_url.registered_domain.lower()

        # Check if domain uses Punycode (xn--)
        is_punycode = norm_url.is_punycode or "xn--" in hostname
        decoded_domain = norm_url.unicode_domain or hostname

        if is_punycode and not norm_url.unicode_domain:
            try:
                decoded_domain = idna.decode(hostname)
            except Exception:
                decoded_domain = hostname

        # 1. Punycode detection
        if is_punycode:
            signals.append(
                Signal(
                    name="Punycode domain detected",
                    severity=SignalSeverity.MEDIUM,
                    evidence=f"Domain uses Punycode encoding ({hostname} -> {decoded_domain})",
                )
            )

        # 2. Check for homoglyphs and mixed scripts across domain labels
        labels = decoded_domain.split(".")
        has_homoglyphs = False
        detected_homoglyphs: List[str] = []
        mixed_script_found = False

        for label in labels:
            scripts: Set[str] = set()
            for ch in label:
                if ch.isalnum():
                    script = get_character_script(ch)
                    scripts.add(script)
                if ch in HOMOGLYPH_MAP:
                    has_homoglyphs = True
                    detected_homoglyphs.append(f"'{ch}' ({unicodedata.name(ch, 'unknown')})")

            # Mixed-script condition: mixing LATIN with CYRILLIC or GREEK in the same label
            if "LATIN" in scripts and ("CYRILLIC" in scripts or "GREEK" in scripts):
                mixed_script_found = True

        if mixed_script_found:
            signals.append(
                Signal(
                    name="Mixed-script domain spoofing",
                    severity=SignalSeverity.HIGH,
                    evidence="Domain contains characters from multiple scripts that may imitate a trusted domain",
                )
            )
        elif has_homoglyphs:
            unique_h = list(dict.fromkeys(detected_homoglyphs))[:3]
            signals.append(
                Signal(
                    name="Homoglyph characters detected",
                    severity=SignalSeverity.MEDIUM,
                    evidence=f"Domain contains characters visually resembling Latin characters: {', '.join(unique_h)}",
                )
            )

        # 3. Check if translated homoglyphs match a trusted domain
        translated = normalize_homoglyphs(decoded_domain)
        if translated != decoded_domain:
            translated_reg = normalize_homoglyphs(reg_domain)
            for trusted in self.trusted_domains:
                if translated_reg == trusted.lower() and reg_domain != trusted.lower():
                    signals.append(
                        Signal(
                            name="Homoglyph brand impersonation",
                            severity=SignalSeverity.HIGH,
                            evidence=f"Homoglyph-normalized domain '{translated_reg}' imitates trusted domain '{trusted}'",
                        )
                    )
                    break

        return signals
