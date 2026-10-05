"""Typosquatting and domain similarity detection service.

Uses Damerau-Levenshtein distance to detect:
- Character substitution (e.g. paypa1.com vs paypal.com)
- Character insertion (e.g. gooogle.com vs google.com)
- Character deletion (e.g. gogle.com vs google.com)
- Character transposition (e.g. goolge.com vs google.com)
- Combotquatting / hyphenated brand lookalikes (e.g. micros0ft-login.com, g00gle-security.com)
"""

from zenshield.config import settings
from zenshield.models.schemas import NormalizedURL, Signal, SignalSeverity

# Common leetspeak substitutions
LEET_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "@": "a",
    "$": "s",
}


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Compute true Damerau-Levenshtein distance between two strings.

    Accounts for insertion, deletion, substitution, and transposition of adjacent characters.
    """
    d = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,  # deletion
                d[(i, j - 1)] + 1,  # insertion
                d[(i - 1, j - 1)] + cost,  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

    return d[(len1 - 1, len2 - 1)]


def normalize_leetspeak(s: str) -> str:
    """Normalize common leetspeak characters to standard Latin equivalents."""
    res = []
    for ch in s.lower():
        res.append(LEET_MAP.get(ch, ch))
    return "".join(res)


def get_domain_sld(domain: str) -> str:
    """Extract second-level domain name (SLD) without the TLD."""
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return parts[0]
    return domain.lower()


class TyposquattingDetector:
    """Detects typosquatting, combotquatting, and similarity to trusted domains."""

    def __init__(self, trusted_domains: list[str] | None = None):
        self.trusted_domains = trusted_domains or settings.TRUSTED_DOMAINS

    def detect(self, norm_url: NormalizedURL) -> list[Signal]:
        """Analyze normalized URL for typosquatting signals."""
        signals: list[Signal] = []

        if not norm_url.is_valid or norm_url.is_ip or not norm_url.registered_domain:
            return signals

        reg_domain = norm_url.registered_domain.lower()
        reg_sld = get_domain_sld(reg_domain)

        # Check if the domain is legitimately one of the trusted domains
        for trusted in self.trusted_domains:
            trusted_lower = trusted.lower()
            if reg_domain == trusted_lower:
                # Legitimate domain! Never flag legitimate domains.
                return []

        # Check for typosquatting against each trusted domain
        for trusted in self.trusted_domains:
            trusted_lower = trusted.lower()
            trusted_sld = get_domain_sld(trusted_lower)

            # 1. Direct SLD comparison (e.g. paypa1 vs paypal)
            dist = damerau_levenshtein_distance(reg_sld, trusted_sld)
            max_len = max(len(reg_sld), len(trusted_sld))

            # If very close (dist 1 on short domains, dist <= 2 on longer domains)
            threshold = 1 if max_len <= 6 else 2
            if 0 < dist <= threshold:
                signals.append(
                    Signal(
                        name="Typosquatting",
                        severity=SignalSeverity.HIGH,
                        evidence=f"Domain is highly similar to trusted domain {trusted_lower}",
                    )
                )
                return signals

            # 2. Check leetspeak normalized version (e.g. g00gle -> google)
            reg_sld_unleet = normalize_leetspeak(reg_sld)
            dist_unleet = damerau_levenshtein_distance(reg_sld_unleet, trusted_sld)
            if dist_unleet == 0 and reg_sld != trusted_sld:
                signals.append(
                    Signal(
                        name="Typosquatting",
                        severity=SignalSeverity.HIGH,
                        evidence=f"Domain is highly similar to trusted domain {trusted_lower} via character substitution",
                    )
                )
                return signals

            # 3. Check combotquatting / hyphenated keywords (e.g. micros0ft-login.com, g00gle-security.com)
            if "-" in reg_sld:
                chunks = reg_sld.split("-")
                for chunk in chunks:
                    chunk_clean = chunk.strip()
                    if not chunk_clean:
                        continue
                    # Distance directly or unleeted
                    chunk_dist = damerau_levenshtein_distance(chunk_clean, trusted_sld)
                    chunk_unleet = normalize_leetspeak(chunk_clean)
                    chunk_unleet_dist = damerau_levenshtein_distance(chunk_unleet, trusted_sld)

                    chunk_thresh = 1 if len(trusted_sld) <= 6 else 2
                    if (0 <= chunk_dist <= chunk_thresh) or (chunk_unleet_dist == 0):
                        signals.append(
                            Signal(
                                name="Typosquatting",
                                severity=SignalSeverity.HIGH,
                                evidence=f"Domain contains typosquatted variation of trusted domain {trusted_lower}",
                            )
                        )
                        return signals

        return signals
