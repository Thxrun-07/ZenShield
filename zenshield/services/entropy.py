"""Shannon entropy analysis service for URL and domain components.

Formula:
H(X) = -Σ p(x) log2 p(x)

Detects:
- Randomized domains / DGA (Domain Generation Algorithms)
- Generated-looking hostnames
- Encoded or obfuscated strings in path/query components

NOTE: Entropy is strictly a supporting signal and does not classify a URL on its own.
"""

from collections import Counter
import math
from typing import List, Optional

from zenshield.config import settings
from zenshield.models.schemas import NormalizedURL, Signal, SignalSeverity


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string.
    
    H(X) = -Σ p(x) * log2(p(x))
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


class EntropyAnalyzer:
    """Analyzes character entropy in hostnames, subdomains, and URL paths."""

    def __init__(
        self,
        hostname_threshold: Optional[float] = None,
        min_length: Optional[int] = None,
    ):
        self.hostname_threshold = (
            hostname_threshold if hostname_threshold is not None else settings.ENTROPY_HOSTNAME_THRESHOLD
        )
        self.min_length = min_length if min_length is not None else settings.ENTROPY_MIN_LENGTH

    def detect(self, norm_url: NormalizedURL) -> List[Signal]:
        signals: List[Signal] = []

        if not norm_url.is_valid or norm_url.is_ip or not norm_url.hostname:
            return signals

        # 1. Analyze registered domain SLD (Second-Level Domain)
        sld = norm_url.registered_domain.split(".")[0] if "." in norm_url.registered_domain else norm_url.registered_domain
        sld_entropy = calculate_shannon_entropy(sld)

        # 2. Analyze subdomain if present
        subdomain_entropy = calculate_shannon_entropy(norm_url.subdomain) if norm_url.subdomain else 0.0

        # Check for randomized SLD
        if len(sld) >= self.min_length and sld_entropy >= self.hostname_threshold:
            signals.append(
                Signal(
                    name="High entropy hostname",
                    severity=SignalSeverity.LOW,
                    evidence=f"Hostname has unusually high character entropy (H={sld_entropy:.2f}, threshold={self.hostname_threshold:.2f})",
                )
            )
        elif len(norm_url.subdomain) >= self.min_length and subdomain_entropy >= self.hostname_threshold:
            signals.append(
                Signal(
                    name="High entropy subdomain",
                    severity=SignalSeverity.LOW,
                    evidence=f"Subdomain has unusually high character entropy (H={subdomain_entropy:.2f}, threshold={self.hostname_threshold:.2f})",
                )
            )

        # 3. Check for high-entropy obfuscated path components
        if norm_url.path and len(norm_url.path) > 25:
            path_entropy = calculate_shannon_entropy(norm_url.path)
            if path_entropy >= 4.3:
                signals.append(
                    Signal(
                        name="High entropy path component",
                        severity=SignalSeverity.LOW,
                        evidence=f"URL path exhibits unusually high character entropy (H={path_entropy:.2f})",
                    )
                )

        return signals
