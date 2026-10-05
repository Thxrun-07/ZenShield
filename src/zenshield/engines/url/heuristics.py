"""Structural URL heuristics and contextual pattern detection service.

Detects:
- Raw IP addresses instead of domain names
- Unusually long URLs and hostnames
- Excessive subdomains
- Suspicious TLDs
- Excessive hyphens in hostnames
- Unusual characters and credential delimiters ('@')
- Excessive percent-encoding and query parameters
- Suspicious path patterns (credential, financial, urgency intents)
- Suspicious / non-standard port numbers
- Nested or obfuscated URL structures

NOTE: Heuristics are contextual. A single weak signal like '/login' by itself
will NEVER make a URL malicious or trigger high risk.
"""

import re
from urllib.parse import parse_qs

from zenshield.config import settings
from zenshield.models.schemas import NormalizedURL, Signal, SignalSeverity

# Regex to detect percent-encoding like %20, %2F
PERCENT_ENCODING_REGEX = re.compile(r"%[0-9a-fA-F]{2}")

# Regex to detect embedded secondary URLs in path or query
EMBEDDED_URL_REGEX = re.compile(r"https?://|www\.", re.IGNORECASE)


class HeuristicDetector:
    """Analyzes structural and semantic characteristics of URLs."""

    def __init__(
        self,
        suspicious_tlds: set[str] | None = None,
        credential_keywords: set[str] | None = None,
        financial_keywords: set[str] | None = None,
        urgency_keywords: set[str] | None = None,
    ):
        self.suspicious_tlds = suspicious_tlds or settings.SUSPICIOUS_TLDS
        self.credential_keywords = credential_keywords or settings.CREDENTIAL_KEYWORDS
        self.financial_keywords = financial_keywords or settings.FINANCIAL_KEYWORDS
        self.urgency_keywords = urgency_keywords or settings.URGENCY_KEYWORDS

    def detect(self, norm_url: NormalizedURL) -> list[Signal]:
        signals: list[Signal] = []

        if not norm_url.is_valid:
            return signals

        # 1. Raw IP address check
        if norm_url.is_ip:
            signals.append(
                Signal(
                    name="Raw IP address hostname",
                    severity=SignalSeverity.MEDIUM,
                    evidence=f"URL uses a raw IP address ({norm_url.hostname}) instead of a domain name",
                )
            )

        # 2. Suspicious TLD check
        reg_domain = norm_url.registered_domain.lower()
        for tld in self.suspicious_tlds:
            if reg_domain.endswith(tld):
                signals.append(
                    Signal(
                        name="Suspicious TLD",
                        severity=SignalSeverity.MEDIUM,
                        evidence=f"Domain uses TLD '{tld}' frequently abused in phishing campaigns",
                    )
                )
                break

        # 3. Excessive subdomains
        if norm_url.subdomain:
            subdomain_labels = [lbl for lbl in norm_url.subdomain.split(".") if lbl]
            if len(subdomain_labels) >= settings.MAX_SUBDOMAINS:
                signals.append(
                    Signal(
                        name="Excessive subdomains",
                        severity=SignalSeverity.LOW,
                        evidence=f"URL contains excessive subdomain levels ({len(subdomain_labels)} levels)",
                    )
                )

        # 4. Excessive hyphens in hostname
        clean_host = norm_url.hostname.replace("xn--", "")
        hyphen_count = clean_host.count("-")
        if hyphen_count > settings.MAX_HYPHENS_IN_DOMAIN:
            signals.append(
                Signal(
                    name="Excessive hyphens in hostname",
                    severity=SignalSeverity.LOW,
                    evidence=f"Hostname contains {hyphen_count} hyphens, often used to bypass filters",
                )
            )

        # 5. Length checks
        if len(norm_url.original_url) > settings.MAX_URL_LENGTH:
            signals.append(
                Signal(
                    name="Unusually long URL",
                    severity=SignalSeverity.LOW,
                    evidence=f"URL is unusually long ({len(norm_url.original_url)} characters)",
                )
            )

        if len(norm_url.hostname) > settings.MAX_HOSTNAME_LENGTH:
            signals.append(
                Signal(
                    name="Unusually long hostname",
                    severity=SignalSeverity.LOW,
                    evidence=f"Hostname is unusually long ({len(norm_url.hostname)} characters)",
                )
            )

        # 6. Userinfo / @ delimiter in original URL
        if "@" in norm_url.original_url.split("?")[0].split("#")[0]:
            signals.append(
                Signal(
                    name="Obfuscated URL with authority delimiter",
                    severity=SignalSeverity.HIGH,
                    evidence="URL contains '@' in authority section, commonly used to disguise destination domain",
                )
            )

        # 7. Nested / embedded secondary URL in path or query
        url_rest = (norm_url.path + "?" + norm_url.query).strip("?")
        embedded_matches = EMBEDDED_URL_REGEX.findall(url_rest)
        if embedded_matches:
            signals.append(
                Signal(
                    name="Nested or open redirect URL pattern",
                    severity=SignalSeverity.MEDIUM,
                    evidence=f"URL path or query parameters contain embedded URL indicator: {embedded_matches[0]}",
                )
            )

        # 8. Excessive URL encoding
        encoded_matches = PERCENT_ENCODING_REGEX.findall(norm_url.original_url)
        if len(encoded_matches) >= 3:
            signals.append(
                Signal(
                    name="Excessive percent-encoding",
                    severity=SignalSeverity.LOW,
                    evidence=f"URL contains {len(encoded_matches)} percent-encoded sequences",
                )
            )

        # 9. Excessive query parameters
        if norm_url.query:
            try:
                parsed_params = parse_qs(norm_url.query)
                if len(parsed_params) > settings.MAX_QUERY_PARAMS:
                    signals.append(
                        Signal(
                            name="Excessive query parameters",
                            severity=SignalSeverity.LOW,
                            evidence=f"URL contains {len(parsed_params)} query parameters",
                        )
                    )
            except Exception:
                pass

        # 10. Suspicious non-standard port
        if norm_url.port and norm_url.port not in (80, 443, 8080, 8443):
            signals.append(
                Signal(
                    name="Non-standard port",
                    severity=SignalSeverity.MEDIUM,
                    evidence=f"URL directs to uncommon non-standard port {norm_url.port}",
                )
            )

        # 11. Path intent patterns (credential, financial, urgency)
        clean_path_lower = norm_url.path.lower()
        path_segments = [seg for seg in re.split(r"[/_.\-]", clean_path_lower) if seg]

        # Credential path intent
        matched_credential = [kw for kw in self.credential_keywords if kw in path_segments]
        if matched_credential:
            signals.append(
                Signal(
                    name="Credential-related path",
                    severity=SignalSeverity.MEDIUM,
                    evidence=f"URL path contains credential/authentication intent keyword: '{matched_credential[0]}'",
                )
            )

        # Financial path intent
        matched_financial = [kw for kw in self.financial_keywords if kw in path_segments]
        if matched_financial:
            signals.append(
                Signal(
                    name="Financial/payment intent",
                    severity=SignalSeverity.MEDIUM,
                    evidence=f"URL path contains financial or payment intent keyword: '{matched_financial[0]}'",
                )
            )

        # Urgency keywords in path or query
        full_lower = (norm_url.path + "?" + norm_url.query).lower()
        matched_urgency = [kw for kw in self.urgency_keywords if kw in full_lower]
        if matched_urgency:
            signals.append(
                Signal(
                    name="Urgency-inducing keyword",
                    severity=SignalSeverity.LOW,
                    evidence=f"URL contains urgency-inducing keyword: '{matched_urgency[0]}'",
                )
            )

        return signals
