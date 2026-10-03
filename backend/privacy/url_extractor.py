"""URL extraction and safe metadata inspection module.

Detects obfuscated URLs (hxxp, [.]), scheme-less shorteners, userinfo spoofing,
punycode, and brand impersonation using an offline Public Suffix List snapshot.
Never exposes path, query strings, or personal parameters in metadata.
"""

import ipaddress
import re
from urllib.parse import urlparse

from backend.config import settings
from backend.privacy.models import URLMetadata

# Multi-part public suffixes for offline domain resolution
MULTI_PART_PUBLIC_SUFFIXES = {
    # India
    "co.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "net.in",
    "org.in", "mil.in", "gen.in", "firm.in", "ind.in",
    # UK / Commonwealth / Global
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "com.sg", "com.my", "com.np", "gov.np", "co.za",
}

# Regex to detect defanged or standard URLs and scheme-less shorteners
URL_REGEX = re.compile(
    r"""(?xi)
    \b
    (?:
        # Explicit scheme (including defanged hxxp/hxxps)
        (?:https?|hxxps?)://
        [^\s<>"'{}|\\^`]+
    |
        # Scheme-less known shorteners
        (?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|shorturl\.at|rb\.gy|bl\.ink|s\.id)/[^\s<>"'{}|\\^`]+
    |
        # Defanged domains with [.]
        [a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\[\.\][a-z]{2,}(?:/[^\s<>"'{}|\\^`]*)?
    |
        # Standard web domains followed by a path or high-risk TLD
        [a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:top|xyz|club|tk|ml|ga|cf|gq|work|loan|click|link|live|buzz)/[^\s<>"'{}|\\^`]*
    )
    """
)


class URLExtractor:
    """Offline URL extractor and security evaluator."""

    def extract_urls(self, text: str) -> list[tuple[int, int, str, URLMetadata]]:
        """Extract all URLs with character spans and non-sensitive URLMetadata.

        Returns:
            List of (start, end, raw_url, url_metadata)
        """
        results: list[tuple[int, int, str, URLMetadata]] = []

        for match in URL_REGEX.finditer(text):
            raw_url = match.group()
            start, end = match.span()

            # Clean defanged representations for analysis
            normalized_url = self._defang_clean(raw_url)
            meta = self._analyze_url(normalized_url)
            results.append((start, end, raw_url, meta))

        return results

    def _defang_clean(self, raw_url: str) -> str:
        """Normalize defanged URLs (hxxp -> http, [.] -> .)."""
        clean = raw_url.replace("[.]", ".")
        clean = re.sub(r"^hxxps://", "https://", clean, flags=re.IGNORECASE)
        clean = re.sub(r"^hxxp://", "http://", clean, flags=re.IGNORECASE)

        if not re.match(r"^https?://", clean, flags=re.IGNORECASE):
            clean = "http://" + clean

        return clean

    def _analyze_url(self, clean_url: str) -> URLMetadata:
        """Parse URL and produce safe metadata without leaking path or query."""
        parsed = urlparse(clean_url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Detect userinfo trick (e.g. sbi.co.in@evil.top)
        has_userinfo_trick = "@" in netloc
        host = netloc.split("@")[-1] if has_userinfo_trick else netloc

        # Strip port if present
        if ":" in host:
            host = host.split(":")[0]

        # Check if host is raw IP address
        is_ip = self._check_is_ip(host)

        # Check for punycode
        is_punycode = "xn--" in host

        # Extract registrable domain and subdomains
        registrable_domain, subdomain_count, tld = self._extract_registrable_domain(host)

        # Check shortener
        is_shortener = (
            registrable_domain in settings.URL_SHORTENERS or
            host in settings.URL_SHORTENERS
        )

        # Check suspicious TLD
        suspicious_tld = tld in settings.SUSPICIOUS_TLDS

        # Brand lookalike evaluation
        brand_lookalike = self._evaluate_brand_lookalike(host, registrable_domain)

        # Composite suspicion verdict
        is_suspicious = (
            is_ip or
            is_shortener or
            is_punycode or
            has_userinfo_trick or
            suspicious_tld or
            brand_lookalike
        )

        return URLMetadata(
            registrable_domain=registrable_domain,
            scheme=scheme,
            is_ip=is_ip,
            is_shortener=is_shortener,
            is_punycode=is_punycode,
            has_userinfo_trick=has_userinfo_trick,
            subdomain_count=subdomain_count,
            suspicious_tld=suspicious_tld,
            brand_lookalike=brand_lookalike,
            is_suspicious=is_suspicious,
        )

    def _check_is_ip(self, host: str) -> bool:
        """Determine if host is an IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _extract_registrable_domain(self, host: str) -> tuple[str, int, str]:
        """Split host into registrable domain, subdomain count, and top-level domain."""
        parts = host.split(".")
        if len(parts) <= 1:
            return host, 0, ""

        tld = parts[-1]

        # Check 2-part suffix (e.g. co.in)
        if len(parts) >= 2:
            two_part = f"{parts[-2]}.{parts[-1]}"
            if two_part in MULTI_PART_PUBLIC_SUFFIXES and len(parts) >= 3:
                registrable_domain = f"{parts[-3]}.{two_part}"
                subdomain_count = len(parts) - 3
                return registrable_domain, max(0, subdomain_count), tld

        registrable_domain = f"{parts[-2]}.{parts[-1]}"
        subdomain_count = len(parts) - 2
        return registrable_domain, max(0, subdomain_count), tld

    def _evaluate_brand_lookalike(self, host: str, registrable_domain: str) -> bool:
        """Check if domain mimics a recognized brand while not being the official domain."""
        host_lower = host.lower()
        reg_lower = registrable_domain.lower()

        for brand, official_domains in settings.OFFICIAL_BRAND_DOMAINS.items():
            # If the brand name appears anywhere in the host
            # (e.g., "sbi" in "sbi-kyc-update.com" or "hdfc-verification.top")
            # Word boundary or hyphen-boundary check for precision
            brand_pattern = rf"(?:^|[-._]){re.escape(brand)}(?:[-._]|$)"
            if re.search(brand_pattern, host_lower) or brand in reg_lower:
                # Check if this registrable domain is among the official domains
                is_official = any(reg_lower == off.lower() for off in official_domains)
                if not is_official:
                    return True

        return False
