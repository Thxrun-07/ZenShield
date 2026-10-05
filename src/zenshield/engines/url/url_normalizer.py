"""URL normalization and static parsing service.

SECURITY NOTE:
This module performs STATIC analysis only. It NEVER initiates network requests,
resolves DNS records, downloads content, or contacts submitted URLs.
"""

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

import idna
import tldextract

from zenshield.models.schemas import NormalizedURL

# TLDExtract configured for 100% offline snapshot operation (no network calls)
_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

# Regex to detect raw IPv4 address with optional port
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")


def is_ip_address(host_or_ip: str) -> tuple[bool, str | None]:
    """Determine whether the given host string is a valid IPv4 or IPv6 address.

    Returns (is_ip, clean_ip_str).
    """
    clean_host = host_or_ip.strip("[]")
    # Strip port if present
    if ":" in clean_host and not clean_host.startswith("["):
        # Check if IPv6 or host:port
        parts = clean_host.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            clean_host = parts[0]

    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return True, str(ip_obj)
    except ValueError:
        return False, None


def normalize_url(raw_url: str) -> NormalizedURL:
    """Safely parse and normalize an input URL without visiting it.

    Handles:
    - Leading/trailing whitespace
    - Missing scheme (defaults to 'http' for parsing)
    - Lowercase hostname
    - Punycode / IDN encoding/decoding
    - IP address identification
    - Port, path, query, subdomain, and registered domain extraction
    - Malformed or crash-inducing inputs
    """
    original = raw_url.strip() if isinstance(raw_url, str) else ""
    if not original:
        return NormalizedURL(
            original_url="",
            normalized_url="",
            scheme="",
            hostname="",
            registered_domain="",
            subdomain="",
            path="",
            query="",
            port=None,
            is_ip=False,
            is_valid=False,
            error="Empty URL provided",
        )

    # Prepend scheme if missing (e.g. "example.com/path" -> "http://example.com/path")
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", original))
    working_url = original if has_scheme else f"http://{original}"

    try:
        parsed = urlparse(working_url)
    except Exception as e:
        return NormalizedURL(
            original_url=original,
            normalized_url=original,
            scheme="",
            hostname="",
            registered_domain="",
            subdomain="",
            path="",
            query="",
            port=None,
            is_ip=False,
            is_valid=False,
            error=f"Malformed URL: {str(e)}",
        )

    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Parse hostname and port safely from netloc
    hostname = ""
    port: int | None = None
    try:
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        # Happens on invalid port strings like 'example.com:abc'
        netloc_parts = netloc.split(":")
        if netloc_parts:
            hostname = netloc_parts[0].lower()

    if not hostname:
        # Fallback if parsed.hostname was None (e.g. bare domain before path)
        hostname = netloc.split(":")[0].lower()

    # Detect IP address
    is_ip, ip_str = is_ip_address(hostname)

    # Punycode / IDN handling
    is_punycode = False
    unicode_domain = hostname
    if "xn--" in hostname:
        is_punycode = True
        try:
            unicode_domain = idna.decode(hostname)
        except Exception:
            unicode_domain = hostname
    else:
        # Check if non-ASCII characters exist in hostname
        try:
            encoded_idna = idna.encode(hostname).decode("ascii")
            if encoded_idna.startswith("xn--") or "xn--" in encoded_idna:
                is_punycode = True
                unicode_domain = hostname
        except Exception:
            pass

    # Extract domain and subdomain
    registered_domain = ""
    subdomain = ""
    if is_ip:
        registered_domain = ip_str or hostname
        subdomain = ""
    else:
        try:
            extracted = _extract(hostname)
            parts = hostname.split(".")
            if extracted.suffix:
                reg_domain = extracted.top_domain_under_public_suffix
                if not reg_domain and extracted.domain:
                    reg_domain = f"{extracted.domain}.{extracted.suffix}"
                registered_domain = (reg_domain or hostname).lower()
                subdomain = (extracted.subdomain or "").lower()
            elif len(parts) >= 2:
                # Non-standard / private / testing TLDs (e.g. .internal, .test, .local)
                registered_domain = ".".join(parts[-2:]).lower()
                subdomain = ".".join(parts[:-2]).lower()
            else:
                registered_domain = hostname
                subdomain = ""
        except Exception:
            # Fallback simple split if tldextract encounters issues
            parts = hostname.split(".")
            if len(parts) >= 2:
                registered_domain = ".".join(parts[-2:])
                subdomain = ".".join(parts[:-2])
            else:
                registered_domain = hostname
                subdomain = ""

    # Build clean normalized URL string
    norm_netloc = hostname
    if port and ((scheme == "http" and port != 80) or (scheme == "https" and port != 443)):
        norm_netloc = f"{hostname}:{port}"

    clean_path = path if path else "/"
    normalized_str = urlunparse((scheme, norm_netloc, clean_path, "", query, ""))

    return NormalizedURL(
        original_url=original,
        normalized_url=normalized_str,
        scheme=scheme,
        hostname=hostname,
        registered_domain=registered_domain,
        subdomain=subdomain,
        path=clean_path,
        query=query,
        port=port,
        is_ip=is_ip,
        ip_address=ip_str,
        is_punycode=is_punycode,
        unicode_domain=unicode_domain,
        is_valid=bool(hostname),
        error=None if hostname else "Could not determine hostname from URL",
    )
