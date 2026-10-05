"""Brand impersonation detection service.

Detects deceptive brand placement in:
- Subdomains of unrelated domains (e.g. paypal.security-example.com)
- Brand names combined with phishing/authentication keywords in registered domains (e.g. microsoft-login.example.com)
- Brand keywords embedded into SLD (e.g. apple-support-recovery.com)

NOTE: Does NOT flag URLs where the brand keyword appears in an article path or on the legitimate brand domain.
"""

import re

from zenshield.config import settings
from zenshield.models.schemas import NormalizedURL, Signal, SignalSeverity

# Phishing / credential lure keywords commonly paired with brands
PHISHING_LURE_KEYWORDS = {
    "login",
    "signin",
    "security",
    "verify",
    "verification",
    "account",
    "update",
    "support",
    "helpdesk",
    "auth",
    "portal",
    "billing",
    "payment",
    "secure",
    "recovery",
    "service",
    "alert",
}


class BrandImpersonationDetector:
    """Detects brand impersonation across domain and subdomain structures."""

    def __init__(self, brand_domains: dict[str, list[str]] | None = None):
        self.brand_domains = brand_domains or settings.BRAND_DOMAINS

    def detect(self, norm_url: NormalizedURL) -> list[Signal]:
        signals: list[Signal] = []

        if not norm_url.is_valid or norm_url.is_ip or not norm_url.hostname:
            return signals

        reg_domain = norm_url.registered_domain.lower()
        subdomain = norm_url.subdomain.lower()
        norm_url.hostname.lower()

        # Check each brand
        for brand, legitimate_domains in self.brand_domains.items():
            brand_lower = brand.lower()

            # If the registered domain is legitimately owned by this brand, skip!
            is_legitimate_brand_domain = any(
                reg_domain == leg.lower() or reg_domain.endswith("." + leg.lower()) for leg in legitimate_domains
            )
            if is_legitimate_brand_domain:
                continue

            # 1. Brand name in subdomain of an unrelated domain
            # e.g., paypal.security-example.com or auth.paypal.phish.com
            subdomain_labels = [lbl for lbl in re.split(r"[-.]", subdomain) if lbl]
            if brand_lower in subdomain_labels:
                signals.append(
                    Signal(
                        name="Brand impersonation in subdomain",
                        severity=SignalSeverity.HIGH,
                        evidence=f"Brand '{brand}' appears in subdomain on unrelated registered domain '{reg_domain}'",
                    )
                )
                return signals

            # 2. Brand name combined with lures in registered domain
            # e.g., microsoft-login.com, paypal-verify.net, apple-support.com
            reg_sld = reg_domain.split(".")[0]
            sld_tokens = [tok for tok in re.split(r"[-_0-9]", reg_sld) if tok]

            if brand_lower in sld_tokens or brand_lower in reg_sld:
                # Check if it has a paired lure or is a compound domain
                has_lure = any(lure in reg_sld for lure in PHISHING_LURE_KEYWORDS)
                is_hyphenated = "-" in reg_sld or "_" in reg_sld
                if has_lure or is_hyphenated or len(reg_sld) > len(brand_lower) + 2:
                    matched_lure = next(
                        (lure for lure in PHISHING_LURE_KEYWORDS if lure in reg_sld), "suspicious compound"
                    )
                    signals.append(
                        Signal(
                            name="Brand impersonation",
                            severity=SignalSeverity.HIGH,
                            evidence=f"Domain '{reg_domain}' embeds brand '{brand}' alongside {matched_lure} pattern",
                        )
                    )
                    return signals

        return signals
