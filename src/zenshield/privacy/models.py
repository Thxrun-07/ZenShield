"""Domain models for the privacy engine.

Includes DetectedEntity, URLMetadata, and MaskedResult.
Entity representations are strictly redacted in __repr__ to guarantee
zero PII leakage into logs, debugging traces, or string conversions.
"""

from typing import Any

from pydantic import BaseModel, Field


class DetectedEntity(BaseModel):
    """Represents a detected PII or security-sensitive entity in canonical text."""

    entity_type: str = Field(..., description="Type of entity, e.g. PHONE, OTP, URL, PERSON")
    start: int = Field(..., description="Starting character index in canonical text")
    end: int = Field(..., description="Ending character index in canonical text")
    original_value: str = Field(..., description="Original raw value extracted")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score")
    replacement: str | None = Field(default=None, description="Assigned replacement placeholder")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Safe auxiliary metadata")

    def __repr__(self) -> str:
        """Override __repr__ to prevent accidental PII leakage in logs or exceptions."""
        return (
            f"DetectedEntity(type={self.entity_type}, "
            f"start={self.start}, end={self.end}, "
            f"confidence={self.confidence:.2f}, "
            f"replacement='{self.replacement}', value='[REDACTED]')"
        )

    def __str__(self) -> str:
        return self.__repr__()


class URLMetadata(BaseModel):
    """Safe, non-PII metadata extracted from a detected URL.

    Path, query parameters, userinfo, and auth tokens are strictly omitted.
    """

    registrable_domain: str = Field(..., description="Extracted registrable domain (e.g. example.com)")
    scheme: str = Field(default="https", description="URL scheme (http/https)")
    is_ip: bool = Field(default=False, description="True if host is an IPv4 or IPv6 address")
    is_shortener: bool = Field(default=False, description="True if domain is a known URL shortener")
    is_punycode: bool = Field(default=False, description="True if domain contains xn-- punycode encoding")
    has_userinfo_trick: bool = Field(default=False, description="True if URL uses userinfo trick (e.g. user@evil.com)")
    subdomain_count: int = Field(default=0, description="Number of subdomains before registrable domain")
    suspicious_tld: bool = Field(default=False, description="True if TLD is in suspicious TLD list")
    brand_lookalike: bool = Field(
        default=False, description="True if domain mimics a known brand without being official"
    )
    is_suspicious: bool = Field(default=False, description="Aggregated suspicion verdict")


class MaskedResult(BaseModel):
    """Result of the privacy sanitization and masking pipeline."""

    canonical_text: str = Field(..., description="Cleaned canonical text before placeholder substitution")
    masked_text: str = Field(..., description="Fully redacted text safe for external transmission")
    entities: list[DetectedEntity] = Field(default_factory=list, description="All detected entities with spans")
    masked_entity_counts: dict[str, int] = Field(default_factory=dict, description="Count of masked items by type")
    url_metadata: list[URLMetadata] = Field(default_factory=list, description="Safe metadata for all detected URLs")
