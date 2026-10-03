"""Configuration module for Zenshield.

Defines all operational thresholds, signal weights, brand allowlists,
and feature flags using Pydantic Settings.
"""


from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global configuration settings for Zenshield."""

    model_config = SettingsConfigDict(
        env_prefix="ZENSHIELD_",
        case_sensitive=False,
        extra="ignore",
    )

    # API and Resource Limits
    MAX_RAW_MESSAGE_LENGTH: int = Field(default=10_000, description="Maximum characters allowed in raw message")
    MAX_POST_NORMALIZATION_LENGTH: int = Field(default=10_500, description="Maximum characters allowed after NFKC normalization")
    MAX_REQUEST_BODY_BYTES: int = Field(default=65_536, description="Max raw HTTP body bytes (64KB)")
    LLM_TIMEOUT_SECONDS: float = Field(default=1.5, description="Timeout for external LLM enrichment")
    MAX_LLM_PAYLOAD_LENGTH: int = Field(default=1_000, description="Max characters sent to LLM payload")

    # Feature Flags & Provider Settings
    ENABLE_LLM_DEFAULT: bool = Field(default=False, description="Whether LLM enrichment is enabled by default")
    PERSIST_MESSAGE_CONTENT: bool = Field(default=False, description="Never persist raw message content")
    LLM_PROVIDER: Literal["noop", "groq"] = Field(default="noop", description="Selected LLM provider")
    LLM_BASE_URL: str = Field(default="https://api.groq.com/openai/v1", description="Base URL for LLM provider")
    LLM_API_KEY: SecretStr | None = Field(default=None, description="API key for LLM provider")
    LLM_MODEL: str = Field(default="", description="Model name for LLM provider")
    LLM_ENDPOINT_ALLOWLIST: set[str] = Field(
        default={"api.groq.com"},
        description="Allowlist of approved LLM hostnames",
    )

    # Risk Thresholds (Validated to be strictly ascending)
    THRESHOLD_LOW: int = Field(default=24, description="Upper bound for LOW risk (0-24)")
    THRESHOLD_MEDIUM: int = Field(default=49, description="Upper bound for MEDIUM risk (25-49)")
    THRESHOLD_HIGH: int = Field(default=74, description="Upper bound for HIGH risk (50-74)")
    # 75-100 is CRITICAL

    # Base Signal Weights (Must be non-negative)
    WEIGHT_MALWARE_RISK: int = Field(default=35)
    WEIGHT_CREDENTIAL_REQUEST: int = Field(default=30)
    WEIGHT_SENSITIVE_DATA_REQUEST: int = Field(default=30)
    WEIGHT_FINANCIAL_REQUEST: int = Field(default=25)
    WEIGHT_SUSPICIOUS_URL: int = Field(default=25)
    WEIGHT_THREAT: int = Field(default=20)
    WEIGHT_URGENCY: int = Field(default=15)
    WEIGHT_IMPERSONATION: int = Field(default=15)
    WEIGHT_SOCIAL_ENGINEERING: int = Field(default=15)
    WEIGHT_CALL_TO_ACTION: int = Field(default=10)
    WEIGHT_CALL_TO_ACTION_TOLL_FREE: int = Field(default=5)
    WEIGHT_PROMPT_INJECTION_ATTEMPT: int = Field(default=15)

    # Combination Bonuses
    BONUS_CRED_URGENCY: int = Field(default=15)
    BONUS_CRED_PHONE_CTA: int = Field(default=10)
    BONUS_KYC_SUSPICIOUS_URL: int = Field(default=20)
    BONUS_GOV_THREAT: int = Field(default=20)
    BONUS_PRIZE_PAYMENT: int = Field(default=20)
    BONUS_LOAN_ADVANCE_FEE: int = Field(default=20)
    BONUS_COURIER_FEE: int = Field(default=15)
    BONUS_SUSPENSION_LOGIN: int = Field(default=20)
    BONUS_THREAT_URGENCY_PAYMENT: int = Field(default=15)

    # Base Cap & Safety Floor
    BASE_SCORE_CAP: int = Field(default=60)
    CRITICAL_SAFETY_FLOOR: int = Field(default=50)

    # Official Brand & Domain Allowlists for URL Lookalike Protection
    # Maps brand keywords to their legitimate registrable domains
    OFFICIAL_BRAND_DOMAINS: dict[str, list[str]] = Field(
        default={
            "sbi": ["sbi.co.in", "onlinesbi.sbi", "statebankofindia.com"],
            "hdfc": ["hdfcbank.com", "hdfc.com"],
            "icici": ["icicibank.com"],
            "axis": ["axisbank.com"],
            "pnb": ["pnbindia.in"],
            "bob": ["bankofbaroda.in", "bankofbaroda.com"],
            "canara": ["canarabank.com"],
            "paytm": ["paytm.com"],
            "phonepe": ["phonepe.com"],
            "gpay": ["google.com"],
            "airtel": ["airtel.in", "airtel.com"],
            "jio": ["jio.com"],
            "vi": ["myvi.in"],
            "bsnl": ["bsnl.co.in"],
            "incometax": ["incometax.gov.in", "incometaxindia.gov.in"],
            "rbi": ["rbi.org.in"],
            "uidai": ["uidai.gov.in"],
            "india-post": ["indiapost.gov.in"],
            "cybercrime": ["cybercrime.gov.in"],
            "amazon": ["amazon.in", "amazon.com"],
            "flipkart": ["flipkart.com"],
            "netflix": ["netflix.com"],
        }
    )

    # Known high-risk / free TLDs often used for SMS phishing
    SUSPICIOUS_TLDS: set[str] = Field(
        default={
            "top", "xyz", "club", "tk", "ml", "ga", "cf", "gq", "work", "loan",
            "click", "link", "guru", "casa", "surf", "buzz", "rest", "fit", "live",
            "monster", "beauty", "hair", "quest", "cyou", "sbs",
        }
    )

    # Known URL Shortener Registrable Domains
    URL_SHORTENERS: set[str] = Field(
        default={
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
            "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc",
            "qr.ae", "s.id", "v.gd", "t.ly", "bl.ink",
        }
    )

    # Known UPI VPA Handles / Suffixes
    VALID_UPI_HANDLES: set[str] = Field(
        default={
            "okhdfcbank", "okaxis", "okicici", "oksbi", "paytm", "ybl", "ibl",
            "axl", "upi", "apl", "postbank", "federal", "indus", "kotak",
            "barodampay", "pnb", "rbl", "aubank", "idfcbank", "yesbank",
        }
    )

    @field_validator("THRESHOLD_MEDIUM")
    @classmethod
    def validate_thresholds(cls, v: int, info: ValidationInfo) -> int:
        low = info.data.get("THRESHOLD_LOW", 24)
        if v <= low:
            raise ValueError(f"THRESHOLD_MEDIUM ({v}) must be greater than THRESHOLD_LOW ({low})")
        return v

    @field_validator("THRESHOLD_HIGH")
    @classmethod
    def validate_threshold_high(cls, v: int, info: ValidationInfo) -> int:
        med = info.data.get("THRESHOLD_MEDIUM", 49)
        if v <= med:
            raise ValueError(f"THRESHOLD_HIGH ({v}) must be greater than THRESHOLD_MEDIUM ({med})")
        return v

    @model_validator(mode="after")
    def validate_llm_configuration(self) -> "Settings":
        """Validate LLM provider settings if enabled by default."""
        if self.ENABLE_LLM_DEFAULT and self.LLM_PROVIDER == "groq":
            if not self.LLM_API_KEY or not self.LLM_API_KEY.get_secret_value().strip():
                raise ValueError("LLM_API_KEY must be set when ENABLE_LLM_DEFAULT is true and LLM_PROVIDER is 'groq'.")
            if not self.LLM_MODEL or not self.LLM_MODEL.strip():
                raise ValueError("LLM_MODEL must be set when ENABLE_LLM_DEFAULT is true and LLM_PROVIDER is 'groq'.")
            parsed = urlparse(self.LLM_BASE_URL)
            if parsed.scheme.lower() != "https":
                raise ValueError(f"LLM_BASE_URL must use https scheme, got '{parsed.scheme}'.")
            hostname = (parsed.hostname or "").lower()
            if hostname not in self.LLM_ENDPOINT_ALLOWLIST:
                raise ValueError(f"LLM_BASE_URL host '{hostname}' is not in LLM_ENDPOINT_ALLOWLIST.")
        return self


settings = Settings()
