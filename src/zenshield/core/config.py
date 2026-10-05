"""Unified configuration settings for ZenShield.

Consolidates all configuration from:
1. ZenShield main orchestration layer
2. URL risk engine
3. Message verification & privacy engine
4. Threat intelligence registry

All environment variables use the `ZENSHIELD_` prefix.
"""

from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base directory of the repository/package
PACKAGE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent


class Settings(BaseSettings):
    """Global configuration settings for ZenShield."""

    model_config = SettingsConfigDict(
        env_prefix="ZENSHIELD_",
        case_sensitive=False,
        extra="ignore",
    )

    # =========================================================================
    # 1. Server & Environment Configuration
    # =========================================================================
    ENVIRONMENT: str = Field(default="development", description="Environment: development, staging, production")
    APP_NAME: str = Field(default="ZenShield", description="Application brand title")
    APP_VERSION: str = Field(default="2.0.0", description="Backend semantic version")
    API_V1_PREFIX: str = Field(default="/api/v1", description="API v1 routing prefix")
    HOST: str = Field(default="0.0.0.0", description="Binding host IP")
    PORT: int = Field(default=8000, description="Binding HTTP port")
    DEBUG: bool = Field(default=False, description="Enable FastAPI debug mode")

    # =========================================================================
    # 2. CORS Configuration
    # =========================================================================
    ALLOWED_ORIGINS: list[str] | str = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"],
        description="Explicit allowed CORS origins. Never use wildcard with credentials.",
    )

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v_trimmed = v.strip()
            if v_trimmed.startswith("[") and v_trimmed.endswith("]"):
                import json
                try:
                    return json.loads(v_trimmed)
                except Exception:
                    pass
            return [origin.strip() for origin in v_trimmed.split(",") if origin.strip()]
        return v

    # =========================================================================
    # 3. Payload & Resource Limits
    # =========================================================================
    MAX_REQUEST_BODY_BYTES: int = Field(default=65_536, description="Max JSON request body bytes (64 KB)")
    MAX_UPLOAD_SIZE_BYTES: int = Field(default=10 * 1024 * 1024, description="Max file upload bytes (10 MB)")
    MAX_RAW_MESSAGE_LENGTH: int = Field(default=10_000, description="Max raw message characters")
    MAX_POST_NORMALIZATION_LENGTH: int = Field(default=10_500, description="Max characters after NFKC normalization")
    MAX_URL_LENGTH: int = Field(default=150, description="Heuristic threshold for unusually long URL")
    MAX_HOSTNAME_LENGTH: int = Field(default=40, description="Heuristic threshold for unusually long hostname")
    MAX_SUBDOMAINS: int = Field(default=3, description="Subdomain threshold for heuristic flags")
    MAX_HYPHENS_IN_DOMAIN: int = Field(default=2, description="Hyphen count threshold for heuristic flags")
    MAX_QUERY_PARAMS: int = Field(default=5, description="Query parameter count threshold")

    # =========================================================================
    # 4. Database & Threat Intelligence
    # =========================================================================
    DATABASE_PATH: str = Field(
        default=str(PROJECT_ROOT / "data" / "zenshield.db"),
        description="Absolute filesystem path for SQLite database",
    )
    DATABASE_URL: str = Field(
        default="",
        description="Optional full SQLAlchemy database URL. Derived from DATABASE_PATH if empty.",
    )

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_url(cls, v: str, info: ValidationInfo) -> str:
        if v and v.strip():
            return v.strip()
        db_path = info.data.get("DATABASE_PATH") or str(PROJECT_ROOT / "data" / "zenshield.db")
        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # Convert windows backslashes to forward slashes for sqlite url
        normalized_path = Path(db_path).resolve().as_posix()
        return f"sqlite:///{normalized_path}"

    # =========================================================================
    # 5. External Threat Intelligence & Providers
    # =========================================================================
    VIRUSTOTAL_API_KEY: SecretStr | None = Field(default=None, description="VirusTotal API key")
    SAFE_BROWSING_API_KEY: SecretStr | None = Field(default=None, description="Google Safe Browsing key")
    ENABLE_EXTERNAL_REPUTATION: bool = Field(default=False, description="Enable outbound external reputation calls")

    # =========================================================================
    # 6. LLM Enrichment & Privacy Settings
    # =========================================================================
    ENABLE_LLM_DEFAULT: bool = Field(default=False, description="Whether LLM enrichment is enabled by default")
    PERSIST_MESSAGE_CONTENT: bool = Field(default=False, description="Never persist raw message content")
    LLM_PROVIDER: Literal["noop", "groq"] = Field(default="noop", description="Selected LLM provider")
    LLM_BASE_URL: str = Field(default="https://api.groq.com/openai/v1", description="Base URL for LLM provider")
    LLM_API_KEY: SecretStr | None = Field(default=None, description="API key for LLM provider")
    LLM_MODEL: str = Field(default="", description="Model name for LLM provider")
    LLM_TIMEOUT_SECONDS: float = Field(default=1.5, description="Timeout for external LLM enrichment")
    MAX_LLM_PAYLOAD_LENGTH: int = Field(default=1_000, description="Max characters sent to LLM payload")
    LLM_ENDPOINT_ALLOWLIST: set[str] = Field(
        default={"api.groq.com"},
        description="Allowlist of approved LLM hostnames",
    )

    # =========================================================================
    # 7. OCR & Vision Settings
    # =========================================================================
    TESSERACT_CMD: str = Field(
        default=r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        description="Filesystem path to Tesseract OCR executable",
    )
    MAX_IMAGE_DIMENSION: int = Field(default=4096, description="Max allowed image width or height")

    # =========================================================================
    # 8. URL Risk Engine Detection Heuristics & Thresholds
    # =========================================================================
    ENTROPY_HOSTNAME_THRESHOLD: float = Field(default=3.8, description="Shannon entropy threshold for hostnames")
    ENTROPY_MIN_LENGTH: int = Field(default=8, description="Minimum hostname length to calculate entropy")

    SUSPICIOUS_TLDS: set[str] = Field(
        default={
            # Dot-prefixed for endswith check
            ".zip",
            ".top",
            ".xyz",
            ".country",
            ".kim",
            ".work",
            ".click",
            ".gq",
            ".ml",
            ".cf",
            ".ga",
            ".tk",
            ".surf",
            ".buzz",
            ".cam",
            ".fit",
            ".casa",
            ".rest",
            ".monster",
            ".club",
            ".loan",
            ".link",
            ".guru",
            ".live",
            ".beauty",
            ".hair",
            ".quest",
            ".cyou",
            ".sbs",
            # Stripped for direct membership check
            "zip",
            "top",
            "xyz",
            "country",
            "kim",
            "work",
            "click",
            "gq",
            "ml",
            "cf",
            "ga",
            "tk",
            "surf",
            "buzz",
            "cam",
            "fit",
            "casa",
            "rest",
            "monster",
            "club",
            "loan",
            "link",
            "guru",
            "live",
            "beauty",
            "hair",
            "quest",
            "cyou",
            "sbs",
        }
    )

    CREDENTIAL_KEYWORDS: set[str] = Field(
        default={
            "login",
            "signin",
            "verify",
            "verification",
            "account",
            "secure",
            "update",
            "kyc",
            "password",
            "otp",
            "auth",
            "authenticate",
            "credential",
            "passcode",
            "reset-password",
            "recover",
            "unlock",
        }
    )

    FINANCIAL_KEYWORDS: set[str] = Field(
        default={
            "payment",
            "refund",
            "billing",
            "invoice",
            "wallet",
            "checkout",
            "banking",
            "transfer",
            "crypto",
            "bitcoin",
            "usdt",
        }
    )

    URGENCY_KEYWORDS: set[str] = Field(
        default={
            "suspended",
            "immediate",
            "urgent",
            "blocked",
            "action-required",
            "warning",
            "alert",
            "expire",
            "limited-time",
            "deadline",
        }
    )

    TRUSTED_DOMAINS: list[str] = Field(
        default=[
            "google.com",
            "microsoft.com",
            "apple.com",
            "paypal.com",
            "amazon.com",
            "facebook.com",
            "netflix.com",
            "github.com",
            "instagram.com",
            "twitter.com",
            "x.com",
            "linkedin.com",
            "chase.com",
            "wellsfargo.com",
            "bankofamerica.com",
            "citibank.com",
            "stripe.com",
            "dropbox.com",
            "whatsapp.com",
            "telegram.org",
            "adobe.com",
            "yahoo.com",
        ]
    )

    BRAND_DOMAINS: dict[str, list[str]] = Field(
        default={
            "paypal": ["paypal.com"],
            "google": ["google.com"],
            "microsoft": ["microsoft.com", "live.com", "office.com"],
            "apple": ["apple.com", "icloud.com"],
            "amazon": ["amazon.com", "aws.amazon.com"],
            "netflix": ["netflix.com"],
            "github": ["github.com"],
            "chase": ["chase.com"],
            "wellsfargo": ["wellsfargo.com"],
            "bankofamerica": ["bankofamerica.com"],
            "citibank": ["citibank.com"],
            "stripe": ["stripe.com"],
            "dropbox": ["dropbox.com"],
            "whatsapp": ["whatsapp.com"],
            "telegram": ["telegram.org"],
            "facebook": ["facebook.com", "meta.com"],
            "instagram": ["instagram.com"],
            "linkedin": ["linkedin.com"],
        }
    )

    # =========================================================================
    # 9. Message Verification Risk Thresholds & Weights
    # =========================================================================
    THRESHOLD_LOW: int = Field(default=24, description="Upper bound for LOW risk (0-24)")
    THRESHOLD_MEDIUM: int = Field(default=49, description="Upper bound for MEDIUM risk (25-49)")
    THRESHOLD_HIGH: int = Field(default=74, description="Upper bound for HIGH risk (50-74)")

    # Base Signal Weights
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

    BASE_SCORE_CAP: int = Field(default=60)
    CRITICAL_SAFETY_FLOOR: int = Field(default=50)

    # Brand allowlists and shorteners
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

    URL_SHORTENERS: set[str] = Field(
        default={
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "buff.ly",
            "ow.ly",
            "cutt.ly",
            "rebrand.ly",
            "shorturl.at",
            "rb.gy",
            "tiny.cc",
            "qr.ae",
            "s.id",
            "v.gd",
            "t.ly",
            "bl.ink",
        }
    )

    VALID_UPI_HANDLES: set[str] = Field(
        default={
            "okhdfcbank",
            "okaxis",
            "okicici",
            "oksbi",
            "paytm",
            "ybl",
            "ibl",
            "axl",
            "upi",
            "apl",
            "postbank",
            "federal",
            "indus",
            "kotak",
            "barodampay",
            "pnb",
            "rbl",
            "aubank",
            "idfcbank",
            "yesbank",
        }
    )

    # =========================================================================
    # Validators
    # =========================================================================
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


def get_settings() -> Settings:
    """Return the global Settings instance."""
    return settings
