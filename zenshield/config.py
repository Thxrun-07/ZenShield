"""Configuration settings for ZenShield."""

from pathlib import Path
from typing import Dict, List, Set
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "ZenShield"
    APP_VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_PATH: str = str(BASE_DIR / "zenshield" / "data" / "ioc.db")

    # Optional External Reputation Services
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    ENABLE_EXTERNAL_REPUTATION: bool = False

    # Detection Heuristics & Thresholds
    ENTROPY_HOSTNAME_THRESHOLD: float = 3.8
    ENTROPY_MIN_LENGTH: int = 8
    MAX_URL_LENGTH: int = 150
    MAX_HOSTNAME_LENGTH: int = 40
    MAX_SUBDOMAINS: int = 3
    MAX_HYPHENS_IN_DOMAIN: int = 2
    MAX_QUERY_PARAMS: int = 5

    # Suspicious TLDs commonly abused in phishing / scam campaigns
    SUSPICIOUS_TLDS: Set[str] = {
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
    }

    # Suspicious path segments & intents
    CREDENTIAL_KEYWORDS: Set[str] = {
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

    FINANCIAL_KEYWORDS: Set[str] = {
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

    URGENCY_KEYWORDS: Set[str] = {
        "suspended",
        "urgent",
        "action-required",
        "immediate",
        "warning",
        "alert",
        "notice",
        "expire",
        "expiring",
        "limited-time",
    }

    # Trusted domain whitelist for brand impersonation & typosquatting detection
    TRUSTED_DOMAINS: List[str] = [
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

    # Brand keywords to legitimate domain mapping
    BRAND_DOMAINS: Dict[str, List[str]] = {
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


settings = Settings()
