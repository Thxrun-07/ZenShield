"""Pydantic schemas and data models for ZenShield API and analysis."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class SignalSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    LOW = "LOW"
    CAUTION = "CAUTION"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Classification(str, Enum):
    SAFE = "Safe"
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    POTENTIAL_PHISHING = "Potential Phishing"
    KNOWN_MALICIOUS = "Known Malicious"


class Signal(BaseModel):
    name: str = Field(..., description="Name of the detected heuristic or indicator")
    severity: SignalSeverity = Field(..., description="Severity level of the signal")
    evidence: str = Field(..., description="Clear, explainable reasoning for the signal")


class URLVerificationRequest(BaseModel):
    url: str = Field(..., description="The URL to be analyzed statically", min_length=1)


class URLVerificationResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0 to 100")
    risk_level: RiskLevel = Field(..., description="Risk category: LOW, CAUTION, HIGH, CRITICAL")
    classification: Classification = Field(..., description="Explainable threat classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in assessment between 0.0 and 1.0")
    known_ioc: bool = Field(..., description="Whether the URL/domain is a known IOC in the reputation database")
    signals: List[Signal] = Field(default_factory=list, description="List of explainable detection signals")
    recommendation: str = Field(..., description="Actionable recommendation for the user")


class IOCRecord(BaseModel):
    id: Optional[int] = None
    indicator: str
    indicator_type: str  # "domain" or "url"
    source: str          # "community", "internal", "cert", "abuse_ch", etc.
    severity: str        # "low", "medium", "high", "critical"
    description: Optional[str] = None
    created_at: Optional[str] = None


class NormalizedURL(BaseModel):
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    registered_domain: str
    subdomain: str
    path: str
    query: str
    port: Optional[int] = None
    is_ip: bool = False
    ip_address: Optional[str] = None
    is_punycode: bool = False
    unicode_domain: str = ""
    is_valid: bool = True
    error: Optional[str] = None
