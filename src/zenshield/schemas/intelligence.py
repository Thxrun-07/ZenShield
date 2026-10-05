"""Pydantic Schemas for ZenShield Threat Intelligence Module.

Defines data contracts for:
- Indicator normalization
- PII masking
- Community fraud reports
- Report confirmations
- Threat IOC registry entries
- IOC reputation lookup queries
- Regional alert summaries
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ==========================================
# 1. Normalization & Privacy Utility Schemas
# ==========================================


class IndicatorNormalizeRequest(BaseModel):
    raw_value: str = Field(..., description="Raw indicator string, e.g. '09876543210' or 'http://evil.com/login'")
    indicator_type: str | None = Field(
        None, description="Optional indicator type: phone, upi_id, email, url, domain, bank_account, or auto"
    )


class IndicatorNormalizeResponse(BaseModel):
    raw_value: str
    normalized_value: str
    detected_type: str


class PIIMaskRequest(BaseModel):
    text: str = Field(..., description="Report narrative that may contain victim PII")
    preserve_values: list[str] | None = Field(
        default=None, description="Indicators that belong to the scammer and should NOT be masked"
    )


class PIIMaskResponse(BaseModel):
    original_text: str
    masked_text: str
    pii_detected: dict[str, int]
    has_pii: bool


# ==========================================
# 2. Community Report Schemas
# ==========================================


class CommunityReportCreate(BaseModel):
    indicator_value: str = Field(
        ..., min_length=2, description="Target threat indicator, e.g. suspect phone, URL, or UPI ID"
    )
    indicator_type: str | None = Field(
        None, description="Type: phone, upi_id, email, url, domain, bank_account, other. Auto-detected if omitted."
    )
    title: str = Field(..., min_length=3, max_length=250, description="Short summary of the incident")
    description: str = Field(
        ..., min_length=10, description="Detailed account of how the fraud occurred (victim PII will be masked)"
    )
    region: str = Field(
        "Tamil Nadu", description="State or city where fraud targeted residents, e.g. Tamil Nadu, Chennai, Coimbatore"
    )
    fraud_category: str = Field(
        "phishing",
        description="Scam type: KYC Phishing, Electricity Bill Scam, Tanglish SMS Scam, UPI Payment Fraud, Part-time Job Scam, etc.",
    )
    amount_lost: float | None = Field(None, ge=0, description="Financial loss incurred in INR, if any")
    incident_date: datetime | None = None


class CommunityReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ioc_id: int | None = None
    indicator_value: str
    indicator_type: str
    title: str
    description: str
    raw_description_had_pii: bool
    region: str
    fraud_category: str
    amount_lost: float | None = None
    confirmation_count: int
    status: str
    incident_date: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ReportConfirmationCreate(BaseModel):
    comment: str | None = Field(
        None, max_length=500, description="Optional brief confirmation notes from another resident"
    )
    region: str | None = Field(None, description="Resident's region")


class ReportConfirmationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    report_id: int
    comment: str | None = None
    region: str | None = None
    created_at: datetime
    new_confirmation_count: int


# ==========================================
# 3. IOC Registry Schemas
# ==========================================


class IOCCreate(BaseModel):
    indicator_value: str = Field(..., description="Indicator string (will be normalized automatically)")
    indicator_type: str | None = Field(None, description="Type (auto-detected if None)")
    threat_category: str | None = Field(
        "phishing", description="Category: phishing, kyc_scam, upi_fraud, electricity_scam, etc."
    )
    threat_level: str | None = Field("medium", description="Severity: low, medium, high, critical")
    confidence_score: float | None = Field(50.0, ge=0.0, le=100.0)
    notes: str | None = None


class IOCUpdate(BaseModel):
    threat_category: str | None = None
    threat_level: str | None = None
    status: str | None = None
    confidence_score: float | None = None
    notes: str | None = None


class IOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator_value: str
    raw_value: str | None = None
    indicator_type: str
    threat_category: str | None = None
    threat_level: str
    confidence_score: float
    report_count: int
    confirmation_count: int
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    notes: str | None = None


# ==========================================
# 4. IOC Reputation Lookup Schemas
# ==========================================


class IOCReputationLookupRequest(BaseModel):
    indicator: str = Field(..., description="Indicator value to search (URL, domain, phone, UPI, email)")
    indicator_type: str | None = Field(None, description="Optional type hint")


class IOCIncidentSummary(BaseModel):
    report_id: int
    title: str
    region: str
    fraud_category: str
    amount_lost: float | None = None
    created_at: datetime


class IOCReputationResponse(BaseModel):
    indicator_value: str
    indicator_type: str
    is_known_threat: bool
    threat_level: str = Field(..., description="safe, low, medium, high, critical")
    risk_score: float = Field(..., description="Normalized risk score from 0.0 to 100.0")
    report_count: int
    confirmation_count: int
    categories: list[str]
    regions_affected: list[str]
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status: str = Field(..., description="clean, active, under_review, verified_malicious, resolved")
    summary: str
    recent_incidents: list[IOCIncidentSummary] = Field(default_factory=list)


# ==========================================
# 5. Regional Alert & Intelligence Feed Schemas
# ==========================================


class CategoryCount(BaseModel):
    category: str
    count: int


class RegionalAlertSummary(BaseModel):
    region: str
    active_threats_count: int
    total_reports: int
    total_financial_loss: float
    top_categories: list[CategoryCount]
    trending_iocs: list[str]
    alert_level: str = Field(..., description="low, elevated, high, severe")
    community_warning: str


# ==========================================
# 6. Community Report API Contract
# ==========================================

VALID_INDICATOR_TYPES = {
    "domain",
    "url",
    "phone",
    "upi_id",
    "email",
    "bank_account",
    "ip",
    "other",
}

VALID_THREAT_TYPES = {
    "phishing",
    "malware",
    "scam",
    "fraud",
    "impersonation",
    "ransomware",
    "kyc_scam",
    "loan_fraud",
    "lottery_scam",
    "job_fraud",
    "electricity_bill_scam",
    "upi_fraud",
    "other",
}


class ReportCreateRequest(BaseModel):
    indicator: str = Field(..., min_length=1, description="Indicator string")
    indicator_type: str = Field(
        ..., description="Type of indicator: domain, url, phone, upi_id, email, bank_account, ip, other"
    )
    threat_type: str = Field(..., description="Threat type: phishing, malware, scam, fraud, impersonation, etc.")
    description: str = Field(..., min_length=1, description="Description of the fraud attempt")
    evidence: str | None = Field(None, description="Evidence / details")
    location: str | None = Field(None, description="Location where fraud occurred")

    @field_validator("indicator_type")
    @classmethod
    def validate_indicator_type(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in VALID_INDICATOR_TYPES:
            raise ValueError(f"Invalid indicator_type '{v}'. Allowed types are: {sorted(list(VALID_INDICATOR_TYPES))}")
        return clean

    @field_validator("threat_type")
    @classmethod
    def validate_threat_type(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in VALID_THREAT_TYPES:
            raise ValueError(f"Invalid threat_type '{v}'. Allowed types are: {sorted(list(VALID_THREAT_TYPES))}")
        return clean


class ReportCreateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: int | str
    ioc_id: int | str
    new_ioc: bool
    report_count: int


# ==========================================
# 7. Reputation Check Schemas
# ==========================================


class KnownIOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    known: bool = True
    indicator: str
    indicator_type: str
    threat_type: str
    status: str = "active"
    confidence: float
    report_count: int


class UnknownIOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    known: bool = False
    indicator: str
    indicator_type: str
    message: str = "Indicator not present in local threat intelligence registry."
