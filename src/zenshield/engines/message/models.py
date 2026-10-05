"""Domain models for message verification, language detection, intent matching, and scoring."""

from enum import StrEnum

from pydantic import BaseModel, Field

from zenshield.privacy.models import URLMetadata


class RiskLevel(StrEnum):
    """Risk severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Classification(StrEnum):
    """Categorical classification of message safety."""

    LIKELY_SAFE = "Likely Safe"
    SUSPICIOUS = "Suspicious"
    POTENTIAL_PHISHING = "Potential Phishing"
    HIGH_RISK_SCAM = "High-Risk Scam"


class LanguageResult(BaseModel):
    """Language and script detection analysis."""

    language: str = Field(..., description="English, Tamil, Tanglish, Mixed, or Unknown")
    confidence: float = Field(..., ge=0.0, le=1.0)
    script: str = Field(..., description="Dominant script: Latin, Tamil, Mixed, or Unknown")
    is_mixed: bool = Field(default=False)
    indicators: list[str] = Field(default_factory=list, description="Safe detected keyword or grammar indicators")


class IntentMatch(BaseModel):
    """Detected user or message intent."""

    intent: str = Field(..., description="One of the 23 enumerated fraud/service intents")
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: str = Field(..., description="Safe rule ID or generic explanation; never raw user text")
    matched_terms: list[str] = Field(default_factory=list, description="Canonical matched lexicon terms")


class RiskSignal(BaseModel):
    """A specific risk signal emitted by the pattern or scoring engine."""

    name: str = Field(..., description="Human-readable signal name")
    category: str = Field(..., description="Signal category (e.g. urgency, credential_request, threat)")
    severity: str = Field(..., description="low, medium, high, or critical")
    evidence: str = Field(..., description="Safe description of the rule fired; never raw user message spans")
    weight: int = Field(..., ge=0, description="Base score weight contribution")
    confidence: float = Field(..., ge=0.0, le=1.0)
    rule_id: str = Field(..., description="Deterministic rule identifier")


class SignalResponse(BaseModel):
    """Signal structure in the API response contract."""

    id: str = Field(..., description="Unique signal identifier")
    weight: int = Field(..., ge=0)
    rule_id: str = Field(...)
    name: str = Field(default="", description="Human-readable signal name")
    severity: str = Field(default="medium", description="Severity: low, medium, high, critical")
    evidence: str = Field(default="", description="Safe explainable evidence")
    category: str = Field(default="", description="Signal category")


class BonusItem(BaseModel):
    """Combination bonus detail in scoring breakdown."""

    name: str = Field(...)
    weight: int = Field(...)
    rule_id: str = Field(...)


class ScoreBreakdown(BaseModel):
    """Explainable scoring computation breakdown."""

    base_raw: int = Field(..., description="Sum of raw distinct signal weights")
    base_capped: int = Field(..., description="Base score capped at 60")
    bonuses: list[BonusItem] = Field(default_factory=list, description="Non-linear combination bonuses triggered")
    llm_delta: int = Field(default=0, description="Bounded adjustment from LLM [-10, +10]")
    anchors_applied: list[str] = Field(default_factory=list, description="Safety floors applied (e.g. floor 50)")
    final: int = Field(..., ge=0, le=100, description="Final calibrated risk score [0, 100]")


class PrivacySummary(BaseModel):
    """Privacy preservation confirmation."""

    pii_detected: bool = Field(...)
    external_text_sent: bool = Field(default=False)
    masked_message: str = Field(...)


class AnalysisSummary(BaseModel):
    """Execution engine summary."""

    rule_based: bool = Field(default=True)
    llm_used: bool = Field(default=False)


class AnalysisResult(BaseModel):
    """Complete response contract for POST /api/v1/verify/message."""

    request_id: str = Field(...)
    score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel = Field(...)
    classification: Classification = Field(...)
    language: str = Field(...)
    intents: list[str] = Field(default_factory=list)
    signals: list[SignalResponse] = Field(default_factory=list)
    breakdown: ScoreBreakdown = Field(...)
    url_metadata: list[URLMetadata] = Field(default_factory=list)
    masked_entity_counts: dict[str, int] = Field(default_factory=dict)
    llm_used: bool = Field(default=False)
    privacy: PrivacySummary = Field(...)
    analysis: AnalysisSummary = Field(...)
