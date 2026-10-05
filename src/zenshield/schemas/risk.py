"""Unified Risk Schema and Mappers for ZenShield.

Harmonizes contracts across:
- Main Orchestration layer (0.0-1.0 risk_score, low|medium|high)
- URL Risk Engine (0-100 score, LOW|CAUTION|HIGH|CRITICAL)
- Message Verification Engine (0-100 score, LOW|MEDIUM|HIGH|CRITICAL)

Maintains full additive backward compatibility for legacy frontends.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class RiskLevel(StrEnum):
    """Unified risk level taxonomy."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SignalSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UnifiedSignal(BaseModel):
    """Explainable, zero-leakage threat signal."""

    id: str = Field(..., description="Unique or canonical signal identifier")
    name: str = Field(default="", description="Human-readable signal name")
    severity: SignalSeverity | str = Field(default=SignalSeverity.MEDIUM, description="Severity rating")
    evidence: str = Field(..., description="Safe description / evidence; NEVER raw user content")
    weight: int | None = Field(default=None, description="Score contribution weight")
    max_weight: int | None = Field(default=None, description="Maximum possible score weight for this category")
    rule_id: str | None = Field(default=None, description="Underlying detection rule identifier")


class RiskAssessment(BaseModel):
    """
    Unified production response contract for ZenShield threat evaluations.
    """

    score: int = Field(..., ge=0, le=100, description="Risk score (0 - 100)")
    level: RiskLevel = Field(..., description="Categorical risk level (LOW, MEDIUM, HIGH, CRITICAL)")
    classification: str = Field(default="Safe", description="Threat classification label")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0, description="Confidence score")
    signals: list[UnifiedSignal] = Field(default_factory=list, description="Explainable detection signals")
    known_ioc: bool = Field(default=False, description="Flag indicating presence in threat intelligence registry")
    recommendation: str = Field(default="No threat detected.", description="Safe, actionable user recommendation")
    request_id: str | None = Field(default=None, description="Tracing request ID")

    # =========================================================================
    # Additive legacy-compatible fields (prevents breaking legacy frontends)
    # =========================================================================
    is_risky: bool = Field(default=False, description="Legacy boolean risk flag")
    risk_score: float = Field(default=0.0, description="Legacy normalized score (0.0 - 1.0)")
    risk_level: str = Field(default="low", description="Legacy lowercase level: low|medium|high|critical")
    reasons: list[str] = Field(default_factory=list, description="Legacy string evidence list")

    @model_validator(mode="after")
    def populate_legacy_fields(self) -> "RiskAssessment":
        # Synchronize risk_score
        if not self.risk_score and self.score:
            self.risk_score = round(self.score / 100.0, 2)
        elif self.risk_score and not self.score:
            self.score = int(round(self.risk_score * 100))

        # Synchronize is_risky
        if self.score >= 50 or self.level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            self.is_risky = True

        # Synchronize risk_level
        self.risk_level = self.level.value.lower()

        # Synchronize reasons
        if not self.reasons and self.signals:
            self.reasons = [s.evidence for s in self.signals if s.evidence]
        return self


class RiskResult(RiskAssessment):
    """
    Direct alias and subclass of RiskAssessment providing drop-in compatibility
    with legacy test suites expecting `RiskResult(is_risky=..., risk_score=..., risk_level=..., reasons=...)`.
    """

    _masked_message: str | None = None

    def __init__(
        self,
        is_risky: bool | None = None,
        risk_score: float | None = None,
        risk_level: str | None = None,
        reasons: list[str] | None = None,
        score: int | None = None,
        level: RiskLevel | None = None,
        **kwargs: Any,
    ):
        # Infer unified fields if instantiated using legacy arguments
        calc_score = score
        if calc_score is None:
            if risk_score is not None:
                calc_score = int(round(risk_score * 100))
            elif is_risky:
                calc_score = 80
            else:
                calc_score = 10

        calc_level = level
        if calc_level is None:
            rl_str = (risk_level or "low").upper()
            if rl_str == "CAUTION":
                calc_level = RiskLevel.MEDIUM
            elif rl_str in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                calc_level = RiskLevel(rl_str)
            else:
                calc_level = RiskLevel.MEDIUM if is_risky else RiskLevel.LOW

        signals = kwargs.pop("signals", [])
        if not signals and reasons:
            signals = [
                UnifiedSignal(id=f"legacy_signal_{i}", name="Detection Flag", evidence=r) for i, r in enumerate(reasons)
            ]

        super().__init__(
            score=calc_score,
            level=calc_level,
            is_risky=is_risky if is_risky is not None else (calc_score >= 50),
            risk_score=risk_score if risk_score is not None else round(calc_score / 100.0, 2),
            risk_level=(risk_level.lower() if risk_level else calc_level.value.lower()),
            reasons=reasons or [],
            signals=signals,
            **kwargs,
        )


def map_level_to_unified(raw_level: Any) -> RiskLevel:
    """Explicit documented level mapping: converts engine levels (including CAUTION -> MEDIUM)."""
    if isinstance(raw_level, RiskLevel):
        return raw_level
    val = getattr(raw_level, "value", raw_level)
    val = str(val).upper().strip()
    if val in ("CAUTION", "MODERATE", "WARNING"):
        return RiskLevel.MEDIUM
    if val in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return RiskLevel(val)
    return RiskLevel.LOW


def map_url_result_to_unified(url_res: Any, request_id: str | None = None) -> RiskAssessment:
    """Mappers for output of URL Risk Engine (RiskEngine.analyze)."""
    unified_level = map_level_to_unified(getattr(url_res, "risk_level", "LOW"))
    signals = []

    URL_WEIGHT_MAP = {
        "brand impersonation": (20, 25),
        "typosquatting": (15, 20),
        "mixed-script": (15, 15),
        "homoglyph": (15, 15),
        "punycode": (15, 15),
        "entropy": (10, 15),
        "known malicious ioc": (40, 40),
        "credential": (15, 20),
        "financial": (10, 20),
        "urgency": (10, 15),
    }

    for s in getattr(url_res, "signals", []):
        sig_name = getattr(s, "name", "URL Signal")
        w, max_w = (10, 15)
        name_lower = sig_name.lower()
        for k, (kw, kmax) in URL_WEIGHT_MAP.items():
            if k in name_lower:
                w, max_w = (kw, kmax)
                break

        signals.append(
            UnifiedSignal(
                id=sig_name.lower().replace(" ", "_"),
                name=sig_name,
                severity=getattr(s, "severity", "medium"),
                evidence=getattr(s, "evidence", ""),
                weight=w,
                max_weight=max_w,
            )
        )

    score = int(getattr(url_res, "risk_score", 0))
    return RiskAssessment(
        score=score,
        level=unified_level,
        classification=str(getattr(url_res, "classification", "Safe")),
        confidence=float(getattr(url_res, "confidence", 0.85)),
        signals=signals,
        known_ioc=bool(getattr(url_res, "known_ioc", False)),
        recommendation=str(getattr(url_res, "recommendation", "")),
        request_id=request_id,
    )


def map_message_result_to_unified(msg_res: Any, request_id: str | None = None) -> RiskAssessment:
    """Mappers for output of Message Verification Engine (MessageAnalyzer.analyze)."""
    unified_level = map_level_to_unified(getattr(msg_res, "risk_level", "LOW"))
    signals = []
    categories = set()

    MSG_MAX_MAP = {
        "financial_request": 25,
        "impersonation": 25,
        "threat": 20,
        "social_engineering": 20,
        "call_to_action": 10,
        "credential_request": 30,
        "urgency": 15,
        "suspicious_url": 25,
    }

    for s in getattr(msg_res, "signals", []):
        cat = getattr(s, "category", "")
        if cat:
            categories.add(cat)
        sig_name = getattr(s, "name", None) or getattr(s, "rule_id", "Message Signal")
        sig_evidence = getattr(s, "evidence", None) or getattr(s, "rule_id", "Pattern fired")
        sig_sev = getattr(s, "severity", None) or ("high" if unified_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else "medium")
        w = getattr(s, "weight", None)
        max_w = MSG_MAX_MAP.get(cat) if cat else None
        if not max_w and w:
            max_w = max(w, 25)

        signals.append(
            UnifiedSignal(
                id=getattr(s, "id", None) or getattr(s, "rule_id", "msg_signal"),
                name=sig_name,
                severity=sig_sev,
                evidence=sig_evidence,
                weight=w,
                max_weight=max_w,
                rule_id=getattr(s, "rule_id", None),
            )
        )

    score = int(getattr(msg_res, "score", 0))

    # Generate context-aware, actionable security insights
    if "impersonation" in categories and ("threat" in categories or "financial_request" in categories):
        recommendation = (
            "Critical Scam Alert: Authority Impersonation & Penalty Extortion detected. "
            "Fraudsters impersonate Traffic Police or transport authorities with fabricated citations and fake discount codes (e.g., 'CHALLAN100'). "
            "Statutory government penalties NEVER offer coupon discounts. "
            "Do NOT click links, download APKs, or make payments. Verify directly on the official Parivahan portal (https://echallan.parivahan.gov.in)."
        )
    elif "credential_request" in categories:
        recommendation = (
            "Critical Security Alert: Active Credential Harvesting. "
            "This message solicits confidential credentials (OTP, PIN, passwords). "
            "Legitimate organizations never ask for your confidential codes via message."
        )
    elif "malware_risk" in categories:
        recommendation = (
            "Critical Threat: Malicious Application Delivery (APK/Sideloading). "
            "Do not download, install, or run files from this message. They can compromise your device."
        )
    elif "social_engineering" in categories and "financial_request" in categories:
        recommendation = (
            "High Risk: Financial Fraud & Social Engineering Lure. "
            "Deceptive discounts, fake rewards, or fees are used to induce payment. Do not proceed with payment."
        )
    elif score >= 75:
        recommendation = (
            "Critical Risk: Multiple cyber-fraud indicators detected. "
            "Do not click links, make transfers, or reply to this message."
        )
    elif score >= 50:
        recommendation = (
            "High Risk: Suspicious solicitation detected. Verify sender identity through official channels."
        )
    elif score >= 25:
        recommendation = (
            "Caution: Contains potential urgency or requests. Review carefully and verify sender legitimacy."
        )
    else:
        recommendation = "No significant threat detected. Message appears safe."

    return RiskAssessment(
        score=score,
        level=unified_level,
        classification=str(getattr(msg_res, "classification", "Likely Safe")),
        confidence=0.90,
        signals=signals,
        known_ioc=False,
        recommendation=recommendation,
        request_id=request_id or getattr(msg_res, "request_id", None),
    )
