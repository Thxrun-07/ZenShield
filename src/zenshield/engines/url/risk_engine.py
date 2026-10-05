"""Centralized Risk Engine for ZenShield.

Integrates:
- URL Normalization
- Local IOC / Reputation Lookups
- Typosquatting Detection
- Punycode & Homoglyph Detection
- Shannon Entropy Analysis
- Structural URL Heuristics
- Brand Impersonation Detection

Computes:
- Weighted risk score (capped 0-100)
- Risk level (LOW, CAUTION, HIGH, CRITICAL)
- Classification (Safe, Low Risk, Suspicious, Potential Phishing, Known Malicious)
- Signal agreement confidence score (0.0 to 1.0)
- Actionable user recommendation
"""

from zenshield.config import settings
from zenshield.models.schemas import (
    Classification,
    RiskLevel,
    Signal,
    SignalSeverity,
    URLVerificationResponse,
)
from zenshield.services.brand_impersonation import BrandImpersonationDetector
from zenshield.services.entropy import EntropyAnalyzer
from zenshield.services.heuristics import HeuristicDetector
from zenshield.services.punycode_homoglyph import PunycodeHomoglyphDetector
from zenshield.services.reputation.base import BaseReputationProvider
from zenshield.services.reputation.local_sqlite import SQLiteReputationProvider
from zenshield.services.typosquatting import TyposquattingDetector
from zenshield.services.url_normalizer import normalize_url


class RiskEngine:
    """Central risk assessment engine for static URL analysis."""

    def __init__(
        self,
        reputation_provider: BaseReputationProvider | None = None,
        typosquatting_detector: TyposquattingDetector | None = None,
        punycode_detector: PunycodeHomoglyphDetector | None = None,
        entropy_analyzer: EntropyAnalyzer | None = None,
        heuristic_detector: HeuristicDetector | None = None,
        brand_detector: BrandImpersonationDetector | None = None,
    ):
        self.reputation = reputation_provider or SQLiteReputationProvider()
        self.typosquatting = typosquatting_detector or TyposquattingDetector()
        self.punycode = punycode_detector or PunycodeHomoglyphDetector()
        self.entropy = entropy_analyzer or EntropyAnalyzer()
        self.heuristics = heuristic_detector or HeuristicDetector()
        self.brand = brand_detector or BrandImpersonationDetector()

    def analyze(self, raw_url: str) -> URLVerificationResponse:
        """Execute full static URL analysis pipeline and calculate risk."""
        # 1. Normalization
        norm_url = normalize_url(raw_url)

        if not norm_url.is_valid:
            # Handle invalid or malformed URL gracefully
            err_signal = Signal(
                name="Malformed URL",
                severity=SignalSeverity.LOW,
                evidence=norm_url.error or "The URL could not be parsed into a valid hostname",
            )
            return URLVerificationResponse(
                risk_score=5,
                risk_level=RiskLevel.LOW,
                classification=Classification.LOW_RISK,
                confidence=0.5,
                known_ioc=False,
                signals=[err_signal],
                recommendation="URL appears malformed or incomplete. Verify before accessing.",
            )

        signals: list[Signal] = []
        is_known_ioc = False

        # 2. Local IOC / Reputation Database Check
        rep_result = self.reputation.check(norm_url)
        if rep_result.is_known_ioc:
            is_known_ioc = True
            sev = rep_result.severity or SignalSeverity.CRITICAL
            source_lbl = f" ({rep_result.source})" if rep_result.source else ""
            desc = f": {rep_result.description}" if rep_result.description else ""
            signals.append(
                Signal(
                    name="Known malicious IOC",
                    severity=sev,
                    evidence=f"Matched active threat indicator '{rep_result.indicator}' in reputation database{source_lbl}{desc}",
                )
            )

        # Check if domain is a legitimate trusted domain (e.g. google.com, github.com)
        is_trusted_domain = (
            norm_url.registered_domain.lower() in [d.lower() for d in settings.TRUSTED_DOMAINS] and not is_known_ioc
        )

        # 3. Domain Analysis: Typosquatting
        typo_signals = self.typosquatting.detect(norm_url)
        signals.extend(typo_signals)

        # 4. Punycode / Homoglyph Detection
        puny_signals = self.punycode.detect(norm_url)
        signals.extend(puny_signals)

        # 5. Shannon Entropy Analysis
        entropy_signals = self.entropy.detect(norm_url)
        signals.extend(entropy_signals)

        # 6. Structural URL Heuristics
        heur_signals = self.heuristics.detect(norm_url)
        # If domain is trusted, contextual path lures (like /login on github.com) are benign
        if is_trusted_domain:
            heur_signals = [
                s
                for s in heur_signals
                if s.name not in ("Credential-related path", "Financial/payment intent", "Urgency-inducing keyword")
            ]
        signals.extend(heur_signals)

        # 7. Brand Impersonation
        brand_signals = self.brand.detect(norm_url)
        signals.extend(brand_signals)

        # 8. Central Score Calculation
        score = self._calculate_risk_score(is_known_ioc, signals, rep_result.source)

        # 9. Risk Level
        risk_level = self._determine_risk_level(score)

        # 10. Classification
        classification = self._determine_classification(is_known_ioc, score, signals)

        # 11. Confidence Calculation
        confidence = self._calculate_confidence(is_known_ioc, is_trusted_domain, score, classification, signals)

        # 12. Recommendation
        recommendation = self._generate_recommendation(classification)

        return URLVerificationResponse(
            risk_score=score,
            risk_level=risk_level,
            classification=classification,
            confidence=confidence,
            known_ioc=is_known_ioc,
            signals=signals,
            recommendation=recommendation,
        )

    def _calculate_risk_score(self, is_known_ioc: bool, signals: list[Signal], rep_source: str | None) -> int:
        """Compute capped engineering risk score (0-100) using defined weights."""
        score = 0

        # Weights per prompt guidelines:
        # Known malicious IOC +40 (+15 if community source)
        if is_known_ioc:
            score += 40
            if rep_source and "community" in rep_source.lower():
                score += 15

        for sig in signals:
            name = sig.name

            if "Brand impersonation" in name:
                score += 20
            elif "Typosquatting" in name:
                score += 15
            elif "Homoglyph" in name or "Mixed-script" in name or "Punycode" in name:
                if sig.severity == SignalSeverity.HIGH:
                    score += 15
                else:
                    score += 8
            elif "Credential-related" in name:
                score += 15
            elif "Financial" in name:
                score += 10
            elif "Urgency" in name:
                score += 8
            elif "Raw IP address" in name:
                score += 15
            elif "Obfuscated URL" in name:
                score += 20
            elif "Suspicious TLD" in name:
                score += 12
            elif "Non-standard port" in name:
                score += 10
            elif "High entropy" in name or "Excessive" in name:
                score += 5
            elif "Nested or open redirect" in name:
                score += 10

        # Known malicious IOCs should always meet or exceed CRITICAL baseline (75)
        if is_known_ioc:
            score = max(score, 80)

        # Cap between 0 and 100
        return max(0, min(100, score))

    def _determine_risk_level(self, score: int) -> RiskLevel:
        """Map score to engineering risk level:
        0–24: LOW
        25–49: CAUTION
        50–74: HIGH
        75–100: CRITICAL
        """
        if score >= 75:
            return RiskLevel.CRITICAL
        elif score >= 50:
            return RiskLevel.HIGH
        elif score >= 25:
            return RiskLevel.CAUTION
        return RiskLevel.LOW

    def _determine_classification(self, is_known_ioc: bool, score: int, signals: list[Signal]) -> Classification:
        """Determine explainable classification:
        Known malicious IOC -> Known Malicious
        Multiple strong suspicious signals or high score -> Potential Phishing
        Several moderate signals or caution score -> Suspicious
        Only weak or isolated contextual signals -> Low Risk
        No meaningful suspicious signals -> Safe
        """
        if is_known_ioc:
            return Classification.KNOWN_MALICIOUS

        high_signals = sum(1 for s in signals if s.severity in (SignalSeverity.HIGH, SignalSeverity.CRITICAL))
        med_signals = sum(1 for s in signals if s.severity == SignalSeverity.MEDIUM)
        low_signals = sum(1 for s in signals if s.severity == SignalSeverity.LOW)

        # 1. Multiple strong signals or high critical score
        if score >= 70 or high_signals >= 2 or (high_signals >= 1 and med_signals >= 2):
            return Classification.POTENTIAL_PHISHING

        # 2. Several moderate signals or high combined caution score
        if score >= 50 or (high_signals >= 1 and med_signals >= 1):
            return Classification.POTENTIAL_PHISHING
        elif score >= 25 or med_signals >= 2 or high_signals >= 1:
            return Classification.SUSPICIOUS

        # 3. Only weak or isolated contextual signals (e.g. lone /login on benign unknown domain)
        if score > 0 or med_signals == 1 or low_signals > 0:
            return Classification.LOW_RISK

        return Classification.SAFE

    def _calculate_confidence(
        self,
        is_known_ioc: bool,
        is_trusted_domain: bool,
        score: int,
        classification: Classification,
        signals: list[Signal],
    ) -> float:
        """Calculate confidence based on signal agreement and evidence strength.

        NOTE: Confidence represents certainty in the classification, NOT risk_score/100.
        - Known IOC or verified trusted domain: very high certainty (0.92 - 0.98)
        - Multi-signal consensus: high certainty (0.85 - 0.92)
        - Ambiguous / isolated weak signal: moderate certainty (0.50 - 0.65)
        - Completely clean URL: high certainty of being Safe (0.85 - 0.90)
        """
        if is_known_ioc:
            return 0.98

        if is_trusted_domain and not signals:
            return 0.95

        high_count = sum(1 for s in signals if s.severity in (SignalSeverity.HIGH, SignalSeverity.CRITICAL))
        med_count = sum(1 for s in signals if s.severity == SignalSeverity.MEDIUM)

        # Multiple concurring high-confidence signals
        if high_count >= 2:
            return 0.92
        elif high_count == 1 and med_count >= 1:
            return 0.88
        elif high_count == 1:
            return 0.80
        elif med_count >= 2:
            return 0.78
        elif med_count == 1:
            # Single contextual medium signal (e.g. lone /login on unknown site)
            return 0.60
        elif signals:
            # Only weak heuristics (entropy, length, etc.)
            return 0.55

        # No signals, unlisted domain
        return 0.85

    def _generate_recommendation(self, classification: Classification) -> str:
        """Generate clear user-facing recommendation."""
        recommendations = {
            Classification.SAFE: "No significant suspicious indicators were detected.",
            Classification.LOW_RISK: "Proceed with normal caution and verify the destination.",
            Classification.SUSPICIOUS: "Verify the domain before entering credentials or personal information.",
            Classification.POTENTIAL_PHISHING: "Avoid entering credentials, OTPs, or payment information.",
            Classification.KNOWN_MALICIOUS: "Do not open this link or provide any personal, financial, or authentication information.",
        }
        return recommendations.get(classification, "Proceed with normal caution and verify the destination.")
