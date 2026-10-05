"""Unified URL adapter connecting URL Risk Engine and Threat Intelligence."""

import asyncio

from zenshield.core.config import settings
from zenshield.engines.url.reputation.database_provider import DatabaseReputationProvider
from zenshield.engines.url.risk_engine import RiskEngine
from zenshield.engines.url.schemas import RiskLevel as URLRiskLevel
from zenshield.engines.url.schemas import Signal, SignalSeverity
from zenshield.engines.url.url_normalizer import normalize_url
from zenshield.schemas.risk import RiskResult, map_url_result_to_unified
from zenshield.services.threat_service import VirusTotalProvider


class URLAdapter:
    """
    Adapter boundary for URL phishing detection engine.
    Integrates static heuristic risk engine with database threat intelligence and external VT.
    """

    def __init__(
        self,
        risk_engine: RiskEngine | None = None,
        vt_provider: VirusTotalProvider | None = None,
    ):
        self.risk_engine = risk_engine or RiskEngine(reputation_provider=DatabaseReputationProvider())
        self.vt_provider = vt_provider or VirusTotalProvider()

    def analyze_url(self, url: str, request_id: str | None = None) -> RiskResult:
        """
        Synchronous URL analysis entry point.
        Evaluates URL statically without issuing HTTP requests to the target URL.
        """
        # 1. Run static URL Risk Engine
        url_resp = self.risk_engine.analyze(url)

        # 2. Check Threat Intelligence IOC Database
        norm_url = normalize_url(url)
        db_rep = DatabaseReputationProvider().check(norm_url)
        known_ioc = url_resp.known_ioc or db_rep.is_known_ioc

        final_score = url_resp.risk_score
        signals = list(url_resp.signals)

        if db_rep.is_known_ioc:
            known_ioc = True
            # Raise score to at least 80 (CRITICAL) for known IOCs
            final_score = max(final_score, 85)
            # Add threat intelligence signal if not already present
            if not any("IOC" in s.name for s in signals):
                signals.append(
                    Signal(
                        name="Threat intelligence match",
                        severity=SignalSeverity.CRITICAL,
                        evidence=f"Matched active community threat IOC: {db_rep.indicator} ({db_rep.description or 'Known phishing threat'})",
                    )
                )

        # 3. Check External VirusTotal Provider if configured & enabled
        if self.vt_provider and settings.ENABLE_EXTERNAL_REPUTATION:
            vt_res = self.vt_provider.lookup_indicator(url, indicator_type="url")
            if vt_res.is_flagged:
                known_ioc = True
                final_score = max(final_score, 90)
                signals.append(
                    Signal(
                        name="External threat intelligence match",
                        severity=SignalSeverity.CRITICAL,
                        evidence=f"Flagged by VirusTotal ({vt_res.malicious_count}/{vt_res.total_engines} engines)",
                    )
                )

        # Update response object fields
        url_resp.risk_score = final_score
        url_resp.known_ioc = known_ioc
        url_resp.signals = signals
        if final_score >= 75:
            url_resp.risk_level = URLRiskLevel.CRITICAL
        elif final_score >= 50:
            url_resp.risk_level = URLRiskLevel.HIGH
        elif final_score >= 25:
            url_resp.risk_level = URLRiskLevel.CAUTION
        else:
            url_resp.risk_level = URLRiskLevel.LOW

        # Map to unified RiskAssessment / RiskResult
        assessment = map_url_result_to_unified(url_resp, request_id=request_id)

        return RiskResult(
            is_risky=assessment.is_risky,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            reasons=assessment.reasons,
            score=assessment.score,
            level=assessment.level,
            classification=assessment.classification,
            confidence=assessment.confidence,
            signals=assessment.signals,
            known_ioc=assessment.known_ioc,
            recommendation=assessment.recommendation,
            request_id=assessment.request_id,
        )

    async def analyze_url_async(self, url: str, request_id: str | None = None) -> RiskResult:
        """Asynchronous wrapper running blocking static analysis in a threadpool."""
        return await asyncio.to_thread(self.analyze_url, url, request_id)
