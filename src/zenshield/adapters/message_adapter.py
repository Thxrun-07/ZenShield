"""Unified Message adapter connecting Message Verification Engine and URL Pipeline."""

import asyncio
import concurrent.futures

from zenshield.adapters.url_adapter import URLAdapter
from zenshield.engines.message.analyzer import MessageAnalyzer
from zenshield.privacy.url_extractor import URLExtractor
from zenshield.schemas.risk import (
    RiskLevel,
    RiskResult,
    UnifiedSignal,
    map_message_result_to_unified,
)


def _run_async(coro):
    """Executes an async coroutine synchronously from any thread or running event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


class MessageAdapter:
    """
    Adapter boundary for SMS / Message phishing detection engine.
    Integrates multilingual Tanglish/Tamil message analysis, PII masking,
    and embedded URL inspection.
    """

    def __init__(
        self,
        analyzer: MessageAnalyzer | None = None,
        url_adapter: URLAdapter | None = None,
    ):
        self.analyzer = analyzer or MessageAnalyzer()
        self.url_adapter = url_adapter or URLAdapter()
        self.url_extractor = URLExtractor()

    def analyze_message(self, message: str, request_id: str | None = None) -> RiskResult:
        """Synchronous message analysis entry point."""
        return _run_async(self.analyze_message_async(message, request_id))

    async def analyze_message_async(self, message: str, request_id: str | None = None) -> RiskResult:
        """
        Asynchronous message analysis pipeline:
        1. Multilingual intent, lexicon, and pattern analysis with privacy masking
        2. Extraction and nested evaluation of embedded URLs via URLAdapter
        3. Score calibration and unified signal aggregation
        """
        # 1. Primary message engine analysis
        msg_result = await self.analyzer.analyze(
            message=message,
            country="IN",
            channel="sms",
            enable_llm=False,
            request_id=request_id,
        )

        assessment = map_message_result_to_unified(msg_result, request_id=request_id)
        final_score = assessment.score
        signals = list(assessment.signals)
        known_ioc = False

        # 2. Extract and inspect embedded URLs
        extracted_urls = self.url_extractor.extract_urls(message)
        for _start, _end, original_url, meta in extracted_urls:
            url_risk = self.url_adapter.analyze_url(original_url, request_id=request_id)
            if url_risk.known_ioc:
                known_ioc = True
                final_score = max(final_score, 85)
                signals.append(
                    UnifiedSignal(
                        id=f"msg_embedded_ioc_{meta.registrable_domain}",
                        name="Embedded malicious URL IOC",
                        severity="critical",
                        evidence=f"Message contains known malicious URL IOC: {meta.registrable_domain}",
                    )
                )
            elif url_risk.score >= 50 or url_risk.is_risky:
                final_score = max(final_score, url_risk.score)
                signals.append(
                    UnifiedSignal(
                        id=f"msg_embedded_url_{meta.registrable_domain}",
                        name="High-risk embedded URL",
                        severity="high",
                        evidence=f"Embedded link '{meta.registrable_domain}' flagged with risk score {url_risk.score}",
                    )
                )

        # 3. Recalibrate risk level based on final score
        if final_score >= 75:
            level = RiskLevel.CRITICAL
        elif final_score >= 50:
            level = RiskLevel.HIGH
        elif final_score >= 25:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        reasons = [s.evidence for s in signals if s.evidence]

        # Attach masked content for privacy
        masked_text = msg_result.privacy.masked_message if hasattr(msg_result, "privacy") else message

        res = RiskResult(
            is_risky=(final_score >= 50),
            risk_score=round(final_score / 100.0, 2),
            risk_level=level.value.lower(),
            reasons=reasons,
            score=final_score,
            level=level,
            classification=assessment.classification,
            confidence=assessment.confidence,
            signals=signals,
            known_ioc=known_ioc,
            recommendation=assessment.recommendation,
            request_id=request_id,
        )
        # Store masked message in object attribute
        res._masked_message = masked_text
        return res
