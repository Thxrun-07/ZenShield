"""Central Message Analyzer orchestrator for Zenshield.

Coordinates the zero-leakage pipeline across:
Sanitization -> PII Detection -> Deterministic Masking -> Language Detection
-> Intent Detection -> Pattern Matching -> Scoring -> Optional LLM -> Safe Response.
"""

import uuid

from backend.config import settings
from backend.message.intent import IntentDetector
from backend.message.language import LanguageDetector
from backend.message.llm import (
    NoOpLLMAnalyzer,
    SafeLLMEnricher,
    SanitizedLLMInput,
)
from backend.message.models import (
    AnalysisResult,
    AnalysisSummary,
    PrivacySummary,
    SignalResponse,
)
from backend.message.patterns import PatternMatcher
from backend.message.scoring import ScoringEngine
from backend.privacy.masker import Masker
from backend.privacy.pii_detector import PIIDetector
from backend.privacy.sanitizer import Sanitizer


class MessageAnalyzer:
    """Orchestrates end-to-end message verification with dependency injection."""

    def __init__(
        self,
        sanitizer: Sanitizer | None = None,
        pii_detector: PIIDetector | None = None,
        masker: Masker | None = None,
        language_detector: LanguageDetector | None = None,
        intent_detector: IntentDetector | None = None,
        pattern_matcher: PatternMatcher | None = None,
        scoring_engine: ScoringEngine | None = None,
        llm_enricher: SafeLLMEnricher | None = None,
    ):
        self.sanitizer = sanitizer or Sanitizer()
        self.pii_detector = pii_detector or PIIDetector()
        self.masker = masker or Masker()
        self.language_detector = language_detector or LanguageDetector()
        self.intent_detector = intent_detector or IntentDetector()
        self.pattern_matcher = pattern_matcher or PatternMatcher()
        self.scoring_engine = scoring_engine or ScoringEngine()
        self.llm_enricher = llm_enricher or SafeLLMEnricher(analyzer=NoOpLLMAnalyzer())

    async def analyze(
        self,
        message: str,
        country: str = "IN",
        channel: str = "sms",
        enable_llm: bool = False,
        request_id: str | None = None,
    ) -> AnalysisResult:
        """Analyze message through privacy pipeline and deterministic scoring.

        Guarantees:
        - Raw message never leaves memory
        - External LLM only receives masked message truncated to 1,000 chars
        - Residual-PII gate aborts LLM if any unmasked entity is detected
        """
        req_id = request_id or str(uuid.uuid4())

        # Stage 0: Validation, Normalization & Dual View construction
        dual_view = self.sanitizer.sanitize(message)

        # Stage 1: PII Detection with priority resolution
        detected_entities = self.pii_detector.detect(dual_view)

        # Stage 2: Deterministic Masking
        masked_res = self.masker.mask(dual_view.canonical_text, detected_entities)

        # Stage 3: Multilingual & Tanglish Detection
        lang_res = self.language_detector.detect(masked_res.masked_text)

        # Stage 4: Context-Aware Intent Detection
        detected_intents = self.intent_detector.detect(dual_view, lang_res.language)

        # Stage 5: Multi-Vector Risk Signal Pattern Matching
        risk_signals = self.pattern_matcher.match_signals(
            dual_view=dual_view,
            intents=detected_intents,
            entities=detected_entities,
            url_metadata=masked_res.url_metadata,
        )

        # Stage 6: Deterministic Primary Scoring (Initial Pass)
        breakdown, risk_level, classification = self.scoring_engine.compute_score(
            signals=risk_signals,
            intents=detected_intents,
            llm_delta=0,
        )

        llm_used = False

        # Stage 7: Optional LLM Enrichment (if enabled and configured)
        if enable_llm:
            sanitized_llm_input = SanitizedLLMInput(
                message=masked_res.masked_text[: settings.MAX_LLM_PAYLOAD_LENGTH],
                language=lang_res.language,
                intents=[i.intent for i in detected_intents],
                rule_signals=[s.category for s in risk_signals],
                url_domains=[u.registrable_domain for u in masked_res.url_metadata],
            )

            llm_result = await self.llm_enricher.enrich(sanitized_llm_input)

            if llm_result.llm_used and llm_result.delta != 0:
                # Recalculate score with bounded LLM delta
                breakdown, risk_level, classification = self.scoring_engine.compute_score(
                    signals=risk_signals,
                    intents=detected_intents,
                    llm_delta=llm_result.delta,
                )
                llm_used = True

        # Stage 8 & 9: Response Synthesis (Strictly Schema-Enforced, Safe Evidence Only)
        signals_response = [
            SignalResponse(
                id=f"sig_{s.category}",
                weight=s.weight,
                rule_id=s.rule_id,
            )
            for s in risk_signals
        ]

        return AnalysisResult(
            request_id=req_id,
            score=breakdown.final,
            risk_level=risk_level,
            classification=classification,
            language=lang_res.language,
            intents=[i.intent for i in detected_intents],
            signals=signals_response,
            breakdown=breakdown,
            url_metadata=masked_res.url_metadata,
            masked_entity_counts=masked_res.masked_entity_counts,
            llm_used=llm_used,
            privacy=PrivacySummary(
                pii_detected=len(detected_entities) > 0,
                external_text_sent=False,
                masked_message=masked_res.masked_text,
            ),
            analysis=AnalysisSummary(
                rule_based=True,
                llm_used=llm_used,
            ),
        )
