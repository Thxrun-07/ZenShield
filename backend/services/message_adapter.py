import logging
from schemas.verification import RiskResult

logger = logging.getLogger(__name__)


class MessageAdapter:
    """
    Adapter boundary for Person 2's SMS / Message phishing detection engine.
    """

    def analyze_message(self, message: str) -> RiskResult:
        """
        ======================================================================
        INSTRUCTIONS FOR PERSON 2 (Message Detection Engine Lead):
        ----------------------------------------------------------------------
        Plug your actual SMS/Message detection function here.
        
        Requirements:
        - Accept the target `message` text string.
        - Return a `schemas.verification.RiskResult` object containing:
            - is_risky: bool
            - risk_score: float (e.g. 0.0 to 1.0)
            - risk_level: "low", "medium", or "high"
            - reasons: list[str]

        Example integration:
            from your_nlp_engine import evaluate_sms
            
            output = evaluate_sms(message)
            return RiskResult(
                is_risky=output.is_spam,
                risk_score=output.confidence,
                risk_level=output.category,
                reasons=output.matched_patterns
            )
        ======================================================================
        """
        raise NotImplementedError("Message detection engine has not been connected yet.")
