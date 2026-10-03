import logging
from schemas.verification import RiskResult

logger = logging.getLogger(__name__)


class URLAdapter:
    """
    Adapter boundary for Person 1's URL phishing detection engine.
    """

    def analyze_url(self, url: str) -> RiskResult:
        """
        ======================================================================
        INSTRUCTIONS FOR PERSON 1 (URL Detection Engine Lead):
        ----------------------------------------------------------------------
        Plug your actual URL detection function here.
        
        Requirements:
        - Accept the target `url` string.
        - Return a `schemas.verification.RiskResult` object containing:
            - is_risky: bool
            - risk_score: float (e.g. 0.0 to 1.0)
            - risk_level: "low", "medium", or "high"
            - reasons: list[str]
            
        Example integration:
            from your_url_engine import evaluate_url
            
            output = evaluate_url(url)
            return RiskResult(
                is_risky=output.is_phishing,
                risk_score=output.score,
                risk_level=output.severity,
                reasons=output.detected_features
            )
        ======================================================================
        """
        raise NotImplementedError("URL detection engine has not been connected yet.")
