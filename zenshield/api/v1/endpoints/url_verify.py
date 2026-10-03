"""API endpoint for static URL risk verification."""

from fastapi import APIRouter, Depends, status
from zenshield.models.schemas import URLVerificationRequest, URLVerificationResponse
from zenshield.services.risk_engine import RiskEngine

router = APIRouter()

# Global engine instance (or dependency injection)
_risk_engine = RiskEngine()


def get_risk_engine() -> RiskEngine:
    return _risk_engine


@router.post(
    "/url",
    response_model=URLVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Statically verify a URL and evaluate threat risk",
    description="""
    Performs static URL analysis and risk evaluation:
    - Robust normalization without visiting or fetching the destination
    - Reputation & local IOC matching
    - Typosquatting / Damerau-Levenshtein similarity
    - Punycode, homoglyph, and mixed-script detection
    - Shannon entropy analysis
    - Structural and contextual heuristics
    - Brand impersonation detection
    - Centralized risk scoring and actionable recommendations
    """,
)
def verify_url(
    payload: URLVerificationRequest,
    engine: RiskEngine = Depends(get_risk_engine),
) -> URLVerificationResponse:
    """Analyze the submitted URL and return structured risk evaluation."""
    return engine.analyze(payload.url)
