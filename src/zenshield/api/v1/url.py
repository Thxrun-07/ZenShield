"""URL verification endpoint: POST /api/v1/verify/url."""

from fastapi import APIRouter, Depends, status
from fastapi.concurrency import run_in_threadpool

from zenshield.core.security import rate_limit_dependency
from zenshield.engines.url.risk_engine import RiskEngine
from zenshield.engines.url.schemas import URLVerificationRequest, URLVerificationResponse

router = APIRouter()

# Global default engine instance
_risk_engine = RiskEngine()


def get_risk_engine() -> RiskEngine:
    return _risk_engine


@router.post(
    "/url",
    response_model=URLVerificationResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_dependency)],
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
async def verify_url(
    payload: URLVerificationRequest,
    engine: RiskEngine = Depends(get_risk_engine),
) -> URLVerificationResponse:
    """Analyze the submitted URL without blocking the async event loop."""
    return await run_in_threadpool(engine.analyze, payload.url)
