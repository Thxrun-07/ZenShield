"""Message verification endpoint: POST /api/v1/verify/message."""

from typing import Literal

import httpx
from fastapi import APIRouter, Depends, Header, Request, status
from pydantic import BaseModel, ConfigDict, Field

from zenshield.core.config import settings
from zenshield.core.security import rate_limit_dependency
from zenshield.engines.message.analyzer import MessageAnalyzer
from zenshield.engines.message.llm import build_llm_enricher
from zenshield.engines.message.models import AnalysisResult

router = APIRouter()


class VerifyMessageRequest(BaseModel):
    """Request contract for message verification.

    Strictly forbids extra unknown fields to prevent parameter tampering.
    """

    model_config = ConfigDict(extra="forbid")

    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Raw message text to inspect and verify",
    )
    country: str = Field(
        default="IN",
        pattern=r"^[A-Z]{2}$",
        description="ISO-3166-1 alpha-2 country code",
    )
    channel: Literal["sms", "whatsapp", "email", "chat"] | None = Field(
        default="sms",
        description="Delivery channel",
    )
    source: Literal["sms", "whatsapp", "email", "chat"] | None = Field(
        default=None,
        description="Alias for channel",
    )
    enable_llm: bool = Field(
        default=False,
        description="Whether optional external LLM enrichment is enabled",
    )


_shared_http_client: httpx.AsyncClient | None = None
_analyzer_instance: MessageAnalyzer | None = None


def get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None or _shared_http_client.is_closed:
        _shared_http_client = httpx.AsyncClient(timeout=settings.LLM_TIMEOUT_SECONDS)
    return _shared_http_client


async def close_shared_http_client() -> None:
    global _shared_http_client
    if _shared_http_client is not None and not _shared_http_client.is_closed:
        await _shared_http_client.aclose()
        _shared_http_client = None


def get_message_analyzer() -> MessageAnalyzer:
    global _analyzer_instance
    if _analyzer_instance is None:
        client = get_shared_http_client()
        enricher = build_llm_enricher(settings, client=client)
        _analyzer_instance = MessageAnalyzer(llm_enricher=enricher)
    return _analyzer_instance


@router.post(
    "/message",
    response_model=AnalysisResult,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Verify message for phishing, fraud, and social engineering",
)
async def verify_message(
    payload: VerifyMessageRequest,
    request: Request,
    analyzer: MessageAnalyzer = Depends(get_message_analyzer),
    x_request_id: str | None = Header(None, alias="X-Request-ID"),
) -> AnalysisResult:
    """Inspect and verify message with zero raw PII retention or external leakage."""
    effective_channel = payload.source or payload.channel or "sms"
    req_id = x_request_id or getattr(request.state, "request_id", None)
    effective_enable_llm = payload.enable_llm and settings.ENABLE_LLM_DEFAULT

    return await analyzer.analyze(
        message=payload.message,
        country=payload.country,
        channel=effective_channel,
        enable_llm=effective_enable_llm,
        request_id=req_id,
    )
