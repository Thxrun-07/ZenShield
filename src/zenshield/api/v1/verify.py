"""Unified Content Verification Endpoint: POST /api/v1/verify."""

import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from zenshield.adapters.message_adapter import MessageAdapter
from zenshield.adapters.url_adapter import URLAdapter
from zenshield.core.security import rate_limit_dependency
from zenshield.schemas.risk import RiskResult
from zenshield.schemas.verification import VerifyRequest, VerifyResponse

logger = logging.getLogger("zenshield.audit")

router = APIRouter(tags=["Verification"])

_url_adapter = URLAdapter()
_message_adapter = MessageAdapter()


def get_url_adapter() -> URLAdapter:
    """FastAPI dependency provider for URLAdapter."""
    return _url_adapter


def get_message_adapter() -> MessageAdapter:
    """FastAPI dependency provider for MessageAdapter."""
    return _message_adapter


@router.post(
    "/verify",
    response_model=VerifyResponse,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Unified Content Verification Endpoint",
    description="Accepts URL or text message verification requests and routes them to respective detection adapters.",
)
async def verify_content(
    request: VerifyRequest,
    req: Request,
    url_adapter: URLAdapter = Depends(get_url_adapter),
    message_adapter: MessageAdapter = Depends(get_message_adapter),
    x_request_id: str | None = Header(None, alias="X-Request-ID"),
) -> VerifyResponse:
    """
    Unified POST /api/v1/verify endpoint.

    Flow:
    1. Validate request payload (type: 'url' | 'message', content: non-empty string).
    2. Route to url_adapter or message_adapter based on `type`.
    3. Return normalized VerifyResponse containing RiskResult.
    4. Privacy preservation: raw PII is masked before being returned in `content`.
    """
    req_id = x_request_id or getattr(req.state, "request_id", None)

    try:
        if request.type == "url":
            if hasattr(url_adapter, "analyze_url_async"):
                result: RiskResult = await url_adapter.analyze_url_async(request.content, request_id=req_id)
            else:
                result = url_adapter.analyze_url(request.content)
            content_out = request.content
        elif request.type == "message":
            if hasattr(message_adapter, "analyze_message_async"):
                result = await message_adapter.analyze_message_async(request.content, request_id=req_id)
            else:
                result = message_adapter.analyze_message(request.content)
            # Privacy preservation: return masked representation if available
            content_out = getattr(result, "_masked_message", request.content)
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unsupported verification type '{request.type}'.",
            )

        return VerifyResponse(
            type=request.type,
            content=content_out,
            result=result,
        )

    except NotImplementedError as e:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(e),
        ) from e
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Unexpected error during verification processing: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while processing the verification request.",
        ) from e
