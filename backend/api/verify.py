import logging
from fastapi import APIRouter, HTTPException, status, Depends
from schemas.verification import VerifyRequest, VerifyResponse, RiskResult
from services.url_adapter import URLAdapter
from services.message_adapter import MessageAdapter

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Verification"])


def get_url_adapter() -> URLAdapter:
    """Dependency provider for URLAdapter."""
    return URLAdapter()


def get_message_adapter() -> MessageAdapter:
    """Dependency provider for MessageAdapter."""
    return MessageAdapter()


@router.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Unified Content Verification Endpoint",
    description="Accepts URL or text message verification requests and routes them to respective detection adapters."
)
async def verify_content(
    request: VerifyRequest,
    url_adapter: URLAdapter = Depends(get_url_adapter),
    message_adapter: MessageAdapter = Depends(get_message_adapter)
):
    """
    Unified POST /api/v1/verify endpoint.

    Flow:
    1. Validate request payload (type: 'url' | 'message', content: non-empty string).
    2. Route to url_adapter or message_adapter based on `type`.
    3. Return normalized VerifyResponse containing RiskResult.
    4. Handle NotImplementedError when engine is unconnected.
    5. Handle unexpected errors without exposing stack traces.
    """
    try:
        if request.type == "url":
            result: RiskResult = url_adapter.analyze_url(request.content)
        elif request.type == "message":
            result: RiskResult = message_adapter.analyze_message(request.content)
        else:
            # Pydantic validates type, but defense-in-depth check
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unsupported verification type '{request.type}'."
            )

        return VerifyResponse(
            type=request.type,
            content=request.content,
            result=result
        )

    except NotImplementedError as e:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during verification processing: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while processing the verification request."
        )
