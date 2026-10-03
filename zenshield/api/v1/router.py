"""V1 API Router integrating detection and verification endpoints."""

from fastapi import APIRouter
from zenshield.api.v1.endpoints.url_verify import router as url_verify_router

api_v1_router = APIRouter()

# Mount URL verification under /verify -> /api/v1/verify/url
api_v1_router.include_router(url_verify_router, prefix="/verify", tags=["URL Verification"])
