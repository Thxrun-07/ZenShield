"""API v1 central router aggregating all endpoints."""

from fastapi import APIRouter

from zenshield.api.v1.campaign import router as campaign_router
from zenshield.api.v1.intelligence import router as intelligence_router
from zenshield.api.v1.message import router as message_router
from zenshield.api.v1.ocr import router as ocr_router
from zenshield.api.v1.qr import router as qr_router
from zenshield.api.v1.report import router as report_router
from zenshield.api.v1.url import router as url_router
from zenshield.api.v1.verify import router as verify_router

api_v1_router = APIRouter()

# Unified verification entry point: POST /api/v1/verify
api_v1_router.include_router(verify_router)

# Direct engine endpoints:
# POST /api/v1/verify/url
api_v1_router.include_router(url_router, prefix="/verify", tags=["URL Verification"])
# POST /api/v1/verify/message
api_v1_router.include_router(message_router, prefix="/verify", tags=["Message Verification"])

# QR code processing: POST /api/v1/qr/scan
api_v1_router.include_router(qr_router)

# OCR text processing: POST /api/v1/ocr/analyze
api_v1_router.include_router(ocr_router)

# Reporting endpoints: POST /api/v1/report/phishing
api_v1_router.include_router(report_router)

# Campaign statistics: GET /api/v1/campaign/stats
api_v1_router.include_router(campaign_router)

# Threat Intelligence: GET /api/v1/intelligence/check, POST /api/v1/intelligence/report
api_v1_router.include_router(intelligence_router)
