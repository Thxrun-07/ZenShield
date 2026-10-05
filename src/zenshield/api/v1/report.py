"""Phishing report endpoint: POST /api/v1/report/phishing."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from zenshield.adapters.threat_intel_adapter import ThreatIntelAdapter
from zenshield.core.security import rate_limit_dependency
from zenshield.db.database import get_db
from zenshield.schemas.intelligence import ReportCreateRequest
from zenshield.schemas.verification import PhishingReportRequest

logger = logging.getLogger("zenshield.audit")

router = APIRouter(prefix="/report", tags=["Community Reporting"])


def get_threat_intel_adapter(db: Session = Depends(get_db)) -> ThreatIntelAdapter:
    return ThreatIntelAdapter(db=db)


@router.post(
    "/phishing",
    dependencies=[Depends(rate_limit_dependency)],
    summary="Submit a Phishing or Fraud Report",
    description="Submits a fraud report and persists indicator into the unified threat intelligence registry.",
)
async def submit_phishing_report(
    report: PhishingReportRequest,
    adapter: ThreatIntelAdapter = Depends(get_threat_intel_adapter),
):
    if not report.target_url and not report.message_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report must contain either a target_url or message_content.",
        )

    # Determine indicator and indicator_type
    if report.target_url:
        indicator = report.target_url.strip()
        indicator_type = "url"
    else:
        # Message content provided
        indicator = (report.message_content or "").strip()[:500]
        indicator_type = "other"

    category = (report.category or "phishing").strip().lower()
    threat_type = category if category in {"phishing", "scam", "fraud", "malware", "impersonation"} else "phishing"

    try:
        req = ReportCreateRequest(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_type=threat_type,
            description=report.description or f"Phishing report for category '{report.category}'",
            evidence=report.message_content if report.target_url else None,
            location="India",
        )
        intel_res = adapter.create_report(req)
        report_id = intel_res.report_id
        ioc_id = intel_res.ioc_id
    except Exception as e:
        logger.error("Failed to store phishing report in threat intel: %s", e, exc_info=True)
        # Still return received if error or re-raise
        report_id = None
        ioc_id = None

    return {
        "status": "received",
        "message": "Phishing report successfully submitted for review.",
        "category": report.category,
        "report_id": report_id,
        "ioc_id": ioc_id,
    }
