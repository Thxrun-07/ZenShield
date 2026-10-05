"""Campaign analytics endpoint: GET /api/v1/campaign/stats."""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from zenshield.core.security import rate_limit_dependency
from zenshield.db.database import get_db
from zenshield.db.models import CommunityReport, IOCRecord, Report

logger = logging.getLogger("zenshield.audit")

router = APIRouter(prefix="/campaign", tags=["Campaign Analytics"])


@router.get(
    "/stats",
    dependencies=[Depends(rate_limit_dependency)],
    summary="Get Phishing Campaign Aggregation Stats",
    description="Returns real aggregation statistics from the unified IOC and fraud report databases.",
)
async def get_campaign_stats(db: Session = Depends(get_db)):
    try:
        # Count distinct categories among active IOCs
        active_campaigns = (
            db.query(func.count(func.distinct(IOCRecord.threat_category))).filter(IOCRecord.status == "active").scalar()
            or 0
        )

        total_iocs = db.query(func.count(IOCRecord.id)).scalar() or 0
        total_reports = (db.query(func.count(Report.id)).scalar() or 0) + (
            db.query(func.count(CommunityReport.id)).scalar() or 0
        )
        active_threats = db.query(func.count(IOCRecord.id)).filter(IOCRecord.status == "active").scalar() or 0
    except Exception as e:
        logger.error("Error calculating campaign stats: %s", e)
        active_campaigns = 0
        total_iocs = 0
        total_reports = 0
        active_threats = 0

    return {
        "status": "active",
        "message": "Campaign and threat aggregation stats retrieved.",
        "active_campaigns_monitored": active_campaigns,
        "total_iocs_monitored": total_iocs,
        "total_reports_processed": total_reports,
        "active_threats_count": active_threats,
    }
