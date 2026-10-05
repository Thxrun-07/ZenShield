"""
Community Fraud Reporting Service for RedFlag Intelligence Module.

Workflow:
1. Validate report request (Pydantic).
2. Normalize target threat indicator.
3. Apply privacy masking to description & evidence (preserving the actual IOC).
4. Find existing IOC or register new IOC without duplicates.
5. Increment report_count and update last_seen timestamp.
6. Persist Report record associated with IOC.
7. Return summary response (report_id, ioc_id, new_ioc, report_count).

Can be invoked:
- Via FastAPI HTTP endpoint POST /api/v1/intelligence/report
- Directly in Python code without requiring an HTTP request or DB session setup.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from zenshield.db.models import IOCRecord, Report
from zenshield.engines.intelligence.masking import mask_sensitive_data
from zenshield.engines.intelligence.normalization import normalize_indicator
from zenshield.engines.intelligence.service import provide_db
from zenshield.schemas.intelligence import ReportCreateRequest, ReportCreateResponse


def create_report(report_data: ReportCreateRequest | dict[str, Any], db: Session | None = None) -> ReportCreateResponse:
    """
    Submits a community fraud report and associates it with an IOC.

    Args:
        report_data: ReportCreateRequest instance or dictionary matching the schema.
        db: Optional active SQLAlchemy session. Auto-managed if None.

    Returns:
        ReportCreateResponse containing report_id, ioc_id, new_ioc, and report_count.
    """
    # 1. Validate request
    if isinstance(report_data, dict):
        validated_data = ReportCreateRequest(**report_data)
    elif isinstance(report_data, ReportCreateRequest):
        validated_data = report_data
    else:
        raise ValueError(f"Invalid report_data type: {type(report_data)}. Expected dict or ReportCreateRequest.")

    # 2. Normalize indicator
    norm_val, det_type = normalize_indicator(
        raw_value=validated_data.indicator, indicator_type=validated_data.indicator_type
    )

    # 3. Privacy masking on description and evidence (preserving the actual IOC)
    masked_desc = mask_sensitive_data(
        text=validated_data.description, preserve_indicator=validated_data.indicator or norm_val
    )
    masked_evidence = (
        mask_sensitive_data(text=validated_data.evidence, preserve_indicator=validated_data.indicator or norm_val)
        if validated_data.evidence
        else None
    )

    # 4-8. Database workflow with IOC and Report association
    with provide_db(db) as session:
        now = datetime.now(UTC)

        # 4 & 5: Search for existing IOC or create without duplication
        ioc = session.query(IOCRecord).filter(IOCRecord.indicator_value == norm_val).first()

        if ioc:
            new_ioc = False
            # 6 & 8: Increment report_count and update last_seen
            ioc.report_count += 1
            ioc.last_seen_at = now
            ioc.last_seen = now
            if not ioc.threat_category or ioc.threat_category == "other":
                ioc.threat_category = validated_data.threat_type
        else:
            new_ioc = True
            ioc = IOCRecord(
                indicator_value=norm_val,
                raw_value=validated_data.indicator,
                indicator_type=det_type,
                threat_category=validated_data.threat_type,
                threat_level="medium",
                confidence_score=50.0,
                report_count=1,
                confirmation_count=0,
                status="active",
                first_seen_at=now,
                last_seen_at=now,
                last_seen=now,
            )
            session.add(ioc)
            session.flush()  # Populates ioc.id

        # 7: Create Report record associated with IOC
        report_record = Report(
            ioc_id=ioc.id,
            report_type=validated_data.threat_type,
            description=masked_desc,
            evidence=masked_evidence,
            location=validated_data.location,
            created_at=now,
        )
        session.add(report_record)
        session.commit()
        session.refresh(report_record)
        session.refresh(ioc)

        # 9: Return structured result
        return ReportCreateResponse(
            report_id=report_record.id, ioc_id=ioc.id, new_ioc=new_ioc, report_count=ioc.report_count
        )


def get_report_by_id(report_id: int, db: Session | None = None) -> Report | None:
    """Helper to fetch a Report record by ID."""
    with provide_db(db) as session:
        return session.query(Report).filter(Report.id == report_id).first()


def get_reports_by_ioc_id(ioc_id: int, db: Session | None = None) -> list[Report]:
    """Helper to fetch all Report records associated with an IOC ID."""
    with provide_db(db) as session:
        return session.query(Report).filter(Report.ioc_id == ioc_id).all()
