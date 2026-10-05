"""
Python Service Layer for RedFlag Intelligence Module.

Exposes clean Python functions for:
- IOC Registration & Updates
- IOC Reputation Lookups (designed for easy invocation by teammates)
- Community Fraud Reporting (with automatic normalization & PII scrubbing)
- Community Report Confirmations / Upvotes
- Regional Alert Summaries & Threat Analytics
- Indicator Normalization & Privacy Masking utilities

Designed to work either:
1. Via FastAPI HTTP router dependency injection
2. Directly imported by other Python modules (Person 1, Person 2, Person 4)
   without requiring external session setup (auto-manages SQLite session if None passed).
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from zenshield.db.database import SessionLocal, init_db
from zenshield.db.models import CommunityReport, IOCRecord, ReportConfirmation
from zenshield.engines.intelligence.normalization import normalize_domain, normalize_indicator
from zenshield.engines.intelligence.privacy import mask_report_text
from zenshield.schemas.intelligence import (
    CategoryCount,
    CommunityReportCreate,
    CommunityReportResponse,
    IndicatorNormalizeResponse,
    IOCCreate,
    IOCIncidentSummary,
    IOCReputationResponse,
    IOCResponse,
    PIIMaskResponse,
    RegionalAlertSummary,
    ReportConfirmationCreate,
    ReportConfirmationResponse,
)


@contextmanager
def provide_db(db: Session | None = None) -> Generator[Session, None, None]:
    """
    Session context provider.
    If a session is passed in, it is yielded as-is.
    If no session is passed, a self-managed session is opened, auto-committed, and closed.
    Ensures tables exist upon first run.
    """
    init_db()
    if db is not None:
        yield db
    else:
        session = SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def calculate_threat_metrics(
    report_count: int, confirmation_count: int, total_amount_lost: float = 0.0, status: str = "active"
) -> tuple[float, str]:
    """
    Computes a risk score (0.0 to 100.0) and threat level (safe, low, medium, high, critical)
    based on community reports and confirmation metrics.
    """
    if status == "false_positive":
        return 0.0, "safe"
    base_score = 75.0 if status == "verified_malicious" else 30.0

    # Add weight for report volume (up to +40 points)
    report_weight = min(report_count * 10.0, 40.0)

    # Add weight for community confirmations (up to +20 points)
    conf_weight = min(confirmation_count * 5.0, 20.0)

    # Add weight for financial damage (up to +10 points)
    financial_weight = 10.0 if total_amount_lost > 50000 else (5.0 if total_amount_lost > 0 else 0.0)

    calculated_score = min(base_score + report_weight + conf_weight + financial_weight, 100.0)

    if calculated_score >= 80.0:
        level = "critical"
    elif calculated_score >= 60.0:
        level = "high"
    elif calculated_score >= 35.0:
        level = "medium"
    elif calculated_score > 0.0:
        level = "low"
    else:
        level = "safe"

    return round(calculated_score, 1), level


# ==============================================================================
# 1. Indicator Normalization & Privacy Services
# ==============================================================================


def normalize_indicator_service(raw_value: str, indicator_type: str | None = None) -> IndicatorNormalizeResponse:
    """
    Normalizes an indicator and returns the canonical value with detected type.
    """
    norm, det_type = normalize_indicator(raw_value, indicator_type)
    return IndicatorNormalizeResponse(raw_value=raw_value, normalized_value=norm, detected_type=det_type)


def mask_pii_service(text: str, preserve_values: list[str] | None = None) -> PIIMaskResponse:
    """
    Scrubs PII from narrative text while preserving malicious indicators.
    """
    masked, counts = mask_report_text(text, preserve_values)
    return PIIMaskResponse(original_text=text, masked_text=masked, pii_detected=counts, has_pii=bool(counts))


# ==============================================================================
# 2. IOC Registry Services
# ==============================================================================


def register_or_update_ioc(ioc_in: IOCCreate, db: Session | None = None) -> IOCResponse:
    """
    Registers a new IOC or updates existing entry.
    """
    norm_val, det_type = normalize_indicator(ioc_in.indicator_value, ioc_in.indicator_type)

    with provide_db(db) as session:
        existing = session.query(IOCRecord).filter(IOCRecord.indicator_value == norm_val).first()
        now = datetime.now(UTC)

        if existing:
            existing.last_seen_at = now
            existing.report_count += 1
            if ioc_in.threat_category:
                existing.threat_category = ioc_in.threat_category
            if ioc_in.notes:
                existing.notes = (existing.notes or "") + f"\n[{now.isoformat()}] {ioc_in.notes}"

            score, level = calculate_threat_metrics(
                existing.report_count, existing.confirmation_count, 0.0, existing.status
            )
            existing.confidence_score = score
            existing.threat_level = level
            session.commit()
            session.refresh(existing)
            return IOCResponse.model_validate(existing)
        else:
            score, level = calculate_threat_metrics(1, 0, 0.0, "active")
            new_ioc = IOCRecord(
                indicator_value=norm_val,
                raw_value=ioc_in.indicator_value,
                indicator_type=det_type,
                threat_category=ioc_in.threat_category or "phishing",
                threat_level=ioc_in.threat_level or level,
                confidence_score=ioc_in.confidence_score or score,
                report_count=1,
                confirmation_count=0,
                status="active",
                notes=ioc_in.notes,
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(new_ioc)
            session.commit()
            session.refresh(new_ioc)
            return IOCResponse.model_validate(new_ioc)


def get_ioc_by_id(ioc_id: int, db: Session | None = None) -> IOCResponse | None:
    """
    Fetches single IOC by ID.
    """
    with provide_db(db) as session:
        ioc = session.query(IOCRecord).filter(IOCRecord.id == ioc_id).first()
        if not ioc:
            return None
        return IOCResponse.model_validate(ioc)


def list_iocs(
    indicator_type: str | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session | None = None,
) -> list[IOCResponse]:
    """
    Lists IOCs with optional type and status filtering.
    """
    with provide_db(db) as session:
        query = session.query(IOCRecord)
        if indicator_type:
            query = query.filter(IOCRecord.indicator_type == indicator_type.lower())
        if status:
            query = query.filter(IOCRecord.status == status.lower())
        records = query.order_by(desc(IOCRecord.last_seen_at)).offset(offset).limit(limit).all()
        return [IOCResponse.model_validate(r) for r in records]


# ==============================================================================
# 3. IOC Reputation Lookup Service (Core Integration Function)
# ==============================================================================


def lookup_ioc_reputation(
    indicator: str, indicator_type: str | None = None, db: Session | None = None
) -> IOCReputationResponse:
    """
    Core function for Person 1, Person 2, and Person 4.
    Accepts any raw indicator (URL, domain, phone, UPI, email), normalizes it,
    and returns its reputation, risk score, reported categories, and incident history.
    """
    if not indicator or not indicator.strip():
        return IOCReputationResponse(
            indicator_value="",
            indicator_type="other",
            is_known_threat=False,
            threat_level="safe",
            risk_score=0.0,
            report_count=0,
            confirmation_count=0,
            categories=[],
            regions_affected=[],
            first_seen=None,
            last_seen=None,
            status="clean",
            summary="Empty indicator provided.",
            recent_incidents=[],
        )

    norm_val, det_type = normalize_indicator(indicator, indicator_type)

    with provide_db(db) as session:
        # 1. Primary lookup by exact normalized indicator
        ioc = session.query(IOCRecord).filter(IOCRecord.indicator_value == norm_val).first()

        # 2. Secondary check: if indicator is a URL and not found, check if its root domain is flagged
        if not ioc and det_type == "url":
            extracted_domain = normalize_domain(norm_val)
            ioc = (
                session.query(IOCRecord)
                .filter(IOCRecord.indicator_value == extracted_domain, IOCRecord.indicator_type == "domain")
                .first()
            )

        # 3. Query linked or matching community reports
        reports = (
            session.query(CommunityReport)
            .filter(CommunityReport.indicator_value == norm_val)
            .order_by(desc(CommunityReport.created_at))
            .all()
        )

        if not reports and ioc and ioc.reports:
            reports = ioc.reports

        if not ioc and not reports:
            return IOCReputationResponse(
                indicator_value=norm_val,
                indicator_type=det_type,
                is_known_threat=False,
                threat_level="safe",
                risk_score=0.0,
                report_count=0,
                confirmation_count=0,
                categories=[],
                regions_affected=[],
                first_seen=None,
                last_seen=None,
                status="clean",
                summary=f"No threat records or resident fraud reports found for {norm_val}.",
                recent_incidents=[],
            )

        # Aggregate metrics
        rep_count = ioc.report_count if ioc else len(reports)
        conf_count = ioc.confirmation_count if ioc else sum(r.confirmation_count for r in reports)
        total_loss = sum(r.amount_lost or 0.0 for r in reports)
        status_val = ioc.status if ioc else "active"

        categories = sorted(list({r.fraud_category for r in reports if r.fraud_category}))
        if ioc and ioc.threat_category and ioc.threat_category not in categories:
            categories.append(ioc.threat_category)

        regions = sorted(list({r.region for r in reports if r.region}))

        first_seen = ioc.first_seen_at if ioc else (reports[-1].created_at if reports else None)
        last_seen = ioc.last_seen_at if ioc else (reports[0].created_at if reports else None)

        score, level = calculate_threat_metrics(rep_count, conf_count, total_loss, status_val)

        incident_summaries = [
            IOCIncidentSummary(
                report_id=r.id,
                title=r.title,
                region=r.region,
                fraud_category=r.fraud_category,
                amount_lost=r.amount_lost,
                created_at=r.created_at,
            )
            for r in reports[:5]
        ]

        summary_text = (
            f"Flagged as {level.upper()} threat with {rep_count} community report(s) "
            f"and {conf_count} confirmation(s). "
            f"Reported in {', '.join(regions[:3]) or 'regional area'}."
        )

        return IOCReputationResponse(
            indicator_value=norm_val,
            indicator_type=det_type,
            is_known_threat=True,
            threat_level=level,
            risk_score=score,
            report_count=rep_count,
            confirmation_count=conf_count,
            categories=categories,
            regions_affected=regions,
            first_seen=first_seen,
            last_seen=last_seen,
            status=status_val,
            summary=summary_text,
            recent_incidents=incident_summaries,
        )


# ==============================================================================
# 4. Community Fraud Reporting Services
# ==============================================================================


def submit_community_report(report_in: CommunityReportCreate, db: Session | None = None) -> CommunityReportResponse:
    """
    Submits a new resident fraud incident report:
    - Normalizes the target indicator
    - Scrubs victim PII from the narrative description
    - Registers or updates the corresponding IOC in the IOC Registry
    - Persists the community report linked to the IOC
    """
    norm_val, det_type = normalize_indicator(report_in.indicator_value, report_in.indicator_type)

    # Privacy mask victim details, preserving the reported indicator
    masked_desc, detected_pii = mask_report_text(
        report_in.description, preserve_values=[report_in.indicator_value, norm_val]
    )

    with provide_db(db) as session:
        # Find or create corresponding IOC record
        ioc = session.query(IOCRecord).filter(IOCRecord.indicator_value == norm_val).first()
        now = datetime.now(UTC)

        if ioc:
            ioc.report_count += 1
            ioc.last_seen_at = now
            if not ioc.threat_category or ioc.threat_category == "other":
                ioc.threat_category = report_in.fraud_category

            score, level = calculate_threat_metrics(
                ioc.report_count, ioc.confirmation_count, report_in.amount_lost or 0.0, ioc.status
            )
            ioc.confidence_score = score
            ioc.threat_level = level
        else:
            score, level = calculate_threat_metrics(1, 0, report_in.amount_lost or 0.0, "active")
            ioc = IOCRecord(
                indicator_value=norm_val,
                raw_value=report_in.indicator_value,
                indicator_type=det_type,
                threat_category=report_in.fraud_category,
                threat_level=level,
                confidence_score=score,
                report_count=1,
                confirmation_count=0,
                status="active",
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(ioc)
            session.flush()

        new_report = CommunityReport(
            ioc_id=ioc.id,
            indicator_value=norm_val,
            indicator_type=det_type,
            title=report_in.title.strip(),
            description=masked_desc,
            raw_description_had_pii=bool(detected_pii),
            region=report_in.region.strip(),
            fraud_category=report_in.fraud_category.strip(),
            amount_lost=report_in.amount_lost,
            confirmation_count=0,
            status="active",
            incident_date=report_in.incident_date,
            created_at=now,
            updated_at=now,
        )
        session.add(new_report)
        session.commit()
        session.refresh(new_report)
        return CommunityReportResponse.model_validate(new_report)


def confirm_community_report(
    report_id: int, confirmation_in: ReportConfirmationCreate | None = None, db: Session | None = None
) -> ReportConfirmationResponse:
    """
    Confirms/upvotes a fraud report, signaling to the community that others have seen it.
    Increments report and IOC confirmation counts and adjusts threat scores.
    """
    with provide_db(db) as session:
        report = session.query(CommunityReport).filter(CommunityReport.id == report_id).first()
        if not report:
            raise ValueError(f"Report with ID {report_id} not found.")

        report.confirmation_count += 1
        now = datetime.now(UTC)
        report.updated_at = now

        # Also increment parent IOC confirmation count
        if report.ioc_id:
            ioc = session.query(IOCRecord).filter(IOCRecord.id == report.ioc_id).first()
            if ioc:
                ioc.confirmation_count += 1
                score, level = calculate_threat_metrics(
                    ioc.report_count, ioc.confirmation_count, report.amount_lost or 0.0, ioc.status
                )
                ioc.confidence_score = score
                ioc.threat_level = level

        comment_val = confirmation_in.comment if confirmation_in else None
        region_val = confirmation_in.region if confirmation_in else None

        confirmation = ReportConfirmation(report_id=report.id, comment=comment_val, region=region_val, created_at=now)
        session.add(confirmation)
        session.commit()
        session.refresh(confirmation)

        return ReportConfirmationResponse(
            id=confirmation.id,
            report_id=report.id,
            comment=confirmation.comment,
            region=confirmation.region,
            created_at=confirmation.created_at,
            new_confirmation_count=report.confirmation_count,
        )


def get_community_reports(
    indicator: str | None = None,
    region: str | None = None,
    fraud_category: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session | None = None,
) -> list[CommunityReportResponse]:
    """
    Queries community reports with filtering and pagination.
    """
    with provide_db(db) as session:
        query = session.query(CommunityReport)
        if indicator:
            norm_val, _ = normalize_indicator(indicator)
            query = query.filter(CommunityReport.indicator_value == norm_val)
        if region:
            query = query.filter(func.lower(CommunityReport.region) == region.strip().lower())
        if fraud_category:
            query = query.filter(func.lower(CommunityReport.fraud_category) == fraud_category.strip().lower())

        reports = query.order_by(desc(CommunityReport.created_at)).offset(offset).limit(limit).all()
        return [CommunityReportResponse.model_validate(r) for r in reports]


def get_report_by_id(report_id: int, db: Session | None = None) -> CommunityReportResponse | None:
    """
    Fetches single community report by ID.
    """
    with provide_db(db) as session:
        report = session.query(CommunityReport).filter(CommunityReport.id == report_id).first()
        if not report:
            return None
        return CommunityReportResponse.model_validate(report)


# ==============================================================================
# 5. Regional Alerts & Threat Analytics Service
# ==============================================================================


def get_regional_alerts(region: str | None = None, limit: int = 10, db: Session | None = None) -> RegionalAlertSummary:
    """
    Aggregates community intelligence to provide localized warning alerts for residents.
    """
    target_region = region.strip() if region else "Tamil Nadu"

    with provide_db(db) as session:
        query = session.query(CommunityReport)
        if region:
            query = query.filter(func.lower(CommunityReport.region) == target_region.lower())

        reports = query.all()
        total_reports = len(reports)
        total_loss = sum(r.amount_lost or 0.0 for r in reports)

        # Top fraud categories
        cat_counts: dict[str, int] = {}
        for r in reports:
            cat_counts[r.fraud_category] = cat_counts.get(r.fraud_category, 0) + 1

        top_cats = [
            CategoryCount(category=k, count=v)
            for k, v in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

        # Active unique indicators
        unique_iocs = list({r.indicator_value for r in reports})
        trending = unique_iocs[:limit]

        # Alert level determination
        if total_reports >= 20 or total_loss > 500000:
            alert_level = "severe"
            warning = f"High alert in {target_region}: Multiple active fraud campaigns targeting local residents."
        elif total_reports >= 8 or total_loss > 100000:
            alert_level = "high"
            warning = f"Elevated scam activity detected in {target_region}. Exercise caution when receiving unsolicited calls or payment requests."
        elif total_reports >= 3:
            alert_level = "elevated"
            warning = f"Moderate fraud signals reported in {target_region}."
        else:
            alert_level = "low"
            warning = f"Normal alert level for {target_region}. Stay vigilant against suspicious links."

        return RegionalAlertSummary(
            region=target_region,
            active_threats_count=len(unique_iocs),
            total_reports=total_reports,
            total_financial_loss=round(total_loss, 2),
            top_categories=top_cats,
            trending_iocs=trending,
            alert_level=alert_level,
            community_warning=warning,
        )
