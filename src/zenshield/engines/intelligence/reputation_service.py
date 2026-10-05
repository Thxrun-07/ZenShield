"""
IOC Reputation Lookup Service for RedFlag Intelligence Module.

Main integration interface for Person 1 (URL Detection & Heuristic Engine)
and Person 2 (SMS Phishing Detection).

CRITICAL RULE:
Unknown does NOT mean safe.
Never returns "safe": true for an unknown IOC.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from zenshield.db.models import IOCRecord
from zenshield.engines.intelligence.normalization import normalize_domain, normalize_indicator
from zenshield.engines.intelligence.service import provide_db
from zenshield.schemas.intelligence import KnownIOCResponse, UnknownIOCResponse


def calculate_confidence(report_count: int, confirmation_count: int = 0, status: str = "active") -> float:
    """
    Calculates normalized confidence level (0.0 to 1.0) based on report volume and status.
    """
    if status == "verified_malicious":
        base = 0.80
    elif status == "under_review":
        base = 0.40
    else:
        base = 0.55

    # Increment with community corroboration
    report_factor = min(report_count * 0.09, 0.35)
    confirmation_factor = min(confirmation_count * 0.05, 0.10)

    score = min(base + report_factor + confirmation_factor, 0.99)
    return round(score, 2)


def check_indicator(
    indicator: str, indicator_type: str | None = None, db: Session | None = None
) -> KnownIOCResponse | UnknownIOCResponse:
    """
    Main integration function called by Person 1's URL detection/risk engine.

    Checks if an indicator is present in the local threat intelligence registry.

    Args:
        indicator: Raw indicator string (domain, URL, phone, UPI, email, etc.)
        indicator_type: Optional indicator type hint ('domain', 'url', 'phone', etc.)
        db: Optional SQLAlchemy Session.

    Returns:
        KnownIOCResponse if found, or UnknownIOCResponse if not found.
        Unknown responses NEVER report safe: true.
    """
    if not indicator or not indicator.strip():
        return UnknownIOCResponse(
            known=False,
            indicator="",
            indicator_type=indicator_type or "other",
            message="Indicator not present in local threat intelligence registry.",
        )

    norm_val, det_type = normalize_indicator(indicator, indicator_type)

    with provide_db(db) as session:
        # 1. Primary lookup by exact normalized indicator
        ioc = session.query(IOCRecord).filter(IOCRecord.indicator_value == norm_val).first()

        # 2. Domain fallback check for URLs
        if not ioc and det_type == "url":
            domain_val = normalize_domain(norm_val)
            ioc = (
                session.query(IOCRecord)
                .filter(IOCRecord.indicator_value == domain_val, IOCRecord.indicator_type == "domain")
                .first()
            )

        if ioc:
            conf = calculate_confidence(
                report_count=ioc.report_count, confirmation_count=ioc.confirmation_count, status=ioc.status
            )
            return KnownIOCResponse(
                known=True,
                indicator=norm_val,
                indicator_type=ioc.indicator_type,
                threat_type=ioc.threat_category or "phishing",
                status=ioc.status or "active",
                confidence=conf,
                report_count=ioc.report_count,
            )

        # Unknown IOC - CRITICAL: Never return "safe": true
        return UnknownIOCResponse(
            known=False,
            indicator=norm_val,
            indicator_type=det_type,
            message="Indicator not present in local threat intelligence registry.",
        )


def check_ioc(
    indicator: str, indicator_type: str | None = None, db: Session | None = None
) -> KnownIOCResponse | UnknownIOCResponse:
    """Alias for check_indicator."""
    return check_indicator(indicator=indicator, indicator_type=indicator_type, db=db)


def find_ioc(indicator: str, indicator_type: str | None = None, db: Session | None = None) -> IOCRecord | None:
    """Finds an IOCRecord model instance by indicator string."""
    norm_val, _ = normalize_indicator(indicator, indicator_type)
    with provide_db(db) as session:
        return session.query(IOCRecord).filter(IOCRecord.indicator_value == norm_val).first()


def get_ioc(ioc_id: int, db: Session | None = None) -> IOCRecord | None:
    """Retrieves an IOCRecord by primary key ID."""
    with provide_db(db) as session:
        return session.query(IOCRecord).filter(IOCRecord.id == ioc_id).first()


def create_ioc(
    indicator: str,
    indicator_type: str | None = None,
    threat_type: str = "phishing",
    threat_level: str = "medium",
    notes: str | None = None,
    db: Session | None = None,
) -> IOCRecord:
    """Creates a new canonical IOC in the registry."""
    norm_val, det_type = normalize_indicator(indicator, indicator_type)
    now = datetime.now(UTC)

    with provide_db(db) as session:
        existing = session.query(IOCRecord).filter(IOCRecord.indicator_value == norm_val).first()
        if existing:
            existing.report_count += 1
            existing.last_seen_at = now
            existing.last_seen = now
            session.commit()
            session.refresh(existing)
            return existing

        new_ioc = IOCRecord(
            indicator_value=norm_val,
            raw_value=indicator,
            indicator_type=det_type,
            threat_category=threat_type,
            threat_level=threat_level,
            confidence_score=50.0,
            report_count=1,
            confirmation_count=0,
            status="active",
            notes=notes,
            first_seen_at=now,
            last_seen_at=now,
            last_seen=now,
        )
        session.add(new_ioc)
        session.commit()
        session.refresh(new_ioc)
        return new_ioc
