"""SQLAlchemy-backed unified reputation provider for ZenShield.

Queries the central threat intelligence `threat_iocs` table.
Enables instant awareness: a community report submitted via /intelligence/report
immediately affects subsequent URL risk evaluations.
"""

from sqlalchemy import func
from sqlalchemy.orm import Session

from zenshield.db.database import SessionLocal
from zenshield.db.models import IOCRecord
from zenshield.engines.url.reputation.base import BaseReputationProvider, ReputationResult
from zenshield.engines.url.schemas import NormalizedURL, SignalSeverity


class DatabaseReputationProvider(BaseReputationProvider):
    """Reputation provider backed by ZenShield's unified SQLAlchemy threat registry."""

    def __init__(self, db: Session | None = None):
        self._external_db = db

    def _get_session(self) -> Session:
        return self._external_db if self._external_db is not None else SessionLocal()

    def check(self, norm_url: NormalizedURL) -> ReputationResult:
        """Check normalized URL against threat intelligence IOC registry."""
        if not norm_url.is_valid:
            return ReputationResult(is_known_ioc=False)

        candidates = set()
        if norm_url.original_url:
            candidates.add(norm_url.original_url.lower().rstrip("/"))
        if norm_url.normalized_url:
            candidates.add(norm_url.normalized_url.lower().rstrip("/"))
        if norm_url.hostname:
            candidates.add(norm_url.hostname.lower())
            # Domain hierarchy
            host_parts = norm_url.hostname.lower().split(".")
            for i in range(len(host_parts)):
                parent = ".".join(host_parts[i:])
                if parent:
                    candidates.add(parent)
        if norm_url.registered_domain:
            candidates.add(norm_url.registered_domain.lower())

        candidates_list = [c for c in candidates if c]
        if not candidates_list:
            return ReputationResult(is_known_ioc=False)

        session = self._get_session()
        close_needed = self._external_db is None
        try:
            # Query canonical indicators matching any candidate
            record = session.query(IOCRecord).filter(func.lower(IOCRecord.indicator_value).in_(candidates_list)).first()
            if record:
                level_str = (record.threat_level or "high").lower()
                try:
                    severity = SignalSeverity(level_str)
                except ValueError:
                    severity = SignalSeverity.HIGH

                return ReputationResult(
                    is_known_ioc=True,
                    indicator=str(record.indicator_value),
                    indicator_type=str(record.indicator_type),
                    source=str(record.threat_category or "community"),
                    severity=severity,
                    description=str(record.notes or f"Threat report count: {record.report_count}"),
                )
        finally:
            if close_needed:
                session.close()

        return ReputationResult(is_known_ioc=False)
