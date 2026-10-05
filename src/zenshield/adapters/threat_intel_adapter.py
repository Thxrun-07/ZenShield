"""Threat Intelligence Adapter wrapping threat registry and community reporting."""

from sqlalchemy.orm import Session

from zenshield.db.database import SessionLocal
from zenshield.engines.intelligence import report_service, reputation_service
from zenshield.schemas.intelligence import (
    KnownIOCResponse,
    ReportCreateRequest,
    ReportCreateResponse,
    UnknownIOCResponse,
)


class ThreatIntelAdapter:
    """Thin adapter for checking indicators and submitting community reports."""

    def __init__(self, db: Session | None = None):
        self._db = db

    def _get_session(self) -> Session:
        return self._db if self._db is not None else SessionLocal()

    def check_indicator(
        self,
        indicator: str,
        indicator_type: str | None = None,
    ) -> KnownIOCResponse | UnknownIOCResponse:
        session = self._get_session()
        close_needed = self._db is None
        try:
            return reputation_service.check_indicator(
                indicator=indicator,
                indicator_type=indicator_type,
                db=session,
            )
        finally:
            if close_needed:
                session.close()

    def create_report(
        self,
        payload: ReportCreateRequest,
    ) -> ReportCreateResponse:
        session = self._get_session()
        close_needed = self._db is None
        try:
            return report_service.create_report(report_data=payload, db=session)
        finally:
            if close_needed:
                session.close()
