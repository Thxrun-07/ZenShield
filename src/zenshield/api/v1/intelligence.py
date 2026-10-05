"""Threat intelligence endpoints: /api/v1/intelligence/check and /api/v1/intelligence/report."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from zenshield.core.security import rate_limit_dependency
from zenshield.db.database import get_db
from zenshield.engines.intelligence import report_service, reputation_service
from zenshield.schemas.intelligence import (
    KnownIOCResponse,
    ReportCreateRequest,
    ReportCreateResponse,
    UnknownIOCResponse,
)

router = APIRouter(
    prefix="/intelligence",
    tags=["Threat Intelligence"],
)


@router.get(
    "/check",
    response_model=KnownIOCResponse | UnknownIOCResponse,
    summary="Check IOC Reputation",
)
def check_ioc_reputation_endpoint(
    indicator: str = Query(..., description="Target indicator to check (domain, URL, phone, etc.)"),
    indicator_type: str | None = Query(None, description="Optional indicator type hint"),
    db: Session = Depends(get_db),
):
    """Checks if an indicator is present in the local threat intelligence registry."""
    return reputation_service.check_indicator(
        indicator=indicator,
        indicator_type=indicator_type,
        db=db,
    )


@router.post(
    "/report",
    response_model=ReportCreateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Submit Community Fraud Report",
)
def create_community_report_endpoint(
    payload: ReportCreateRequest,
    db: Session = Depends(get_db),
):
    """Submits a community fraud report with privacy masking and idempotent IOC linking."""
    try:
        return report_service.create_report(report_data=payload, db=db)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the community report.",
        ) from e
