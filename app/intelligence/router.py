"""
FastAPI Router for RedFlag Threat Intelligence Module.

Final intelligence routes exposed:
- GET  /api/v1/intelligence/check
- POST /api/v1/intelligence/report

Mount into the main FastAPI application as:
    from app.intelligence.router import router as intelligence_router
    app.include_router(intelligence_router)
"""

from __future__ import annotations

from typing import Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.intelligence.database import get_db, init_db
from app.intelligence.schemas import (
    ReportCreateRequest,
    ReportCreateResponse,
    KnownIOCResponse,
    UnknownIOCResponse,
)
from app.intelligence import reputation_service, report_service

# Auto-initialize database tables upon router import
init_db()

router = APIRouter(
    prefix="/api/v1/intelligence",
    tags=["Threat Intelligence"],
)


@router.get(
    "/check",
    response_model=Union[KnownIOCResponse, UnknownIOCResponse],
    summary="Check IOC Reputation",
)
def check_ioc_reputation_endpoint(
    indicator: str = Query(..., description="Target indicator to check (domain, URL, phone, etc.)"),
    indicator_type: Optional[str] = Query(None, description="Optional indicator type hint"),
    db: Session = Depends(get_db)
):
    """
    Checks if an indicator is present in the local threat intelligence registry.
    Returns status, confidence, and report count if known.
    CRITICAL: Unknown indicators NEVER return safe: true.
    """
    return reputation_service.check_indicator(
        indicator=indicator,
        indicator_type=indicator_type,
        db=db
    )


@router.post(
    "/report",
    response_model=ReportCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Community Fraud Report",
)
def create_community_report_endpoint(
    payload: ReportCreateRequest,
    db: Session = Depends(get_db)
):
    """
    Submits a community fraud report:
    1. Validates the request.
    2. Normalizes the target indicator.
    3. Searches for an existing IOC or creates one without duplicates.
    4. Increments report_count and updates last_seen.
    5. Applies privacy masking to description and evidence (preserving the actual IOC).
    6. Creates and links Report record.
    7. Returns report_id, ioc_id, new_ioc, and report_count.
    """
    try:
        return report_service.create_report(report_data=payload, db=db)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the community report."
        )
