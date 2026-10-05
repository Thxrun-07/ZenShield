"""Compatibility router for app.intelligence.router with prefix /api/v1/intelligence."""

from fastapi import APIRouter

from zenshield.api.v1.intelligence import (
    check_ioc_reputation_endpoint,
    create_community_report_endpoint,
)

router = APIRouter(prefix="/api/v1/intelligence", tags=["Threat Intelligence"])
router.add_api_route(
    "/check",
    check_ioc_reputation_endpoint,
    methods=["GET"],
    summary="Check IOC Reputation",
)
router.add_api_route(
    "/report",
    create_community_report_endpoint,
    methods=["POST"],
    status_code=201,
    summary="Submit Community Fraud Report",
)
