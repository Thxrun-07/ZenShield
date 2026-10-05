"""
RedFlag Intelligence Module Public Interface.

Exports:
- router: FastAPI router ready for app.include_router(intelligence_router)
- Stable Service Functions:
    create_ioc()
    find_ioc()
    get_ioc()
    check_ioc()
    create_report()
    check_indicator()
- Normalization & Masking helpers:
    normalize_indicator()
    mask_sensitive_data()
"""

from zenshield.engines.intelligence.masking import mask_sensitive_data
from zenshield.engines.intelligence.normalization import detect_indicator_type, normalize_indicator
from zenshield.engines.intelligence.report_service import (
    create_report,
    get_report_by_id,
    get_reports_by_ioc_id,
)
from zenshield.engines.intelligence.reputation_service import (
    check_indicator,
    check_ioc,
    create_ioc,
    find_ioc,
    get_ioc,
)

__all__ = [
    "create_ioc",
    "find_ioc",
    "get_ioc",
    "check_ioc",
    "create_report",
    "check_indicator",
    "normalize_indicator",
    "detect_indicator_type",
    "mask_sensitive_data",
    "get_report_by_id",
    "get_reports_by_ioc_id",
]
