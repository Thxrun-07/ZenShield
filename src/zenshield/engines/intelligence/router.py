"""Forwarding router for intelligence engine."""

from typing import Any

__all__ = [  # noqa: F822
    "router",
    "check_ioc_reputation_endpoint",
    "create_community_report_endpoint",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import zenshield.api.v1.intelligence as intel_api

        return getattr(intel_api, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
