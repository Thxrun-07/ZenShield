"""Base interface and data models for reputation providers."""

from abc import ABC, abstractmethod

from pydantic import BaseModel

from zenshield.models.schemas import NormalizedURL, SignalSeverity


class ReputationResult(BaseModel):
    is_known_ioc: bool = False
    indicator: str | None = None
    indicator_type: str | None = None  # "domain" or "url"
    source: str | None = None  # "local_sqlite", "community", "virustotal", etc.
    severity: SignalSeverity | None = None
    description: str | None = None


class BaseReputationProvider(ABC):
    """Abstract base class for all reputation / IOC providers."""

    @abstractmethod
    def check(self, norm_url: NormalizedURL) -> ReputationResult:
        """Check whether the given normalized URL or domain is a known IOC."""
        pass
