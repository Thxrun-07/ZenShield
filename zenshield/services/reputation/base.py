"""Base interface and data models for reputation providers."""

from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel
from zenshield.models.schemas import NormalizedURL, SignalSeverity


class ReputationResult(BaseModel):
    is_known_ioc: bool = False
    indicator: Optional[str] = None
    indicator_type: Optional[str] = None  # "domain" or "url"
    source: Optional[str] = None          # "local_sqlite", "community", "virustotal", etc.
    severity: Optional[SignalSeverity] = None
    description: Optional[str] = None


class BaseReputationProvider(ABC):
    """Abstract base class for all reputation / IOC providers."""

    @abstractmethod
    def check(self, norm_url: NormalizedURL) -> ReputationResult:
        """Check whether the given normalized URL or domain is a known IOC."""
        pass
