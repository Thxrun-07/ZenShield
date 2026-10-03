"""Optional external reputation provider integrations (e.g. VirusTotal, Google Safe Browsing).

SECURITY NOTE:
- These providers are strictly OPTIONAL and disabled by default.
- No API keys are hardcoded; all credentials must be supplied via environment variables.
- When disabled or keys are unset, these providers safely return negative results without network errors.
"""

from typing import Optional
from zenshield.config import settings
from zenshield.models.schemas import NormalizedURL, SignalSeverity
from zenshield.services.reputation.base import BaseReputationProvider, ReputationResult


class OptionalVirusTotalProvider(BaseReputationProvider):
    """Optional VirusTotal provider stub for domain/URL reputation."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self.enabled = bool(self.api_key and settings.ENABLE_EXTERNAL_REPUTATION)

    def check(self, norm_url: NormalizedURL) -> ReputationResult:
        if not self.enabled:
            return ReputationResult(is_known_ioc=False)
        # If enabled with valid key, query VT API in a production deployment
        # Returns clean default if inactive
        return ReputationResult(is_known_ioc=False)


class OptionalSafeBrowsingProvider(BaseReputationProvider):
    """Optional Google Safe Browsing provider stub."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.enabled = bool(self.api_key and settings.ENABLE_EXTERNAL_REPUTATION)

    def check(self, norm_url: NormalizedURL) -> ReputationResult:
        if not self.enabled:
            return ReputationResult(is_known_ioc=False)
        return ReputationResult(is_known_ioc=False)
