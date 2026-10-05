"""External threat intelligence service providers (e.g. VirusTotal)."""

import base64
import logging
import os
from abc import ABC, abstractmethod

import requests
from pydantic import BaseModel, Field

logger = logging.getLogger("zenshield.audit")


class ThreatIntelResult(BaseModel):
    """
    Normalized response format for threat intelligence lookups.
    Contains no secrets, API keys, or raw provider credentials.
    """

    indicator: str = Field(..., description="The Indicator of Compromise (URL, domain, IP, hash) evaluated")
    indicator_type: str = Field(default="url", description="Type of IOC ('url', 'domain', 'ip', 'hash')")
    provider_name: str = Field(..., description="Name of the threat intelligence provider")
    is_flagged: bool = Field(default=False, description="Whether indicator was flagged as malicious or suspicious")
    malicious_count: int = Field(default=0, description="Number of engines flagging indicator as malicious")
    total_engines: int = Field(default=0, description="Total number of security engines evaluated")
    status: str = Field(
        ...,
        description="Lookup status ('success', 'unconfigured', 'timeout', 'connection_error', 'rate_limited', 'unauthorized', 'provider_error', 'error')",
    )
    error_message: str | None = Field(default=None, description="Clean user-safe error message if lookup failed")


class ThreatIntelProvider(ABC):
    """
    Abstract Interface for External Threat Intelligence Providers.
    Any new threat intel provider (e.g. Google Safe Browsing, AbuseIPDB)
    must implement this interface.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the name of the threat intelligence provider."""
        pass

    @abstractmethod
    def lookup_indicator(self, indicator: str, indicator_type: str = "url") -> ThreatIntelResult:
        """Performs lookup for given IOC indicator and returns normalized ThreatIntelResult."""
        pass


class VirusTotalProvider(ThreatIntelProvider):
    """
    VirusTotal API v3 Threat Intelligence Provider implementation.

    Security Controls:
    - Reads API key ONLY from environment variable `VIRUSTOTAL_API_KEY` or constructor.
    - Enforces explicit HTTP request timeouts (default 5.0 seconds).
    - Sends ONLY the minimum required IOC string.
    - Catches all network/HTTP exceptions without crashing the application.
    """

    def __init__(self, api_key: str | None = None, timeout_seconds: float = 5.0):
        self._api_key = api_key if api_key is not None else os.getenv("VIRUSTOTAL_API_KEY")
        self.timeout_seconds = timeout_seconds

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

    def lookup_indicator(self, indicator: str, indicator_type: str = "url") -> ThreatIntelResult:
        if not self._api_key or self._api_key == "your_virustotal_api_key_here":
            logger.info("Threat intel provider unconfigured: VIRUSTOTAL_API_KEY missing.")
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider_name=self.provider_name,
                is_flagged=False,
                status="unconfigured",
                error_message="VirusTotal API key is not configured in environment.",
            )

        headers = {
            "x-apikey": self._api_key,
            "Accept": "application/json",
        }

        url_id = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("utf-8").strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        try:
            logger.info("Executing threat intel query to %s for indicator.", self.provider_name)
            response = requests.get(api_url, headers=headers, timeout=self.timeout_seconds)

            if response.status_code == 200:
                attributes = response.json().get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected

                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider_name=self.provider_name,
                    is_flagged=(malicious > 0 or suspicious > 0),
                    malicious_count=malicious,
                    total_engines=total,
                    status="success",
                )

            elif response.status_code in (401, 403):
                logger.warning("Unauthorized API key response from %s.", self.provider_name)
                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider_name=self.provider_name,
                    status="unauthorized",
                    error_message="Invalid or unauthorized threat intelligence API key.",
                )

            elif response.status_code == 429:
                logger.warning("Rate limit exceeded from %s.", self.provider_name)
                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider_name=self.provider_name,
                    status="rate_limited",
                    error_message="Threat intelligence API rate limit exceeded.",
                )

            elif response.status_code == 404:
                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider_name=self.provider_name,
                    is_flagged=False,
                    status="success",
                )

            else:
                logger.error("%s API returned error HTTP status code %d.", self.provider_name, response.status_code)
                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider_name=self.provider_name,
                    status="provider_error",
                    error_message=f"Threat intelligence provider returned HTTP {response.status_code}.",
                )

        except requests.exceptions.Timeout:
            logger.warning("Request timeout while contacting %s.", self.provider_name)
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider_name=self.provider_name,
                status="timeout",
                error_message="Threat intelligence query request timed out.",
            )

        except requests.exceptions.ConnectionError:
            logger.warning("Connection failure contacting %s.", self.provider_name)
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider_name=self.provider_name,
                status="connection_error",
                error_message="Failed to establish connection to threat intelligence service.",
            )

        except Exception as e:
            logger.error("Unexpected error querying threat intelligence: %s", e)
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider_name=self.provider_name,
                status="error",
                error_message="An unexpected error occurred during threat intelligence lookup.",
            )


class ThreatService:
    """
    Manager class coordinating threat intelligence operations.
    Supports provider dependency injection for easy provider switching.
    """

    def __init__(self, provider: ThreatIntelProvider | None = None):
        self.provider = provider or VirusTotalProvider()

    def check_indicator(self, indicator: str, indicator_type: str = "url") -> ThreatIntelResult:
        """
        Executes threat intelligence lookup on IOC indicator string.
        Guaranteed to never raise uncaught HTTP exceptions or crash backend calls.
        """
        return self.provider.lookup_indicator(indicator=indicator, indicator_type=indicator_type)
