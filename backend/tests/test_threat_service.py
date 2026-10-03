import sys
import requests
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure backend root is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from services.threat_service import (
    ThreatService,
    VirusTotalProvider,
    ThreatIntelProvider,
    ThreatIntelResult
)


@patch("requests.get")
def test_threat_service_success_flagged(mock_get):
    """
    1. Test successful threat intelligence response for a flagged malicious URL.
       Verifies ThreatIntelResult schema contract.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 15,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 10
                }
            }
        }
    }
    mock_get.return_value = mock_response

    provider = VirusTotalProvider(api_key="test_valid_api_key")
    service = ThreatService(provider=provider)

    result = service.check_indicator("http://malicious-phishing.com")

    # Validate ThreatIntelResult schema contract
    assert isinstance(result, ThreatIntelResult)
    assert result.status == "success"
    assert result.is_flagged is True
    assert result.malicious_count == 15
    assert result.total_engines == 87
    assert result.provider_name == "VirusTotal"
    assert result.error_message is None


def test_threat_service_unconfigured():
    """
    Test threat intel lookup when API key is unconfigured.
    """
    provider = VirusTotalProvider(api_key="")
    service = ThreatService(provider=provider)

    result = service.check_indicator("http://example.com")

    assert result.status == "unconfigured"
    assert result.is_flagged is False
    assert "API key is not configured" in result.error_message


@patch("requests.get")
def test_threat_service_timeout_handling(mock_get):
    """
    2. Test handling of external API request timeouts.
    """
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out after 5 seconds")

    provider = VirusTotalProvider(api_key="test_api_key")
    service = ThreatService(provider=provider)

    result = service.check_indicator("http://example.com")

    assert result.status == "timeout"
    assert result.is_flagged is False
    assert "timed out" in result.error_message


@patch("requests.get")
def test_threat_service_connection_failure(mock_get):
    """
    3. Test handling of network connection failures.
    """
    mock_get.side_effect = requests.exceptions.ConnectionError("Failed to resolve host")

    provider = VirusTotalProvider(api_key="test_api_key")
    service = ThreatService(provider=provider)

    result = service.check_indicator("http://example.com")

    assert result.status == "connection_error"
    assert result.is_flagged is False
    assert "Failed to establish connection" in result.error_message


@patch("requests.get")
def test_threat_service_http_401_unauthorized(mock_get):
    """
    4. Test handling of HTTP 401 Unauthorized (invalid API key).
    """
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_get.return_value = mock_response

    provider = VirusTotalProvider(api_key="invalid_key")
    service = ThreatService(provider=provider)

    result = service.check_indicator("http://example.com")

    assert result.status == "unauthorized"
    assert result.is_flagged is False
    assert "Invalid or unauthorized" in result.error_message


@patch("requests.get")
def test_threat_service_http_429_rate_limited(mock_get):
    """
    5. Test handling of HTTP 429 Rate Limited.
    """
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_get.return_value = mock_response

    provider = VirusTotalProvider(api_key="test_key")
    service = ThreatService(provider=provider)

    result = service.check_indicator("http://example.com")

    assert result.status == "rate_limited"
    assert result.is_flagged is False
    assert "rate limit exceeded" in result.error_message.lower()


@patch("requests.get")
def test_threat_service_http_500_server_error(mock_get):
    """
    6. Test handling of HTTP 500 Server Error from threat provider.
    """
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_get.return_value = mock_response

    provider = VirusTotalProvider(api_key="test_key")
    service = ThreatService(provider=provider)

    result = service.check_indicator("http://example.com")

    assert result.status == "provider_error"
    assert result.is_flagged is False
    assert "HTTP 500" in result.error_message


@patch("requests.get")
def test_threat_service_not_found(mock_get):
    """
    Test handling of HTTP 404 (indicator not recorded in threat database yet).
    """
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    provider = VirusTotalProvider(api_key="test_key")
    service = ThreatService(provider=provider)

    result = service.check_indicator("http://new-clean-site.com")

    assert result.status == "success"
    assert result.is_flagged is False
    assert result.malicious_count == 0


def test_custom_provider_abstraction():
    """
    Test adding a custom ThreatIntelProvider subclass without altering application callers.
    """
    class MockCustomProvider(ThreatIntelProvider):
        @property
        def provider_name(self) -> str:
            return "CustomIntel"

        def lookup_indicator(self, indicator: str, indicator_type: str = "url") -> ThreatIntelResult:
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider_name=self.provider_name,
                is_flagged=True,
                malicious_count=1,
                total_engines=1,
                status="success"
            )

    custom_provider = MockCustomProvider()
    service = ThreatService(provider=custom_provider)

    result = service.check_indicator("http://test.com")

    assert result.provider_name == "CustomIntel"
    assert result.is_flagged is True
    assert result.status == "success"
