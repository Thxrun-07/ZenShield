"""Tests for URL parsing and normalization service."""

import pytest
from zenshield.services.url_normalizer import is_ip_address, normalize_url


def test_normalizer_standard_url():
    url = "https://Example.COM/login?User=123"
    norm = normalize_url(url)
    assert norm.is_valid is True
    assert norm.scheme == "https"
    assert norm.hostname == "example.com"
    assert norm.registered_domain == "example.com"
    assert norm.path == "/login"
    assert norm.query == "User=123"
    assert norm.is_ip is False


def test_normalizer_url_without_scheme():
    url = "example.com/login"
    norm = normalize_url(url)
    assert norm.is_valid is True
    assert norm.scheme == "http"
    assert norm.hostname == "example.com"
    assert norm.registered_domain == "example.com"
    assert norm.path == "/login"


def test_normalizer_ip_address():
    url = "http://192.168.1.1:8080/admin"
    norm = normalize_url(url)
    assert norm.is_valid is True
    assert norm.is_ip is True
    assert norm.hostname == "192.168.1.1"
    assert norm.registered_domain == "192.168.1.1"
    assert norm.port == 8080


def test_normalizer_subdomains():
    url = "https://portal.secure.banking.paypal.com/signin"
    norm = normalize_url(url)
    assert norm.is_valid is True
    assert norm.hostname == "portal.secure.banking.paypal.com"
    assert norm.registered_domain == "paypal.com"
    assert norm.subdomain == "portal.secure.banking"


def test_normalizer_punycode_domain():
    url = "http://xn--pple-43d.com"
    norm = normalize_url(url)
    assert norm.is_valid is True
    assert norm.is_punycode is True
    assert norm.hostname == "xn--pple-43d.com"
    assert "apple" in norm.unicode_domain or "pple" in norm.unicode_domain


def test_normalizer_internationalized_domain():
    url = "http://аpple.com"  # Cyrillic 'а'
    norm = normalize_url(url)
    assert norm.is_valid is True
    assert norm.is_punycode is True


def test_normalizer_malformed_url_no_crash():
    malformed_inputs = [
        "",
        "   ",
        "http://[::1/path",
        "://missing-scheme",
        "http://invalid_port:999999",
        "ftp://",
    ]
    for inp in malformed_inputs:
        norm = normalize_url(inp)
        assert isinstance(norm.is_valid, bool)
        # Should never raise an uncaught exception


def test_is_ip_address():
    assert is_ip_address("192.168.1.1")[0] is True
    assert is_ip_address("10.0.0.1:8080")[0] is True
    assert is_ip_address("google.com")[0] is False
    assert is_ip_address("256.256.256.256")[0] is False
