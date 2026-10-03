"""
Tests for RedFlag Indicator Normalization Module.
"""

import pytest
from app.intelligence.normalization import (
    detect_indicator_type,
    normalize_phone,
    normalize_upi,
    normalize_email,
    normalize_domain,
    normalize_url,
    normalize_bank_account,
    normalize_indicator,
)


def test_detect_indicator_type():
    # URLs
    assert detect_indicator_type("https://secure-bank-login.xyz/kyc") == "url"
    assert detect_indicator_type("http://free-recharge.in") == "url"
    assert detect_indicator_type("phishing-site.com/verify-account") == "url"

    # Domains
    assert detect_indicator_type("sbi-kyc-update.com") == "domain"
    assert detect_indicator_type("www.fake-lottery.org") == "domain"

    # Emails
    assert detect_indicator_type("support@fake-support.com") == "email"

    # UPI IDs
    assert detect_indicator_type("scammer@okhdfcbank") == "upi_id"
    assert detect_indicator_type("fraudster99@paytm") == "upi_id"
    assert detect_indicator_type("9876543210@ybl") == "upi_id"

    # Phones
    assert detect_indicator_type("9876543210") == "phone"
    assert detect_indicator_type("+91 98765 43210") == "phone"
    assert detect_indicator_type("09876543210") == "phone"
    assert detect_indicator_type("+14155552671") == "phone"

    # Bank Accounts
    assert detect_indicator_type("123456789012:SBIN0001234") == "bank_account"


def test_normalize_phone():
    assert normalize_phone("9876543210") == "+919876543210"
    assert normalize_phone("09876543210") == "+919876543210"
    assert normalize_phone("919876543210") == "+919876543210"
    assert normalize_phone("+91 98765-43210") == "+919876543210"
    assert normalize_phone("+1 (415) 555-2671") == "+14155552671"


def test_normalize_upi():
    assert normalize_upi("  ScamPayment@OkHdfcBank  ") == "scampayment@okhdfcbank"
    assert normalize_upi("FRAUD@PAYTM") == "fraud@paytm"


def test_normalize_email():
    assert normalize_email(" Support@PhishingMail.com ") == "support@phishingmail.com"


def test_normalize_domain():
    assert normalize_domain("https://WWW.Fake-Bank.com/") == "fake-bank.com"
    assert normalize_domain("www.sbi-alert.xyz") == "sbi-alert.xyz"
    assert normalize_domain("  malicious-domain.in:8080/path  ") == "malicious-domain.in"


def test_normalize_url():
    # Removes default port, tracking query params, lowercases host
    raw = "HTTPS://Evil-Bank.com:443/login/?utm_source=sms&utm_medium=blast&account=test#fragment"
    norm = normalize_url(raw)
    assert norm == "https://evil-bank.com/login?account=test"

    # Adds missing protocol
    norm2 = normalize_url("phishing-recharge.in/claim-offer/")
    assert norm2 == "http://phishing-recharge.in/claim-offer"


def test_normalize_bank_account():
    assert normalize_bank_account(" 1234 5678 9012 : sbin0001234 ") == "123456789012:SBIN0001234"
    assert normalize_bank_account("1234-5678-9012") == "123456789012"


def test_normalize_indicator_dispatch():
    val, itype = normalize_indicator(" 98765 43210 ")
    assert val == "+919876543210"
    assert itype == "phone"

    val, itype = normalize_indicator("Fraud@YBL")
    assert val == "fraud@ybl"
    assert itype == "upi_id"

    val, itype = normalize_indicator("HTTP://SCAM.COM/Offer/")
    assert val == "http://scam.com/Offer"
    assert itype == "url"
