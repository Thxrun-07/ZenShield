# RedFlag — Threat Intelligence & Community Reporting Module

Community-focused Threat Intelligence & Community Fraud Reporting module for the **RedFlag** cybersecurity platform.

---

## 1. Purpose of the Module

This module provides:
- **IOC Registry**: Canonical storage of threat indicators (domains, URLs, phone numbers, UPI IDs, emails, bank accounts).
- **Community Fraud Reporting**: Enables regional residents to report localized fraud campaigns and link incidents to canonical IOCs.
- **IOC Reputation Lookup**: Instant querying for known threats with confidence scoring and community corroboration volume.
- **Indicator Normalization**: Standardizes raw user inputs (e.g. `+91 98765 43210`, `09876543210`, `9876543210` -> `+919876543210`; stripping URL tracking parameters).
- **Privacy Masking**: Scrubs victim PII (phones, emails, OTPs, credit cards, bank accounts) before storage while preserving target threat indicators.

> **CRITICAL RULE**: Unknown does **NOT** mean safe. Never returns `"safe": true` for an unknown IOC. The URL heuristic engine continues its own risk analysis.

---

## 2. Folder Structure

```
app/
└── intelligence/
    ├── __init__.py               # Public module exports
    ├── database.py               # SQLite connection & session management
    ├── models.py                 # SQLAlchemy models (IOCRecord, Report)
    ├── schemas.py                # Pydantic validation & response schemas
    ├── normalization.py          # Indicator canonicalization & type inference
    ├── masking.py                # Sensitive PII redaction engine
    ├── reputation_service.py     # Reputation check interface (for Person 1)
    ├── report_service.py         # Community reporting workflow service
    ├── service.py                # General IOC registry services
    ├── router.py                 # FastAPI APIRouter (GET /check, POST /report)
    └── README.md                 # Complete module documentation
tests/
    ├── test_community_reporting.py # Community reporting workflow & validation tests
    ├── test_final_acceptance.py    # End-to-end integration acceptance tests
    ├── test_normalization.py       # Indicator normalization tests
    ├── test_privacy.py             # Privacy scrubber unit tests
    ├── test_router.py              # FastAPI endpoint tests
    └── test_service.py             # Service layer tests
```

---

## 3. Database Schema

Uses self-contained SQLite (`redflag_intelligence.db`) with zero external service dependencies. Tables auto-initialize upon import.

### Table: `threat_iocs`
| Column | Type | Description |
|---|---|---|
| `id` | Integer (PK) | Unique IOC ID |
| `indicator_value` | String (Unique, Index) | Canonical normalized indicator |
| `raw_value` | String | Original raw input string |
| `indicator_type` | String (Index) | `domain`, `url`, `phone`, `upi_id`, `email`, `bank_account`, `ip`, `other` |
| `threat_category` | String | `phishing`, `malware`, `scam`, `fraud`, `impersonation`, etc. |
| `threat_level` | String | `low`, `medium`, `high`, `critical` |
| `confidence_score` | Float | Internal confidence score (0.0 to 100.0) |
| `report_count` | Integer | Total community reports submitted for this IOC |
| `confirmation_count` | Integer | Resident upvotes/confirmations |
| `status` | String | `active`, `under_review`, `verified_malicious`, `resolved` |
| `first_seen_at` | DateTime (UTC) | Initial report timestamp |
| `last_seen_at` | DateTime (UTC) | Most recent report timestamp |
| `last_seen` | DateTime (UTC) | Most recent update timestamp |
| `notes` | Text | Optional threat notes |

### Table: `reports`
| Column | Type | Description |
|---|---|---|
| `id` | Integer (PK) | Unique Report ID |
| `ioc_id` | Integer (FK -> threat_iocs.id) | Linked parent IOC ID |
| `report_type` | String | Scam/threat category |
| `description` | Text | Privacy-masked incident narrative |
| `evidence` | Text | Privacy-masked supporting evidence |
| `location` | String | Regional location (e.g. `Chennai`, `Coimbatore`) |
| `created_at` | DateTime (UTC) | Submission timestamp |

---

## 4. API Endpoints

Router prefix: `/api/v1/intelligence`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/intelligence/check` | Look up reputation of an indicator |
| `POST` | `/api/v1/intelligence/report` | Submit a resident fraud report |

---

## 5. Request Examples

### Check Indicator (GET)
```http
GET /api/v1/intelligence/check?indicator=fake-bank-a.example&indicator_type=domain HTTP/1.1
Host: localhost:8000
```

### Submit Report (POST)
```http
POST /api/v1/intelligence/report HTTP/1.1
Host: localhost:8000
Content-Type: application/json

{
    "indicator": "fake-bank-a.example",
    "indicator_type": "domain",
    "threat_type": "phishing",
    "description": "Fake banking verification page asking for OTP 482931 and account details",
    "evidence": "Requests credentials and phone 9876543210",
    "location": "Chennai"
}
```

---

## 6. Response Examples

### Known IOC Response (GET /check)
```json
{
    "known": true,
    "indicator": "fake-bank-a.example",
    "indicator_type": "domain",
    "threat_type": "phishing",
    "status": "active",
    "confidence": 0.91,
    "report_count": 4
}
```

### Unknown IOC Response (GET /check)
*(Unknown never says `"safe": true`)*
```json
{
    "known": false,
    "indicator": "unknown.example",
    "indicator_type": "domain",
    "message": "Indicator not present in local threat intelligence registry."
}
```

### Submit Report Response (POST /report)
```json
{
    "report_id": 1,
    "ioc_id": 1,
    "new_ioc": true,
    "report_count": 1
}
```

*(Subsequent reports for the same IOC increment `report_count` and return `new_ioc: false`)*

---

## 7. Service Functions

Stable functions exported for direct Python use without requiring HTTP:

- `check_indicator(indicator, indicator_type=None, db=None)`: Checks registry reputation.
- `check_ioc(indicator, indicator_type=None, db=None)`: Alias for `check_indicator`.
- `find_ioc(indicator, indicator_type=None, db=None)`: Retrieves IOC database record by indicator.
- `get_ioc(ioc_id, db=None)`: Retrieves IOC record by integer ID.
- `create_ioc(indicator, indicator_type=None, threat_type="phishing", ...)`: Directly registers an IOC.
- `create_report(report_data, db=None)`: Executes complete community report ingestion workflow.

---

## 8. Normalization Rules

- **Domains**: Lowercased, strips `www.`, removes protocols (`http://`), paths, and ports (`sbi-fake.com:8080/path` -> `sbi-fake.com`).
- **URLs**: Scheme and host lowercased, default ports stripped (:80, :443), trailing slashes cleaned, tracking params removed (`utm_*`, `gclid`, `fbclid`).
- **Phone Numbers**: Converted to canonical `+91XXXXXXXXXX` (handles 10 digits starting with 6-9, 0-prefixed, 91-prefixed, spaces/dashes).
- **UPI IDs**: Lowercased and trimmed (`Scam@Paytm` -> `scam@paytm`).
- **Emails**: Lowercased and trimmed.
- **Bank Accounts**: Spaces and dashes removed.

---

## 9. Privacy Masking

Automatically executed on `description` and `evidence`:
- Phone numbers: `9876543210` -> `[PHONE_REDACTED]`
- Email addresses: `test@gmail.com` -> `[EMAIL_REDACTED]`
- OTPs: `OTP 482931` -> `OTP [OTP_REDACTED]`
- Credit / Debit Cards: `4111-2222-3333-4444` -> `[CARD_REDACTED]`
- Bank Account Numbers: `account: 123456789012` -> `account: [ACCOUNT_REDACTED]`

**Indicator Preservation**: The target indicator being reported is protected and remains intact and searchable.

---

## 10. How to Integrate the Router

In `main.py` (for Person 4):

```python
from fastapi import FastAPI
from zenshield.engines.intelligence.router import router as intelligence_router

app = FastAPI(title="RedFlag Cybersecurity Platform")

# Mount Intelligence router
app.include_router(intelligence_router)
```

---

## 11. How Person 1 Can Call `check_indicator()`

Direct Python service invocation for the URL detection & heuristic risk engine:

```python
from zenshield.engines.intelligence.reputation_service import check_indicator

result = check_indicator(indicator="example.com", indicator_type="domain")

if result.known:
    print(f"Known Threat: {result.threat_type}")
    print(f"Confidence: {result.confidence}")
    print(f"Report Count: {result.report_count}")
else:
    print(result.message)
    # Result is unknown - proceed with URL heuristics
```

---

## 12. How to Run Tests

Run pytest across all intelligence module tests:

```bash
python -m pytest -v
```

All 38 automated tests pass out of the box with zero external configuration or database setup.
