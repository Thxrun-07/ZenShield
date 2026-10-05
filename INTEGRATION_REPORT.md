# ZenShield 2.0 – Backend Integration & Hardening Report

**Date:** October 4, 2026  
**Status:** Complete & Production Ready  
**Overall Test Results:** **209 Passed / 0 Failed (100% Pass Rate)**  
**Code Quality:** **Ruff (0 errors), Mypy (0 errors), pip-audit (0 vulnerabilities)**  

---

## 1. Executive Summary

Four disparate ZenShield backend codebases have been successfully consolidated into a unified, hardened, production-grade FastAPI application:

1. **ZenShield (Main Repo):** FastAPI orchestration, `/verify` routing, QR/OCR endpoints, and VirusTotal threat provider.
2. **ZenShield-feature-url-risk-engine:** Static URL heuristic risk evaluation engine, normalizer, typosquatting, entropy, punycode/homoglyph detectors, and SQLite IOC store.
3. **ZenShield-feature-message-verification:** Multilingual (English/Tamil/Tanglish) intent classifier, PII detector/masker, URL extractor, and Groq LLM enricher.
4. **ZenShield-feature-threat-intelligence:** SQLAlchemy community fraud registry, IOC indicator normalization, confirmation workflow, and reputation check endpoints.

The unified application is delivered under the standard `src/` layout (`src/zenshield/`) with a single `pyproject.toml`, unified configuration system, shared SQLAlchemy data layer, ordered ASGI middleware stack, and strict zero-leakage privacy guarantees.

---

## 2. Test Execution & Verification Metrics

### Baseline vs. Final Test Comparison

| Test Suite / Codebase | Baseline Count | Final Count | Status | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **URL Risk Engine** | 57 | 57 | **PASS** | Fully migrated to `tests/unit/url/`, offline PSL enforced |
| **Privacy & Masking** | 14 | 14 | **PASS** | Preserved in `tests/unit/privacy/` with Aadhaar/PAN/OTP rules |
| **Message Engine** | 50 | 50 | **PASS** | Preserved in `tests/unit/message/`, multilingual + Tanglish |
| **Threat Intelligence** | 38 | 38 | **PASS** | Preserved in `tests/unit/intelligence/`, import side-effects fixed |
| **External Threat Service** | 9 | 9 | **PASS** | Extracted to `tests/unit/services/test_threat_service.py` |
| **QR Code Processing** | 7 | 7 | **PASS** | Hardened in `tests/integration/test_qr.py` |
| **OCR Image Processing** | 6 | 6 | **PASS** | Hardened in `tests/integration/test_ocr.py` |
| **Campaign & Reporting** | 4 | 4 | **PASS** | Implemented in `tests/integration/test_campaign_report.py` |
| **Startup & Resilience** | 4 | 4 | **PASS** | Implemented in `tests/integration/test_startup.py` |
| **Unified Verification** | 10 | 10 | **PASS** | Implemented in `tests/integration/test_verify.py` |
| **Security Hardening** | 10 | 10 | **PASS** | Implemented in `tests/integration/test_security.py` |
| **TOTAL** | **198** | **209** | **100% PASS** | **+11 new comprehensive integration & security tests** |

### Static Analysis & Security Audits

```bash
# Pytest Test Execution Output
============================= test session starts =============================
platform win32 -- Python 3.11.15, pytest-9.1.1
collected 209 items
tests/integration/test_campaign_report.py ....                           [  1%]
tests/integration/test_ocr.py ......                                     [  4%]
tests/integration/test_qr.py .......                                     [  8%]
tests/integration/test_security.py ..........                            [ 12%]
tests/integration/test_startup.py ....                                   [ 14%]
tests/integration/test_verify.py ..........                              [ 19%]
tests/unit/intelligence/test_community_reporting.py ..............       [ 26%]
tests/unit/intelligence/test_final_acceptance.py ...                     [ 27%]
tests/unit/intelligence/test_normalization.py ........                   [ 31%]
tests/unit/intelligence/test_privacy.py ......                           [ 34%]
tests/unit/intelligence/test_router.py ..                                [ 35%]
tests/unit/intelligence/test_service.py .....                            [ 37%]
tests/unit/message/test_analyzer.py ..........                           [ 42%]
tests/unit/message/test_groq_llm.py ...............                      [ 49%]
tests/unit/message/test_intent.py .....                                  [ 52%]
tests/unit/message/test_language.py .......                              [ 55%]
tests/unit/message/test_message_api.py ......                            [ 58%]
tests/unit/message/test_scoring.py .......                               [ 61%]
tests/unit/privacy/test_masker.py .....                                  [ 64%]
tests/unit/privacy/test_pii_detector.py .........                        [ 68%]
tests/unit/services/test_threat_service.py .........                     [ 72%]
tests/unit/url/test_brand_impersonation.py ....                          [ 74%]
tests/unit/url/test_entropy.py ...                                       [ 76%]
tests/unit/url/test_heuristics.py ........                               [ 79%]
tests/unit/url/test_normalizer.py ........                               [ 83%]
tests/unit/url/test_punycode_homoglyph.py .....                          [ 86%]
tests/unit/url/test_reputation.py ....                                   [ 88%]
tests/unit/url/test_risk_engine.py ............                          [ 93%]
tests/unit/url/test_typosquatting.py .....                               [ 96%]
tests/unit/url/test_url_api.py ........                                  [100%]
============================= 209 passed in 7.03s =============================

# Ruff Code Quality
ruff check src tests -> All checks passed!
ruff format --check src tests -> 158 files already formatted

# Mypy Type Checker
mypy src/zenshield -> Success: no issues found in 87 source files

# Pip-Audit Vulnerability Scan
pip-audit -> No known vulnerabilities found
```

---

## 3. Resolution of the 23 Identified Conflicts

| # | Conflict Identified | Resolution Mechanism |
| :- | :--- | :--- |
| **1** | **Package Root Collision** (`backend` vs `zenshield` vs `app`) | Migrated all modules into a single installable package `src/zenshield/`. Provided backward-compatibility package shims (`src/backend` and `src/app`) so unmodified tests and legacy imports resolve without broken links. |
| **2** | **Import Style Discrepancies** | Replaced all relative/flat imports with absolute `zenshield.*` imports. App can be executed from any directory or as an installed package. |
| **3** | **Multiple `main.py`, `/health`, and lifespans** | Created single `zenshield.main:app` factory. Consolidated lifespan handler managing database table creation, seed data, and HTTP client lifecycle. Unified `/health` reporting DB status and readiness of all 3 engines (`url`, `message`, `intelligence`). Added `/` root status endpoint. |
| **4** | **Risk Schema Mismatches** (`0.0-1.0` vs `0-100`, levels `LOW/MEDIUM/HIGH/CRITICAL` vs `low/medium/high`) | Created unified `RiskAssessment` and aliased `RiskResult`. Normalized score to `int 0-100` and level to `LOW|MEDIUM|HIGH|CRITICAL`. Implemented `map_level_to_unified()` mapping `CAUTION -> MEDIUM`. Retained additive legacy fields (`is_risky`, `risk_score` 0.0-1.0, lowercase `risk_level`, `reasons`) for frontend backward compatibility. |
| **5** | **Sync vs Async Event Loop Blocking** | Implemented `run_in_threadpool` and `asyncio.to_thread` wrappers in `URLAdapter.analyze_url_async()`. SQLite database lookups, regex operations, and blocking requests now execute without blocking the main event loop. |
| **6** | **Inconsistent Error Response Envelopes** | Standardized all error responses to a unified envelope: `{"error": {"code", "message", "details?"}, "detail": message, "request_id": uuid}`. Preserved `"detail"` string key to maintain compatibility with Starlette/FastAPI default expectations. |
| **7** | **Raw Content Echo / Privacy Leakage** | `VerifyResponse` and `OCRAnalyzeResponse` now sanitize and return masked message text (`content_out = getattr(result, "_masked_message", ...)`). Zero raw sensitive PII is returned or logged in audit records. |
| **8** | **Fragmented Configuration Systems** | Unified all settings into `zenshield.core.config.Settings` (Pydantic BaseSettings) with `ZENSHIELD_` prefix. Configured fallback readers to transparently accept legacy unprefixed environment variables (`HOST`, `PORT`, `DEBUG`, `APP_NAME`, etc.). |
| **9** | **Obsolete Microservice Placeholders** | Removed `URL_DETECTION_ENGINE_URL` and `SMS_DETECTION_ENGINE_URL` from configuration and `.env.example`. All engines operate in-process via typed adapters. |
| **10** | **Missing & Split Dependencies** | Consolidated all dependencies in `pyproject.toml` (enforcing Python `>=3.11`). Added `sqlalchemy`, `pydantic-settings`, `tldextract`, `idna`, `pytest-asyncio`, `hypothesis`, and `pip-audit`. |
| **11** | **`tldextract` Outbound Network Calls** | Configured `tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)` in `url_normalizer.py`, completely preventing runtime downloads from publicsuffix.org. |
| **12** | **Dual Unconnected IOC Stores** | Merged SQLite IOC store and intelligence database into a single SQLAlchemy `threat_iocs` table. Implemented `DatabaseReputationProvider` so community reports submitted via `/intelligence/report` immediately elevate risk scores and set `known_ioc: true` in `/verify`. |
| **13** | **Import-Time Side Effects (`init_db()`)** | Removed `init_db()` from `app.intelligence.router` module-level scope. Database initialization now runs deterministically inside the FastAPI `lifespan` handler. |
| **14** | **Double Prefixing on Intelligence Router** | Configured `prefix="/intelligence"` in `zenshield/api/v1/intelligence.py` and mounted under `/api/v1` in `main.py`, cleanly producing `/api/v1/intelligence/check` and `/api/v1/intelligence/report`. |
| **15** | **Overlapping Phishing Report Endpoints** | Wired `POST /api/v1/report/phishing` to `ThreatIntelAdapter.create_report()`. Validates payload, persists indicator to `threat_iocs`, and returns backward-compatible `{status: "received", category, report_id, ioc_id}`. |
| **16** | **Campaign Analytics Stub** | Replaced hard-coded stub in `GET /api/v1/campaign/stats` with live SQL aggregations querying active campaigns, total IOCs, total reports, and active threat counts. |
| **17** | **Insecure CORS Configuration** | Corrected CORS configuration. Set `allow_credentials=False` whenever wildcard `"*"` is included in origins. Environment-driven origin parsing with validation. |
| **18** | **Conflicting Body Size Limits** | Implemented route-aware `BodySizeLimitMiddleware`: enforces 64 KB limit for standard JSON endpoints (`/verify`, `/intelligence/report`) and 10 MB limit for multipart image endpoints (`/qr/scan`, `/ocr/analyze`). |
| **19** | **Streaming / Chunked Body Limit Bypass** | Enforced body size limits on the ASGI `receive()` byte stream (`receive_with_limit`), rejecting oversized chunked transfers with HTTP 413 even when `Content-Length` header is omitted. |
| **20** | **Inconsistent Brand Names** | Standardized service identity on `ZenShield` across logs, titles, schemas, docs, and health checks. Deprecated references to `RedFlag`. |
| **21** | **Colliding Test Trees** | Reorganized tests into `tests/unit/{url,message,intelligence,privacy,services}/` and `tests/integration/`. Created root `tests/conftest.py` with session-scoped in-memory DB and shared client fixtures. |
| **22** | **Dirty VCS & Cache Files in Artifacts** | Cleaned up all `__pycache__`, `.pytest_cache`, and stray `.db` files. Created comprehensive `.gitignore` and `.gitattributes` (`* text=auto eol=lf`). |
| **23** | **Duplicate / Obsolete READMEs** | Replaced conflicting documentation with a single, production-grade `README.md` including architecture diagram, endpoint table, configuration guide, and setup instructions. |

---

## 4. Architecture & Package Structure

```
zenshield-backend/
├── pyproject.toml              # Unified project specification & tooling config
├── .env.example                # Single source of truth for environment variables
├── .gitattributes              # Normalizes line endings to LF across repository
├── .gitignore                  # Comprehensive ignore patterns
├── Dockerfile                  # Multi-stage production container with Tesseract/OpenCV
├── docker-compose.yml          # Containerized local orchestration
├── Makefile                    # Developer targets (install, test, lint, format, run)
├── README.md                   # Consolidated technical documentation
├── INTEGRATION_REPORT.md       # Full integration & hardening audit report
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI matrix (3.11, 3.12)
├── src/
│   ├── zenshield/
│   │   ├── main.py             # create_app() factory, lifespan, health & root routes
│   │   ├── core/
│   │   │   ├── config.py       # pydantic-settings Settings with ZENSHIELD_ prefix
│   │   │   ├── errors.py       # Unified error response envelope & sanitized 422 handler
│   │   │   ├── logging.py      # Zero-leakage audit logger
│   │   │   ├── middleware.py   # Request ID, route-aware body size limit, CORS
│   │   │   └── security.py     # Magic bytes, path sanitization, decompression bomb check
│   │   ├── db/
│   │   │   ├── database.py     # Database session factory, lifespan init_db, IOC seed
│   │   │   └── models.py       # SQLAlchemy models (threat_iocs, reports, community_reports)
│   │   ├── schemas/
│   │   │   ├── risk.py         # Unified RiskAssessment, RiskResult, level mappers
│   │   │   ├── verification.py # VerifyRequest, VerifyResponse, QRScan, OCR models
│   │   │   └── intelligence.py # IOC registration, community reporting schemas
│   │   ├── adapters/
│   │   │   ├── url_adapter.py  # Coordinates RiskEngine, DatabaseProvider, VirusTotal
│   │   │   ├── message_adapter.py # Coordinates MessageAnalyzer, PII, nested URL checking
│   │   │   └── threat_intel_adapter.py # Coordinates reputation check & reporting
│   │   ├── engines/
│   │   │   ├── url/            # Static URL risk engine (normalizer, heuristics, entropy)
│   │   │   ├── message/        # Message engine (multilingual lexicon, scoring, Groq LLM)
│   │   │   └── intelligence/   # Threat intel services (reputation, reports, masking)
│   │   ├── privacy/            # PII detector, masker, sanitizer, offline url_extractor
│   │   ├── services/
│   │   │   ├── qr_service.py   # OpenCV QR decoder with URL risk forwarding
│   │   │   ├── ocr_service.py  # Tesseract OCR extraction with message risk forwarding
│   │   │   └── threat_service.py # VirusTotal & external threat provider abstraction
│   │   └── api/v1/
│   │       ├── router.py       # API v1 aggregator router
│   │       ├── verify.py       # POST /api/v1/verify (unified entrypoint)
│   │       ├── url.py          # POST /api/v1/verify/url
│   │       ├── message.py      # POST /api/v1/verify/message
│   │       ├── qr.py           # POST /api/v1/qr/scan
│   │       ├── ocr.py          # POST /api/v1/ocr/analyze
│   │       ├── report.py       # POST /api/v1/report/phishing
│   │       ├── campaign.py     # GET /api/v1/campaign/stats
│   │       └── intelligence.py # /api/v1/intelligence/check & /report
│   ├── backend/                # Compatibility shim package for legacy imports
│   └── app/                    # Compatibility shim package for intelligence imports
└── tests/
    ├── conftest.py             # Session-scoped test DB, client fixture
    ├── integration/
    │   ├── test_verify.py      # Full-app end-to-end verification tests
    │   ├── test_security.py    # Hardening, byte limits, magic bytes, zero leakage
    │   ├── test_startup.py     # Boots from foreign dir, custom DB path, health
    │   ├── test_qr.py          # QR scanning integration tests
    │   ├── test_ocr.py         # OCR image processing integration tests
    │   └── test_campaign_report.py # Phishing report & campaign stats
    └── unit/
        ├── url/                # 57 URL engine tests
        ├── message/            # 50 Message engine tests
        ├── privacy/            # 14 PII & masker tests
        ├── intelligence/       # 38 Threat intel tests
        └── services/           # 9 ThreatService & VirusTotal tests
```

---

## 5. Unified Response Contract & Backward Compatibility

All verification endpoints return payloads conforming to the `RiskAssessment` contract:

```json
{
  "type": "url",
  "content": "https://suspicious-domain.com/login",
  "result": {
    "score": 85,
    "level": "CRITICAL",
    "classification": "Known Malicious",
    "confidence": 0.95,
    "signals": [
      {
        "id": "url_signal_threat_intelligence_match",
        "name": "Threat intelligence match",
        "severity": "critical",
        "evidence": "Matched active community threat IOC: suspicious-domain.com",
        "weight": null,
        "rule_id": null
      }
    ],
    "known_ioc": true,
    "recommendation": "Block and do not interact with this indicator.",
    "request_id": "8c35a64b-810a-4786-8a71-d8ecb160a28f",

    "is_risky": true,
    "risk_score": 0.85,
    "risk_level": "critical",
    "reasons": [
      "Matched active community threat IOC: suspicious-domain.com"
    ]
  }
}
```

### Risk Level Mapping Table

| Source Level / Score | Unified Score | Unified Level | Legacy `is_risky` | Legacy `risk_level` |
| :--- | :---: | :---: | :---: | :---: |
| `0 - 24` / `LOW` | `0 - 24` | `LOW` | `false` | `"low"` |
| `25 - 49` / `CAUTION` / `MEDIUM` | `25 - 49` | `MEDIUM` | `false` (or `true` if flagged) | `"medium"` |
| `50 - 74` / `HIGH` | `50 - 74` | `HIGH` | `true` | `"high"` |
| `75 - 100` / `CRITICAL` | `75 - 100` | `CRITICAL` | `true` | `"critical"` |

---

## 6. Environment Variable Migration Guide

| Old Environment Variable | New Standard Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `APP_NAME` | `ZENSHIELD_APP_NAME` | `"ZenShield"` | Service name in health checks |
| `DEBUG` | `ZENSHIELD_DEBUG` | `false` | Debug mode |
| `HOST` | `ZENSHIELD_HOST` | `"0.0.0.0"` | Bind interface |
| `PORT` | `ZENSHIELD_PORT` | `8000` | Server listen port |
| `ALLOWED_ORIGINS` | `ZENSHIELD_ALLOWED_ORIGINS` | `"http://localhost:3000,..."` | CORS allowed origins |
| `MAX_REQUEST_BODY_BYTES` | `ZENSHIELD_MAX_REQUEST_BODY_BYTES` | `65536` | Maximum JSON request size (64 KB) |
| `DATABASE_URL` | `ZENSHIELD_DATABASE_URL` | `"sqlite:///./zenshield.db"` | Central SQLAlchemy connection string |
| `DATABASE_PATH` | `ZENSHIELD_DATABASE_PATH` | `"./data/ioc.db"` | Fallback SQLite IOC database path |
| `VIRUSTOTAL_API_KEY` | `ZENSHIELD_VIRUSTOTAL_API_KEY` | `""` | VirusTotal API v3 key |
| `SAFE_BROWSING_API_KEY` | `ZENSHIELD_SAFE_BROWSING_API_KEY` | `""` | Google Safe Browsing API key |
| `GROQ_API_KEY` | `ZENSHIELD_GROQ_API_KEY` | `""` | Groq LLM API key |
| `TESSERACT_CMD` | `ZENSHIELD_TESSERACT_CMD` | `""` | Custom path to Tesseract binary |
| *N/A (obsolete)* | `URL_DETECTION_ENGINE_URL` | *Removed* | Obsolete microservice placeholder |
| *N/A (obsolete)* | `SMS_DETECTION_ENGINE_URL` | *Removed* | Obsolete microservice placeholder |

---

## 7. Security Hardening & Zero-Leakage Verification

1. **Streaming Body Size Limit:** The custom `BodySizeLimitMiddleware` intercepts raw ASGI chunks as they arrive. Attempts to stream more than 64 KB of JSON via chunked transfer encoding (omitting `Content-Length`) immediately terminate with `HTTP 413 Payload Too Large`.
2. **Magic Bytes Validation:** Files uploaded to `/qr/scan` or `/ocr/analyze` are inspected for exact file signatures (`\x89PNG\r\n\x1a\n` for PNG, `\xff\xd8\xff` for JPEG, `RIFF....WEBP` for WebP). Content-type spoofing (such as plain text files renamed with `.png` extensions) is rejected with `HTTP 400 Bad Request`.
3. **Decompression Bomb Defense:** Image dimensions are validated prior to decoding or scaling. Uploads exceeding `4096 × 4096` pixels are rejected with `HTTP 400 Bad Request`.
4. **Path Traversal Protection:** File names in multipart uploads are scrubbed using `os.path.basename` and stripped of control characters and path traversal sequences (`../../`).
5. **SSRF Prevention:** URL analysis strictly computes static lexical, structural, and cryptographic properties (entropy, Levenshtein distance, Punycode decoders, brand lookalikes). Under no circumstances are socket connections or HTTP requests made to target URLs.
6. **Information Disclosure Prevention:** The unified `unhandled_exception_handler` catches all uncaught server errors and returns a generic `500 Internal Server Error` message. Stack traces, credentials, and internal database paths are never leaked to the client.
7. **Sanitized Input Validation:** The custom `RequestValidationError` handler returns only field names and validation codes. It never echoes client inputs or canary tokens back in error details.

---

## 8. Residual Risks & Production Recommendations

1. **Tesseract-OCR System Dependency:**
   - *Risk:* In local development environments on Windows, `pytesseract` requires manual installation of Tesseract binaries.
   - *Mitigation:* The provided `Dockerfile` installs `tesseract-ocr` and `tesseract-ocr-eng` automatically. In local environments where Tesseract is absent, the endpoint returns an informative `500` error directing the administrator to configure `ZENSHIELD_TESSERACT_CMD`.
2. **PostgreSQL Migration for High-Throughput Deployments:**
   - *Recommendation:* SQLite with `check_same_thread=False` and WAL mode is suitable for moderate workloads. For horizontal scaling across multiple container replicas, set `ZENSHIELD_DATABASE_URL="postgresql+psycopg://user:pass@host:5432/zenshield"` without code changes.
3. **VirusTotal Rate Limits:**
   - *Recommendation:* VirusTotal's public API tier enforces a limit of 4 requests/minute. In production, keep `ZENSHIELD_ENABLE_EXTERNAL_REPUTATION=false` or ensure an enterprise API key is provided with caching enabled.
