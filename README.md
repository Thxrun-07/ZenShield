# Zenshield: Multilingual Message Phishing Verification & Privacy Engine

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/framework-FastAPI-teal.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-64%20passed-brightgreen.svg)]()
[![Privacy](https://img.shields.io/badge/privacy-Zero%20Data%20Leakage-purple.svg)]()

Zenshield is a production-ready, security-focused backend verification engine designed to detect SMS phishing (smishing), fraudulent payment links, social engineering, impersonation scams, and credential harvesting in incoming communications (SMS, WhatsApp, email, chat).

It features native support for **Tamil Unicode** and **Tanglish** (Tamil written phonetically in Latin characters), an algorithmic dual-view text normalization engine, explainable deterministic integer scoring, and an optional, sandboxed LLM enrichment layer guarded by a strict **Residual-PII Gate**.

---

## Architecture Overview

```
                               Raw Message Ingestion
                                        │
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │       Stage 0: Dual-View Sanitizer Engine            │
             │  • NFKC Normalization   • Indic-to-ASCII Digits     │
             │  • Strip Bidi / ZWSP    • Canonical & Fold Views    │
             └──────────────────────────┬──────────────────────────┘
                                        │
                     ┌──────────────────┴──────────────────┐
                     │                                     │
                     ▼                                     ▼
        ┌─────────────────────────┐           ┌─────────────────────────┐
        │  Stage 1: PII Detector  │           │   URLExtractor (PSL)    │
        │  • Aadhaar (Verhoeff)   │           │  • Lookalike vs Brands  │
        │  • Phone, Email, UPI    │           │  • Punycode & Shortener │
        │  • PAN, IFSC, Account   │           │  • Strip Path & Query   │
        └────────────┬────────────┘           └────────────┬────────────┘
                     │                                     │
                     └──────────────────┬──────────────────┘
                                        │
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │         Stage 2: Deterministic Span Masker          │
             │  • Right-to-Left Replacement (No Offset Drift)      │
             │  • Request-Scoped Counters (PERSON_01, PERSON_02)   │
             │  • Safe URL Metadata & Preserved Financial Amounts  │
             └──────────────────────────┬──────────────────────────┘
                                        │
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │       Stage 3: Multilingual & Tanglish Engine       │
             │  • Unicode Script Ratio • Algorithmic Canonicalizer │
             │  • Digraph Mapping (dh->d, th->t, ee->i, oo->u)     │
             │  • N-Gram Token Density (1-gram, 2-gram, 3-gram)    │
             └──────────────────────────┬──────────────────────────┘
                                        │
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │    Stage 4: Context & Negation-Aware Intents (23)   │
             │  • Bidirectional Negation (English & Tamil/Tanglish)│
             │  • OTP_NOTIFICATION vs Malicious OTP_REQUEST        │
             └──────────────────────────┬──────────────────────────┘
                                        │
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │     Stage 5: Multi-Vector Signal Pattern Matcher     │
             │  • Malware / APK Risk   • Credential Solicitation   │
             │  • Impersonation Threat • Prompt Injection Attempt  │
             └──────────────────────────┬──────────────────────────┘
                                        │
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │        Stage 6: Deterministic Scoring Engine        │
             │  • Base Weights (Capped at 60)                      │
             │  • Non-Linear Combination Bonuses (+10 to +20)      │
             │  • Safety Floor Anchors (Floor 50 for Malware/Cred) │
             └──────────────────────────┬──────────────────────────┘
                                        │
                                        ├──────────────────────────────┐
                           [enable_llm=true]                           │ [enable_llm=false]
                                        ▼                              │
             ┌───────────────────────────────────────────┐             │
             │     Stage 7: Optional LLM Enrichment      │             │
             │  • Residual-PII Gate (Fails Closed)       │             │
             │  • Injection Bypass (Skips LLM)           │             │
             │  • Strict Bounded Delta [-10, +10]        │             │
             └──────────────────────────┬────────────────┘             │
                                        │                              │
                                        └──────────────┬───────────────┘
                                                       │
                                                       ▼
                                     ┌───────────────────────────────────┐
                                     │   Final Response Synthesis        │
                                     │  • Score [0-100] & Risk Level     │
                                     │  • Zero Raw PII in Response       │
                                     └───────────────────────────────────┘
```

---

## Privacy and Data Handling

The system adheres strictly to the **Zero-Leakage Privacy Contract**:

1. **Process Boundary Invariant**: Raw message content and sensitive identity values never leave the local application process memory.
2. **Residual-PII Gate**: When optional LLM enrichment is enabled, the masked text is passed through the PII detector a second time. If even one residual entity is detected, external dispatch is aborted immediately (fails closed).
3. **No Message Persistence**: Raw message bodies are never written to disk, databases, application logs, or telemetry.
4. **Scrubbed HTTP 422 Errors**: FastAPI's default validation handler is replaced with a custom sanitizer that returns only field names and error codes, never echoing user input in error responses.
5. **Safe URL Redaction**: Full URLs are masked as `[URL_REDACTED]`. Only safe domain-level metadata (e.g., registrable domain, HTTPS status, punycode flag) is extracted; query strings, auth tokens, tracking IDs, and personal paths are discarded.
6. **Preservation of Security Concepts**: Sensitive identities are masked while security-critical terminology remains intact:
   - Preserved: `OTP`, `KYC`, `Password`, `UPI`, `Bank`, `Account`, `Refund`, `Loan`, `Challan`, `Amount (e.g. ₹500)`.
   - Masked: `[OTP_REDACTED]`, `[PHONE_REDACTED]`, `[EMAIL_REDACTED]`, `[UPI_REDACTED]`, `[ACCOUNT_REDACTED]`, `[AADHAAR_REDACTED]`, `[PAN_REDACTED]`, `[IFSC_REDACTED]`, `[URL_REDACTED]`, `PERSON_01`.

---

## Directory Structure

```
backend/
├── api/
│   ├── __init__.py           # Package router exports
│   └── routes.py             # FastAPI routes (POST /api/v1/verify/message)
├── message/
│   ├── __init__.py           # Message package exports
│   ├── analyzer.py           # MessageAnalyzer orchestrator with Dependency Injection
│   ├── intent.py             # 23 fraud/transactional intents with bidirectional negation
│   ├── language.py           # Multilingual & Tanglish canonicalization engine
│   ├── llm.py                # LLM Protocol, SafeLLMEnricher, and Residual-PII Gate
│   ├── models.py             # Pydantic v2 schemas and domain models
│   ├── patterns.py           # Multi-vector regex risk signal matchers
│   └── scoring.py            # Integer scoring engine with combination bonuses
├── privacy/
│   ├── __init__.py           # Privacy package exports
│   ├── masker.py             # Right-to-left deterministic span substitution
│   ├── models.py             # DetectedEntity, URLMetadata, MaskedResult
│   ├── pii_detector.py       # Verhoeff Aadhaar, phone, OTP, PAN, IFSC, UPI extractor
│   ├── sanitizer.py          # DualViewText builder, Indic digits to ASCII, homoglyphs
│   └── url_extractor.py      # Offline PSL domain resolver & lookalike detector
├── config.py                 # Pydantic BaseSettings, weights, and brand allowlists
└── main.py                   # FastAPI application factory & security middleware

tests/
├── test_analyzer.py          # End-to-end integration tests & ReDoS latency checks
├── test_api.py               # API endpoints, 422 input scrubbing, 413 size limits
├── test_intent.py            # 23 intents, negation scoping, spoofing defense
├── test_language.py          # English, Tamil, Tanglish, and Mixed script tests
├── test_masker.py            # Masking span integrity, canary tests, Hypothesis properties
├── test_pii_detector.py      # PII detection accuracy, Verhoeff checksums, priority resolution
└── test_scoring.py           # Boundary scoring, combination bonuses, floor anchors
```

---

## Installation & Setup

### Prerequisites
- Python 3.11+ (Python 3.14 fully supported)
- pip

### Installation
```bash
# Clone the repository
git clone https://github.com/your-org/zenshield.git
cd zenshield

# Install dependencies
pip install -e .

# Install testing dependencies
pip install pytest pytest-asyncio hypothesis ruff
```

---

## Configuration & Environment Variables

All configuration options are defined in [`backend/config.py`](file:///c:/Users/shinc/projects/Zenshield/backend/config.py) and can be overridden via environment variables prefixed with `ZENSHIELD_`:

| Environment Variable | Default | Description |
|---|---|---|
| `ZENSHIELD_MAX_RAW_MESSAGE_LENGTH` | `10000` | Max character length of incoming raw message |
| `ZENSHIELD_MAX_REQUEST_BODY_BYTES` | `65536` | Max HTTP request body size (64 KB) |
| `ZENSHIELD_PERSIST_MESSAGE_CONTENT` | `false` | Invariant: raw messages are never written to disk or logs |
| `ZENSHIELD_LLM_PROVIDER` | `"noop"` | LLM provider: `"noop"` (default, zero network calls) or `"groq"` |
| `ZENSHIELD_ENABLE_LLM_DEFAULT` | `false` | Server-side gate allowing optional LLM enrichment |
| `ZENSHIELD_LLM_BASE_URL` | `https://api.groq.com/openai/v1` | OpenAI-compatible API base URL (must use HTTPS) |
| `ZENSHIELD_LLM_API_KEY` | `None` | API key (SecretStr, required if provider is `"groq"` and enabled) |
| `ZENSHIELD_LLM_MODEL` | `""` | Model identifier (e.g. `llama-3.3-70b-versatile`) |
| `ZENSHIELD_LLM_ENDPOINT_ALLOWLIST` | `{"api.groq.com"}` | Approved hostnames for external LLM dispatch |
| `ZENSHIELD_LLM_TIMEOUT_SECONDS` | `1.5` | Strict timeout in seconds for LLM call |
| `ZENSHIELD_MAX_LLM_PAYLOAD_LENGTH` | `1000` | Character truncation limit for masked LLM payload |
| `ZENSHIELD_THRESHOLD_LOW` | `24` | Upper bound for LOW risk (0-24) |
| `ZENSHIELD_THRESHOLD_MEDIUM` | `49` | Upper bound for MEDIUM risk (25-49) |
| `ZENSHIELD_THRESHOLD_HIGH` | `74` | Upper bound for HIGH risk (50-74) |

### Groq LLM Integration & Privacy Architecture

Zenshield supports optional contextual risk refinement via **Groq** (OpenAI-compatible chat completions). The engine is **100% deterministic by default** with `ZENSHIELD_LLM_PROVIDER="noop"`.

#### Enabling Groq
To enable Groq enrichment, configure your environment or `.env` file:
```bash
ZENSHIELD_ENABLE_LLM_DEFAULT=true
ZENSHIELD_LLM_PROVIDER=groq
ZENSHIELD_LLM_API_KEY=gsk_your_groq_api_key_here
ZENSHIELD_LLM_MODEL=llama-3.3-70b-versatile
```

#### Privacy Advisory & Process Boundary Guarantees
> [!WARNING] **Privacy Notice**
> When `ZENSHIELD_ENABLE_LLM_DEFAULT=true` and `ZENSHIELD_LLM_PROVIDER="groq"`, **sanitized and masked text** (where all detected phone numbers, OTPs, Aadhaar numbers, accounts, PANs, IFSCs, and full URLs have been deterministically redacted) along with extracted intent and signal names leave the process boundary to Groq (`api.groq.com`).
>
> **Raw unmasked message content and PII never leave the local application memory under any circumstances.**

#### Multi-Tier Defense-in-Depth for LLM Calls:
1. **Dual Gatekeeper**:
   - **Residual-PII Gate**: Before any network request is created, the masked text is scanned again by the PII detector. If even a single residual entity is detected, the external call is aborted immediately (fails closed).
   - **Prompt Injection Bypass**: If an adversarial prompt injection pattern is detected, the LLM call is bypassed entirely and the deterministic signal `prompt_injection_attempt` (+15) is scored.
2. **Server-Side Authorization**:
   - Client requests with `"enable_llm": true` only take effect if `ZENSHIELD_ENABLE_LLM_DEFAULT=true` is configured on the server. External callers cannot force external LLM egress.
3. **Strict Validation & Host Allowlisting**:
   - Startup validation mandates that `ZENSHIELD_LLM_BASE_URL` uses `https` and its host is in `ZENSHIELD_LLM_ENDPOINT_ALLOWLIST` (`api.groq.com`).
   - The API key is stored as `SecretStr` and is never exposed in `repr(settings)`, application logs, or error strings.
4. **Structured JSON Output & Clamped Deltas**:
   - The prompt requires strict JSON output: `{"delta": int, "rationale_code": str}`.
   - `rationale_code` is validated against a closed enum (`CONSISTENT_WITH_RULES`, `LEGIT_CONTEXT`, `ADDITIONAL_RISK`, `UNCLEAR`).
   - `delta` is strictly clamped to $[-10, +10]$.
   - If the message has no deterministic signals, the LLM is prohibited from increasing the score ($\Delta \le 0$).
5. **Zero-Retry Fail-Safe Fallbacks**:
   - HTTP 429 (rate limits), HTTP 5xx (server errors), connection timeouts (1.5s), and invalid JSON schemas gracefully fall back to the deterministic score with `llm_used=false`.
   - No request bodies, response contents, or exception strings from `httpx` are ever logged.

---

## API Usage

### Endpoint: `POST /api/v1/verify/message`

#### Request Headers
- `Content-Type: application/json`
- `X-Request-ID: <optional-uuid>`

#### Request Body
```json
{
  "message": "Hi Ravi, your OTP is 482931. Call 9876543210 immediately to verify your KYC.",
  "country": "IN",
  "channel": "sms",
  "enable_llm": false
}
```

#### Example cURL Command
```bash
curl -X POST http://localhost:8000/api/v1/verify/message \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Ungal account block aagum. Ippove OTP kuduthu KYC verify pannunga. Call 9876543210.",
    "country": "IN",
    "channel": "sms",
    "enable_llm": false
  }'
```

#### Successful Response (`200 OK`)
```json
{
  "request_id": "7b8e1f52-4a5e-4c75-8120-74737c355919",
  "score": 80,
  "risk_level": "CRITICAL",
  "classification": "High-Risk Scam",
  "language": "Tanglish",
  "intents": [
    "OTP_REQUEST",
    "KYC",
    "ACCOUNT_SUSPENSION"
  ],
  "signals": [
    {
      "id": "sig_credential_request",
      "weight": 30,
      "rule_id": "RULE_CREDENTIAL_REQUEST"
    },
    {
      "id": "sig_threat",
      "weight": 20,
      "rule_id": "RULE_THREAT_COERCION"
    },
    {
      "id": "sig_urgency",
      "weight": 15,
      "rule_id": "RULE_URGENCY_PRESSURE"
    },
    {
      "id": "sig_call_to_action",
      "weight": 10,
      "rule_id": "RULE_CTA_ACTION"
    }
  ],
  "breakdown": {
    "base_raw": 75,
    "base_capped": 60,
    "bonuses": [
      {
        "name": "credential_urgency",
        "weight": 15,
        "rule_id": "BONUS_CRED_URGENCY"
      },
      {
        "name": "credential_phone_cta",
        "weight": 10,
        "rule_id": "BONUS_CRED_PHONE_CTA"
      }
    ],
    "llm_delta": 0,
    "anchors_applied": [],
    "final": 80
  },
  "url_metadata": [],
  "masked_entity_counts": {
    "PHONE": 1
  },
  "llm_used": false,
  "privacy": {
    "pii_detected": true,
    "external_text_sent": false,
    "masked_message": "Ungal account block aagum. Ippove OTP kuduthu KYC verify pannunga. Call [PHONE_REDACTED]."
  },
  "analysis": {
    "rule_based": true,
    "llm_used": false
  }
}
```

---

## Risk Scoring & Taxonomy

### The 11 Risk Signals & Base Weights
- `malware_risk`: **35** (APK installation, sideload links)
- `credential_request`: **30** (OTP, password, PIN, CVV harvesting)
- `sensitive_data_request`: **30** (Aadhaar, PAN, bank statements without credentials)
- `financial_request`: **25** (Payment demands, processing fees, advance fees)
- `suspicious_url`: **25** (Lookalikes, punycode, shorteners, raw IP)
- `threat`: **20** (Arrest warrants, police action, disconnection)
- `urgency`: **15** (Immediate action, today only, ippove, udane)
- `impersonation`: **15** (Govt, police, cyber crime, banks, couriers)
- `social_engineering`: **15** (Lottery, fake job offers, crypto returns)
- `call_to_action`: **10** (Phone call, link click; **5** for toll-free 1800/1860)
- `prompt_injection_attempt`: **15** (Adversarial override attacks)

### Non-Linear Combination Bonuses
- `credential_urgency`: $+15$
- `credential_phone_cta`: $+10$
- `kyc_suspicious_url`: $+20$
- `gov_threat`: $+20$
- `prize_payment`: $+20$
- `loan_advance_fee`: $+20$
- `courier_fee`: $+15$
- `suspension_login`: $+20$
- `threat_urgency_payment`: $+15$

### Safety Floors & Bounded LLM Adjustments
- Base score is capped at `60` before bonuses.
- Final score is bounded strictly within $[0, 100]$.
- **Safety Floor 50**: Applied if `malware_risk` is detected or if `credential_request + call_to_action` occurs.
- **LLM Delta Guard**: LLM adjustments are clamped to $[-10, +10]$. If no deterministic signals fired, the LLM cannot raise the score ($\Delta \le 0$).

---

## Running Tests & Quality Verification

```bash
# Run the complete test suite (64 unit and integration tests including Groq mock tests)
python -m pytest -v

# Run strict type checking across all backend modules
python -m mypy --strict backend

# Run linting and code style checks
python -m ruff check .
```

---

## Running the API Locally

```bash
# Start the server with uvicorn
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Test the health check endpoint:
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"zenshield"}
```

---

## Production Deployment Recommendations

1. **Reverse Proxy & TLS Termination**: Run behind NGINX or AWS ALB with TLS 1.3. Limit maximum client body size to 64KB.
2. **Process Isolation**: Deploy as a containerized stateless microservice. No local disk persistence is required.
3. **Structured Audit Logging**: Pipe logs to CloudWatch/Datadog with log aggregation. Only request IDs, latency, and status codes are recorded.
4. **Latency Budget**: The deterministic pipeline executes within 10–25ms p95 on 1,000-character messages. When enabling LLM enrichment, run workers with async connection pools.
