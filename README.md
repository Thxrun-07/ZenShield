# ZenShield — Backend URL Detection & Centralized Risk Engine

ZenShield is a community-focused cybersecurity platform designed to protect users against malicious URLs, regional financial fraud campaigns, phishing links, and brand impersonation domains.

This module implements **Person 1 — Backend URL Verification and Centralized Risk Engine**.

---

## 🔒 Security Design Principle: 100% Static URL Analysis

> [!IMPORTANT]
> **Static Safety Guarantee:**
> Submitted URLs are **NEVER visited, fetched, or contacted**.
> The system **does NOT**:
> - Make HTTP/HTTPS network requests to the target destination
> - Resolve external DNS queries for untrusted hosts
> - Execute JavaScript
> - Follow HTTP redirects
> - Download page content or binaries
> - Submit raw submitted URLs to arbitrary external cloud APIs without explicit user consent
>
> All detection routines operate strictly via in-memory static analysis, mathematical entropy calculation, lexical heuristics, and local IOC databases.

---

## 🏗️ Architecture & Static Detection Pipeline

```
                     Input Raw URL
                           │
                           ▼
               1. URL Normalization & Parsing
         (Whitespace, Scheme, Netloc, Punycode, IDN)
                           │
                           ▼
               2. Local IOC / Reputation Check
           (SQLite-backed Domain and URL Indicators)
                           │
                           ▼
                3. Lexical & Domain Analysis
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
    ▼                      ▼                      ▼
Typosquatting      Punycode & Homoglyph    Shannon Entropy
(Damerau-Levenshtein) (Mixed-Script, Lookalikes) (Randomized DGA)
    │                      │                      │
    ▼                      ▼                      ▼
Structural Heuristics Brand Impersonation  Contextual Path Lures
(Raw IP, TLD, Subdomains) (Subdomains & Compounds) (/login, /otp, /payment)
    └──────────────────────┼──────────────────────┘
                           │
                           ▼
               4. Centralized Risk Engine
         (Weighted scoring: 0–100, Risk Levels,
          Signal agreement confidence: 0.0–1.0)
                           │
                           ▼
                5. Structured API Response
```

---

## 📊 Risk Scoring & Classification

The Central Risk Engine caps all scores between **0** and **100** based on weighted engineering signals:

| Component | Weight | Description |
| :--- | :---: | :--- |
| **Known Malicious IOC** | +40 | Direct match in local threat indicator repository (+15 if community-verified) |
| **Brand Impersonation** | +20 | Trusted brand keyword in subdomain or compound registered domain |
| **Typosquatting** | +15 | Damerau-Levenshtein edit distance <= 2 to trusted domains (e.g. `paypa1.com`) |
| **Punycode / Homoglyph** | +15 | Mixed-script lookalikes or homoglyphs imitating trusted brands |
| **Raw IP Address Host** | +15 | URL uses direct IP instead of registered domain |
| **Credential-related Path** | +15 | Path contains `/login`, `/signin`, `/verify`, `/otp`, etc. |
| **Suspicious TLD** | +12 | Domain ends in `.zip`, `.top`, `.xyz`, `.country`, `.click`, etc. |
| **Financial / Payment Intent**| +10 | Path contains `/payment`, `/refund`, `/invoice`, `/wallet`, etc. |
| **Non-standard Port** | +10 | Uses non-standard port (e.g. `:4444`, `:8080`) |
| **Urgency Keyword** | +8 | Contains `suspended`, `action-required`, `urgent`, etc. |
| **High Entropy** | +5 | Unusually high Shannon character entropy (H >= 3.8) indicating DGA |

### Engineering Risk Levels
- `0 – 24`: **LOW**
- `25 – 49`: **CAUTION**
- `50 – 74`: **HIGH**
- `75 – 100`: **CRITICAL**

### Explainable Classifications
- **Safe**: Clean URL, verified trusted domain, or no suspicious signals detected.
- **Low Risk**: Isolated weak/contextual heuristics (e.g. single `/login` on benign unlisted site).
- **Suspicious**: Moderate signals or concurring indicators (e.g. raw IP host + login intent).
- **Potential Phishing**: Multiple concurring high-confidence threats (e.g. typosquatting + credential path + brand lure).
- **Known Malicious**: URL or domain explicitly present in active threat IOC database.

### Confidence Score (0.0 to 1.0)
Confidence represents certainty in the classification based on signal strength and agreement:
- **0.95 – 0.98**: Known IOC match or verified legitimate trusted domain
- **0.85 – 0.92**: High signal agreement across multiple detection vectors
- **0.70 – 0.85**: Moderate signal agreement
- **0.50 – 0.65**: Ambiguous or isolated contextual signal

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.11+
- Virtual environment tool (`venv`)

### 2. Setup Virtual Environment & Dependencies

```bash
# Create virtual environment
python3.11 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### 4. Running the FastAPI Application

```bash
# Start Uvicorn development server
uvicorn zenshield.main:app --host 0.0.0.0 --port 8000 --reload
```

The interactive OpenAPI Swagger documentation is available at:
`http://localhost:8000/docs`

---

## 📡 API Reference

### Health Check
```http
GET /health
```
**Response:**
```json
{
  "status": "healthy",
  "service": "ZenShield",
  "version": "0.1.0"
}
```

### Verify URL
```http
POST /api/v1/verify/url
Content-Type: application/json

{
  "url": "https://paypa1.com/login"
}
```

**Response Contract:**
```json
{
  "risk_score": 30,
  "risk_level": "CAUTION",
  "classification": "Potential Phishing",
  "confidence": 0.88,
  "known_ioc": false,
  "signals": [
    {
      "name": "Typosquatting",
      "severity": "high",
      "evidence": "Domain is highly similar to trusted domain paypal.com"
    },
    {
      "name": "Credential-related path",
      "severity": "medium",
      "evidence": "URL path contains credential/authentication intent keyword: 'login'"
    }
  ],
  "recommendation": "Avoid entering credentials, OTPs, or payment information."
}
```

---

## 🧪 Testing

The test suite validates every component across 57 unit and integration tests.

```bash
# Run all tests
pytest -v
```

### Key Test Scenarios Covered
1. **Legitimate URLs**: `https://google.com`, `https://github.com` (score 0, Safe, confidence >= 0.90)
2. **Typosquatting**: `https://paypa1.com`, `https://micros0ft-login.com`, `https://g00gle-security.com`
3. **Punycode / Homoglyphs**: `http://xn--pple-43d.com`, Cyrillic `аpple.com`
4. **Raw IP URLs**: `http://192.168.1.1/login`
5. **Contextual Paths**: `https://example.com/login` (ensures lone `/login` is never marked CRITICAL)
6. **High Entropy Hostnames**: DGA randomized domains
7. **Known IOC**: Seeded SQLite threat indicator matching
8. **Unknown IOC**: Verifies heuristics still run when domain is not in IOC database
9. **Malformed Inputs**: URLs without scheme, empty inputs, unparseable inputs (no crashes)
10. **Static Safety**: Mocks `socket.connect` and `urllib.request.urlopen` to prove target URLs are never contacted
11. **API Contract Verification**: Confirms strict JSON schema adherence

---

## 🤝 Teammate Integration Guide

- **Person 2 (SMS / AI Detection)**:
  Extract URLs from incoming SMS messages and submit to `POST /api/v1/verify/url`. Use the `risk_score`, `signals`, and `recommendation` in the aggregate SMS risk assessment.
- **Person 3 (QR / OCR Processing)**:
  Decoded QR code target URLs can be directly piped into `POST /api/v1/verify/url`.
- **Person 4 (Threat Intelligence & Community Reports)**:
  New community-reported malicious domains/URLs can be registered directly into the SQLite IOC repository via `SQLiteReputationProvider.add_ioc(indicator, indicator_type, source, severity, description)`.
- **Frontend**:
  Integrate with `POST /api/v1/verify/url`. Display `risk_score` (0–100 progress gauge), `risk_level` badge, `recommendation` alert, and render the `signals` list with evidence explanations.
