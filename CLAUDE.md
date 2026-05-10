# CLAUDE.md — Automated Web Application Vulnerability Scanner

## Project Identity

- **Name:** VulnScanner
- **Full Title:** Automated Web Application Vulnerability Scanner with CVSS Risk Scoring and OWASP Top 10 Mapping
- **Author:** Hein Htet Zaw
- **Programme:** BSc (Hons) Computing — University of Sunderland (via BUC, Myanmar)
- **Module:** CET300 Final Year Computing Project
- **Supervisor:** U Tay Zar Thein
- **Timeline:** 09 Feb 2026 – 07 Aug 2026 (26 weeks, 400 hours)

---

## What This File Is

This is the master reference for building VulnScanner using Claude CLI (Claude Code). Every section below tells Claude exactly what to build, in what order, with what tech, and how each piece connects. When working with Claude CLI, reference this file so Claude understands the full architecture and can write code that fits together.

---

## Tech Stack (Locked In)

| Layer | Technology | Version |
|-------|-----------|---------|
| Backend framework | Python + FastAPI | Python 3.11, FastAPI 0.100+ |
| Async HTTP | httpx | latest |
| HTML parsing | BeautifulSoup4 | latest |
| Headless browser | Selenium + ChromeDriver | latest |
| CVSS scoring | cvss (Python library) | latest |
| Database (dev) | SQLite via SQLAlchemy | SQLAlchemy 2.0+ |
| Database (prod) | PostgreSQL | 15+ |
| Migrations | Alembic | latest |
| PDF reports | WeasyPrint | latest |
| Frontend framework | React.js | 18+ |
| Frontend styling | Tailwind CSS | 3+ |
| HTTP client (frontend) | Axios | latest |
| Containerisation | Docker + Docker Compose | latest |
| Version control | Git | latest |
| Testing | pytest + pytest-asyncio + pytest-cov | latest |
| Linting | ruff (Python), ESLint + Prettier (JS) | latest |

---

## Directory Structure

```
vulnscanner/
├── CLAUDE.md                          # THIS FILE — master project reference
├── README.md                          # User-facing install and usage guide
├── LICENSE                            # MIT License
├── docker-compose.yml                 # Full stack orchestration
├── .gitignore
├── .env.example                       # Environment variable template
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/
│   │   └── versions/                  # Migration scripts
│   │
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI app entry point, CORS, lifespan
│   │   ├── config.py                  # Settings via pydantic-settings
│   │   ├── database.py                # SQLAlchemy engine, session, Base
│   │   │
│   │   ├── models/                    # SQLAlchemy ORM models
│   │   │   ├── __init__.py
│   │   │   ├── scan.py                # Scan, ScanStatus enum
│   │   │   └── finding.py             # Finding, Severity enum
│   │   │
│   │   ├── schemas/                   # Pydantic request/response schemas
│   │   │   ├── __init__.py
│   │   │   ├── scan.py                # ScanCreate, ScanResponse, ScanProgress
│   │   │   └── finding.py             # FindingResponse, FindingDetail
│   │   │
│   │   ├── api/                       # FastAPI route handlers
│   │   │   ├── __init__.py
│   │   │   ├── router.py              # Main API router aggregator
│   │   │   ├── scans.py               # POST /scans, GET /scans/{id}, DELETE
│   │   │   ├── findings.py            # GET /scans/{id}/findings, filters
│   │   │   └── reports.py             # GET /scans/{id}/report/pdf, /json
│   │   │
│   │   ├── scanner/                   # Core scanning engine
│   │   │   ├── __init__.py
│   │   │   ├── engine.py              # ScanEngine orchestrator class
│   │   │   ├── crawler.py             # Web crawler / spider
│   │   │   ├── modules/               # Detection modules (one file each)
│   │   │   │   ├── __init__.py
│   │   │   │   ├── base.py            # BaseModule abstract class
│   │   │   │   ├── sqli.py            # SQL injection detection
│   │   │   │   ├── xss_reflected.py   # Reflected XSS detection
│   │   │   │   ├── xss_stored.py      # Stored XSS detection
│   │   │   │   ├── xss_dom.py         # DOM-based XSS (Selenium)
│   │   │   │   ├── bac.py             # Broken access control (IDOR + SSRF)
│   │   │   │   ├── misconfig.py       # Security misconfiguration
│   │   │   │   └── exposure.py        # Sensitive data exposure
│   │   │   └── payloads/              # Payload files (txt/json)
│   │   │       ├── sqli.txt
│   │   │       ├── xss.txt
│   │   │       ├── common_paths.txt
│   │   │       └── security_headers.json
│   │   │
│   │   ├── scoring/                   # Risk scoring
│   │   │   ├── __init__.py
│   │   │   ├── cvss_engine.py         # CVSS v3.1 score calculator
│   │   │   └── vectors.py             # Pre-defined CVSS vectors per vuln type
│   │   │
│   │   ├── mapping/                   # OWASP classification
│   │   │   ├── __init__.py
│   │   │   └── owasp_mapper.py        # Maps finding type → A01-A10
│   │   │
│   │   ├── reporting/                 # Report generation
│   │   │   ├── __init__.py
│   │   │   ├── pdf_generator.py       # WeasyPrint PDF report
│   │   │   ├── json_exporter.py       # JSON export
│   │   │   └── templates/             # HTML/CSS templates for PDF
│   │   │       ├── report.html
│   │   │       └── report.css
│   │   │
│   │   └── utils/                     # Shared utilities
│   │       ├── __init__.py
│   │       ├── http_client.py         # Rate-limited httpx client wrapper
│   │       ├── url_validator.py       # URL validation + private IP blocking
│   │       └── logger.py              # Structured logging setup
│   │
│   └── tests/
│       ├── conftest.py                # Fixtures: test DB, test client, mock targets
│       ├── test_crawler.py
│       ├── test_sqli.py
│       ├── test_xss.py
│       ├── test_cvss.py
│       ├── test_owasp_mapper.py
│       ├── test_api_scans.py
│       └── test_api_findings.py
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── tailwind.config.js
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx                   # React entry point
│       ├── App.jsx                    # Router setup
│       ├── api/
│       │   └── client.js              # Axios instance, base URL config
│       ├── pages/
│       │   ├── ScanPage.jsx           # URL input + auth checkbox + start
│       │   ├── ProgressPage.jsx       # Live scan progress
│       │   ├── ResultsPage.jsx        # Findings dashboard
│       │   └── FindingDetail.jsx      # Single finding evidence view
│       ├── components/
│       │   ├── ScanForm.jsx           # URL input + config form
│       │   ├── AuthCheckbox.jsx       # Legal disclaimer checkbox
│       │   ├── ProgressBar.jsx        # Scan progress indicator
│       │   ├── FindingsTable.jsx      # Sortable/filterable table
│       │   ├── SeverityBadge.jsx      # Colour-coded severity label
│       │   ├── OWASPFilter.jsx        # A01-A10 dropdown filter
│       │   ├── EvidencePanel.jsx      # Expandable request/response viewer
│       │   └── Navbar.jsx             # Top navigation bar
│       └── utils/
│           └── constants.js           # Severity colours, OWASP categories
│
└── test-targets/
    └── docker-compose.yml             # DVWA + Juice Shop for testing
```

---

## Database Schema

Two core tables. Keep it simple — SQLite for dev, PostgreSQL for prod.

### Table: scans

| Column | Type | Notes |
|--------|------|-------|
| id | UUID (primary key) | Auto-generated |
| target_url | String(2048) | Validated URL |
| status | Enum | queued, crawling, scanning, completed, failed, cancelled |
| started_at | DateTime | Nullable, set when scan begins |
| completed_at | DateTime | Nullable, set when scan ends |
| total_urls_found | Integer | Updated by crawler |
| total_findings | Integer | Updated as findings are saved |
| config | JSON | Which modules enabled, crawl depth, etc. |
| created_at | DateTime | Auto timestamp |

### Table: findings

| Column | Type | Notes |
|--------|------|-------|
| id | UUID (primary key) | Auto-generated |
| scan_id | UUID (FK → scans.id) | Parent scan |
| vuln_type | String | sqli_error, sqli_blind_boolean, sqli_blind_time, xss_reflected, xss_stored, xss_dom, idor, ssrf, misconfig_header, misconfig_file, data_exposure |
| severity | Enum | critical, high, medium, low, info |
| cvss_score | Float | 0.0 to 10.0 |
| cvss_vector | String | Full CVSS v3.1 vector string |
| owasp_category | String | A01 through A10 |
| owasp_name | String | e.g. "Broken Access Control" |
| affected_url | String(2048) | The URL where vuln was found |
| affected_parameter | String | The input parameter name |
| payload_used | Text | The exact payload that triggered it |
| evidence_request | Text | Full HTTP request sent |
| evidence_response | Text | Relevant portion of HTTP response |
| remediation | Text | Fix guidance |
| confidence | Enum | confirmed, tentative |
| created_at | DateTime | Auto timestamp |

---

## API Endpoints

All endpoints are prefixed with `/api/v1`.

### Scans

| Method | Path | Description | Request Body |
|--------|------|-------------|-------------|
| POST | /scans | Start a new scan | `{ target_url, authorisation_confirmed: true, config: { modules: [...], crawl_depth: 3 } }` |
| GET | /scans | List all scans | Query params: status, limit, offset |
| GET | /scans/{id} | Get scan details + progress | — |
| GET | /scans/{id}/progress | SSE stream of live progress | Server-Sent Events |
| POST | /scans/{id}/cancel | Cancel a running scan | — |
| DELETE | /scans/{id} | Delete scan and its findings | — |

### Findings

| Method | Path | Description | Query Params |
|--------|------|-------------|-------------|
| GET | /scans/{id}/findings | Get findings for a scan | severity, owasp_category, sort_by, order, limit, offset |
| GET | /scans/{id}/findings/{fid} | Get single finding with full evidence | — |

### Reports

| Method | Path | Description |
|--------|------|-------------|
| GET | /scans/{id}/report/pdf | Download PDF report |
| GET | /scans/{id}/report/json | Download JSON export |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Returns `{ status: "ok", version: "1.0.0" }` |

---

## CVSS v3.1 Vector Mappings

Each vulnerability type gets a pre-defined CVSS v3.1 base vector. The `cvss` Python library calculates the numeric score from the vector string.

```python
CVSS_VECTORS = {
    # SQL Injection — network, low complexity, no privs, no interaction, changed scope, high CIA
    "sqli_error":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",     # 10.0 Critical
    "sqli_blind_boolean":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",     # 10.0 Critical
    "sqli_blind_time":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",     # 10.0 Critical

    # XSS Reflected — needs user interaction
    "xss_reflected":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1 Medium
    # XSS Stored — no user interaction needed for trigger
    "xss_stored":          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",     # 6.5 Medium
    # XSS DOM-based
    "xss_dom":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1 Medium

    # IDOR — access control bypass
    "idor":                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",     # 8.1 High
    # SSRF
    "ssrf":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",     # 8.6 High

    # Security Misconfiguration — missing headers
    "misconfig_header":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",     # 5.3 Medium
    # Exposed sensitive files
    "misconfig_file":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # 7.5 High

    # Sensitive data exposure
    "data_exposure":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # 7.5 High
}
```

---

## OWASP Top 10:2025 Mapping

```python
OWASP_MAPPING = {
    "sqli_error":         {"category": "A03", "name": "Injection"},
    "sqli_blind_boolean": {"category": "A03", "name": "Injection"},
    "sqli_blind_time":    {"category": "A03", "name": "Injection"},
    "xss_reflected":      {"category": "A03", "name": "Injection"},
    "xss_stored":         {"category": "A03", "name": "Injection"},
    "xss_dom":            {"category": "A03", "name": "Injection"},
    "idor":               {"category": "A01", "name": "Broken Access Control"},
    "ssrf":               {"category": "A01", "name": "Broken Access Control"},
    "misconfig_header":   {"category": "A05", "name": "Security Misconfiguration"},
    "misconfig_file":     {"category": "A05", "name": "Security Misconfiguration"},
    "data_exposure":      {"category": "A02", "name": "Cryptographic Failures"},
}
```

---

## Step-by-Step Build Plan for Claude CLI

Work through these phases in order. Each phase produces working, testable code. Do not skip ahead.

---

### PHASE 1: Project Skeleton + Environment (Sprint 1, Week 1)

**Goal:** Empty project that runs. FastAPI serves one endpoint. React shows one page.

**Claude CLI prompts to use:**

```
Phase 1.1 — Backend skeleton:
"Create the backend project structure for a FastAPI application. Set up:
- app/main.py with FastAPI app, CORS middleware (allow all origins for dev), and a GET /health endpoint
- app/config.py using pydantic-settings to load DATABASE_URL, RATE_LIMIT_RPS, and APP_VERSION from environment
- app/database.py with SQLAlchemy async engine, sessionmaker, and Base declarative class for SQLite
- requirements.txt with: fastapi, uvicorn[standard], sqlalchemy[asyncio], aiosqlite, pydantic-settings, httpx, beautifulsoup4, python-multipart, cvss, weasyprint, alembic, pytest, pytest-asyncio, pytest-cov, ruff
- A Dockerfile that installs requirements and runs uvicorn on port 8000
Follow the directory structure from CLAUDE.md exactly."
```

```
Phase 1.2 — Database models:
"Create SQLAlchemy ORM models following the schema in CLAUDE.md:
- models/scan.py: Scan model with UUID pk, target_url, status enum (queued/crawling/scanning/completed/failed/cancelled), timestamps, config JSON, counters
- models/finding.py: Finding model with UUID pk, scan_id FK, vuln_type, severity enum, cvss_score, cvss_vector, owasp fields, evidence fields, remediation, confidence
- Set up Alembic for migrations and create the initial migration"
```

```
Phase 1.3 — API routes (empty handlers):
"Create the API route structure:
- api/router.py that aggregates all sub-routers under /api/v1
- api/scans.py with POST /scans (accept ScanCreate schema, create DB record, return 201), GET /scans, GET /scans/{id}, POST /scans/{id}/cancel, DELETE /scans/{id}
- api/findings.py with GET /scans/{id}/findings (support severity and owasp_category query filters, sort_by, order params), GET /scans/{id}/findings/{fid}
- api/reports.py with GET /scans/{id}/report/pdf and /json (return 501 Not Implemented for now)
- schemas/scan.py and schemas/finding.py with Pydantic models for all request/response shapes
Wire the router into main.py"
```

```
Phase 1.4 — Frontend skeleton:
"Set up a React + Vite + Tailwind CSS frontend:
- Create the project with Vite (React template)
- Install and configure Tailwind CSS
- Install axios and react-router-dom
- Create api/client.js with Axios instance pointing to http://localhost:8000/api/v1
- Create a minimal App.jsx with routes: / → ScanPage, /scan/:id/progress → ProgressPage, /scan/:id/results → ResultsPage
- Create ScanPage.jsx with: URL text input, authorisation checkbox with legal text referencing Computer Misuse Act 1990 and Myanmar Electronic Transactions Law 2004, a Start Scan button that is disabled until checkbox is checked, on submit POST to /scans and redirect to progress page
- Create placeholder ProgressPage and ResultsPage components
- Dockerfile for frontend using nginx to serve the build
- docker-compose.yml in project root that runs backend + frontend + creates a shared network"
```

```
Phase 1.5 — Verify everything works:
"Start docker-compose, verify:
- GET /health returns 200
- POST /scans with a valid URL creates a scan record in SQLite
- Frontend loads, shows the scan form, checkbox enables the button
- Submitting the form hits the API and returns a scan ID
Write a basic pytest for the /health and POST /scans endpoints"
```

---

### PHASE 2: URL Validation + Rate-Limited HTTP Client (Sprint 1, Week 2)

**Goal:** Safe HTTP client that respects rate limits and blocks private IPs.

```
Phase 2.1 — URL validator:
"Create utils/url_validator.py with:
- validate_url(url: str) → returns cleaned URL or raises ValueError
- Checks: must be http or https, must have valid hostname, must resolve to a valid IP
- is_private_ip(url: str) → bool that checks if the URL resolves to RFC 1918 (10.x, 172.16-31.x, 192.168.x), loopback (127.x), or link-local ranges
- If private IP detected and override not set, raise PrivateIPError with message explaining why
Write unit tests covering: valid URLs, invalid schemes, private IPs, localhost, public IPs"
```

```
Phase 2.2 — Rate-limited HTTP client:
"Create utils/http_client.py with:
- A class RateLimitedClient wrapping httpx.AsyncClient
- Constructor takes: rate_limit (requests per second, default 10), timeout (default 10s), user_agent string
- Implements an asyncio semaphore or token bucket to enforce rate limiting
- Methods: get(url, **kwargs), post(url, data, **kwargs), head(url, **kwargs)
- All methods handle httpx exceptions gracefully, returning None or raising custom ScannerHTTPError
- Configurable via app/config.py settings
Write unit tests using httpx mock transport"
```

---

### PHASE 3: Web Crawler (Sprint 2, Week 1)

**Goal:** Crawler that discovers all pages, forms, and parameters on a target.

```
Phase 3 — Web crawler:
"Create scanner/crawler.py with a Crawler class:

Constructor takes: base_url, http_client (RateLimitedClient), max_depth (default 3), max_pages (default 500)

Method crawl() → CrawlResult containing:
  - discovered_urls: set of all unique URLs found within scope
  - forms: list of FormData objects, each with: action_url, method (GET/POST), inputs (list of {name, type, value})
  - parameters: list of ParameterData objects, each with: url, param_name, param_location (query/body/path)

Crawling logic:
1. Start from base_url, fetch the page
2. Parse HTML with BeautifulSoup
3. Extract all <a href> links, resolve relative URLs to absolute, keep only same-domain links
4. Extract all <form> elements: action URL, method, all <input>/<select>/<textarea> fields with name attributes
5. Extract URL query parameters from every discovered URL
6. Respect max_depth (how many clicks from the start page) and max_pages
7. Skip non-HTML content types, skip URLs with file extensions like .jpg .png .css .js .pdf .zip
8. Use a BFS queue with a visited set to avoid loops
9. Report progress via a callback: on_progress(pages_crawled, total_queued)

The crawler must NOT:
- Follow external domain links
- Download binary files
- Get stuck in infinite loops (URL normalisation + visited set)
- Exceed rate limits (handled by http_client)

Write tests against a simple mock HTTP server (use pytest fixtures with a local test server or mock responses)"
```

---

### PHASE 4: Scanner Engine + Base Module (Sprint 2, Week 2)

**Goal:** Engine that orchestrates crawling then runs detection modules.

```
Phase 4.1 — Base detection module:
"Create scanner/modules/base.py with an abstract class BaseModule:
- name: str property (e.g. 'SQL Injection')
- vuln_types: list[str] property (e.g. ['sqli_error', 'sqli_blind_boolean', 'sqli_blind_time'])
- Abstract async method run(target_urls, forms, parameters, http_client) → list[RawFinding]
- RawFinding is a dataclass with: vuln_type, affected_url, affected_parameter, payload_used, evidence_request, evidence_response, confidence

Every detection module inherits from BaseModule and implements run()."
```

```
Phase 4.2 — Scan engine orchestrator:
"Create scanner/engine.py with ScanEngine class:
- Constructor takes: scan_id (UUID), target_url, config (which modules to run), db_session
- Holds a list of detection module instances
- Main method: async run_scan()
  1. Update scan status to 'crawling'
  2. Run the Crawler, save crawl results
  3. Update scan status to 'scanning', update total_urls_found
  4. For each enabled module, call module.run() with crawl results
  5. For each RawFinding returned:
     a. Look up CVSS vector from scoring/vectors.py
     b. Calculate CVSS score using cvss library
     c. Look up OWASP category from mapping/owasp_mapper.py
     d. Look up remediation text
     e. Create Finding database record
  6. Update scan status to 'completed', set completed_at, update total_findings
  7. Handle exceptions: set status to 'failed' on unrecoverable errors
- Support cancellation: check a cancellation flag between modules
- Send progress updates via a callback or event system

Wire this into the POST /scans endpoint: when a scan is created, launch engine.run_scan() as a background task using FastAPI's BackgroundTasks or asyncio.create_task()"
```

---

### PHASE 5: SQL Injection Module (Sprint 2)

**Goal:** Detect error-based, boolean-based, and time-based blind SQLi.

```
Phase 5 — SQL injection detection:
"Create scanner/modules/sqli.py implementing BaseModule:

The module receives all discovered forms and URL parameters from the crawler.

Three detection techniques:

1. ERROR-BASED SQLi:
   - Inject payloads like: ' , '' , ' OR '1'='1 , ' OR 1=1-- , 1' ORDER BY 1-- , ' UNION SELECT NULL--
   - Check the response body for database error strings:
     MySQL: 'You have an error in your SQL syntax', 'mysql_fetch', 'Warning: mysql'
     PostgreSQL: 'pg_query', 'PG::SyntaxError', 'unterminated quoted string'
     SQLite: 'SQLite3::SQLException', 'SQLITE_ERROR', 'unrecognized token'
     MSSQL: 'Microsoft SQL Native Client error', 'Unclosed quotation mark'
     Generic: 'SQL syntax', 'sql error', 'database error'
   - If error string found → confirmed finding

2. BOOLEAN-BASED BLIND SQLi:
   - Send two requests to each parameter:
     a. True condition: ' OR '1'='1 (or AND 1=1)
     b. False condition: ' OR '1'='2 (or AND 1=2)
   - Compare response lengths and content
   - If true-condition response significantly differs from false-condition → tentative finding
   - Threshold: response length difference > 50 chars or different HTTP status codes

3. TIME-BASED BLIND SQLi:
   - Inject time-delay payloads:
     MySQL: ' OR SLEEP(5)--
     PostgreSQL: '; SELECT pg_sleep(5)--
     SQLite: ' OR 1=1; WAITFOR DELAY '0:0:5'--
     Generic: ' OR BENCHMARK(10000000,SHA1('test'))--
   - Measure response time
   - If response takes > 4.5 seconds (with a 5-second payload) → tentative finding
   - Run twice to confirm (avoid false positives from slow networks)

For each parameter in each form/URL:
  - Try error-based first (fastest, most reliable)
  - If nothing found, try boolean-based
  - If nothing found, try time-based
  - Stop testing a parameter once a finding is confirmed

Payload file: scanner/payloads/sqli.txt — one payload per line, lines starting with # are comments

Save the full HTTP request and response as evidence.

Write tests using mock responses that simulate vulnerable and non-vulnerable endpoints."
```

---

### PHASE 6: XSS Detection Modules (Sprint 3)

```
Phase 6.1 — Reflected XSS:
"Create scanner/modules/xss_reflected.py implementing BaseModule:

For each parameter in URLs and forms:
1. Generate a unique canary string: 'xSs' + random 8-char alphanumeric (e.g. 'xSsA1b2C3d4')
2. Inject the canary into the parameter value
3. Send the request
4. Check if the canary appears in the response body UNENCODED
5. If found unencoded, try actual XSS payloads:
   - <script>alert('XSS')</script>
   - <img src=x onerror=alert('XSS')>
   - <svg onload=alert('XSS')>
   - \" onfocus=alert('XSS') autofocus=\"
   - javascript:alert('XSS')
6. Check if the payload appears in the response without sanitisation
7. Context-aware checking: is the reflection inside HTML body, inside an attribute, inside a script tag?

A finding is 'confirmed' if a full payload reflects unencoded. 'Tentative' if canary reflects but payloads are partially filtered."
```

```
Phase 6.2 — Stored XSS:
"Create scanner/modules/xss_stored.py implementing BaseModule:

This is trickier because the payload persists:
1. For each form that uses POST method (likely data-saving forms):
   a. Generate a unique marker payload: <script>/*xSsStored_UNIQUEID*/</script>
   b. Submit the form with the payload in each text input field
   c. After submission, re-crawl the same pages the crawler found
   d. Check if the unique marker appears on ANY page in the response body
   e. If found → confirmed stored XSS finding
2. The unique marker ensures we know which form submission caused the stored XSS
3. Be careful: only test forms on the target, never submit to external URLs
4. Record which form was submitted and which page shows the stored payload"
```

```
Phase 6.3 — DOM-based XSS:
"Create scanner/modules/xss_dom.py implementing BaseModule:

Uses Selenium with headless Chrome:
1. For each discovered URL:
   a. Open the page in headless Chrome via Selenium
   b. Check for dangerous JavaScript sinks in the page source:
      - document.write(), innerHTML, outerHTML, eval()
      - Using sources like: location.hash, location.search, document.referrer, window.name
   c. Inject payloads via URL fragment (#) and query parameters:
      - #<img src=x onerror=alert(1)>
      - ?q=<script>alert(1)</script>
   d. Execute JavaScript to check if DOM was modified in an exploitable way
   e. Use Selenium's execute_script to check for JavaScript errors or alert dialogs
2. This module is optional (Should-have) — if Selenium setup fails, skip gracefully with a warning
3. Wrap all Selenium calls in try/except to handle WebDriver crashes"
```

---

### PHASE 7: CVSS Scoring Engine + OWASP Mapper (Sprint 3)

```
Phase 7 — Scoring and mapping:
"Create scoring/cvss_engine.py:
- Function calculate_cvss(vuln_type: str) → tuple[float, str, str]
  Returns: (score, severity_label, vector_string)
- Uses the cvss Python library: from cvss import CVSS3
- Looks up the vector from scoring/vectors.py (the CVSS_VECTORS dict from CLAUDE.md)
- Calculates: c = CVSS3(vector_string), score = c.base_score, severity = c.severities()[0]
- Returns the numeric score (float), severity label (Critical/High/Medium/Low), and vector string

Create mapping/owasp_mapper.py:
- Function map_to_owasp(vuln_type: str) → tuple[str, str]
  Returns: (category_code, category_name) e.g. ('A03', 'Injection')
- Uses the OWASP_MAPPING dict from CLAUDE.md
- Also stores a REMEDIATION dict with fix guidance for each vuln_type:
  sqli_*: 'Use parameterised queries (prepared statements). Never concatenate user input into SQL strings. Use an ORM. Apply input validation as a secondary defense.'
  xss_*: 'Encode all user-supplied output using context-appropriate encoding (HTML entity, JavaScript, URL encoding). Implement Content-Security-Policy header. Use a templating engine with auto-escaping.'
  idor: 'Implement proper authorisation checks on every request. Use indirect object references (map user-facing IDs to internal IDs via a server-side mapping). Validate that the authenticated user has permission to access the requested resource.'
  ssrf: 'Validate and sanitise all user-supplied URLs. Implement an allowlist of permitted domains and IP ranges. Block requests to private/internal IP ranges. Use a dedicated HTTP client that cannot reach internal services.'
  misconfig_header: 'Add the missing security headers to your web server configuration. Recommended headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: strict-origin-when-cross-origin.'
  misconfig_file: 'Remove or restrict access to sensitive files. Add server rules to deny access to .env, .git, backup files, and configuration files. Use .htaccess or nginx location blocks to return 403/404 for these paths.'
  data_exposure: 'Remove exposed credentials and API keys immediately. Rotate all compromised secrets. Implement proper access controls on sensitive file paths. Use environment variables for secrets, never commit them to source code.'

Write unit tests: given a vuln_type, verify the score matches the expected value, severity label is correct, and OWASP category is correct."
```

---

### PHASE 8: Broken Access Control + Misconfig + Data Exposure (Sprint 4)

```
Phase 8.1 — IDOR detection:
"Create the IDOR portion of scanner/modules/bac.py:
- Look at discovered URLs for patterns with numeric IDs: /user/1, /profile/123, /api/users/42
- For each such URL, try adjacent IDs: if the original was /user/1, try /user/2, /user/3
- Compare responses: if /user/2 returns 200 with different content than /user/1, this may indicate IDOR
- Mark as 'tentative' — IDOR confirmation usually requires authentication context
- Record the original URL, the manipulated URL, and both response snippets as evidence"
```

```
Phase 8.2 — SSRF detection:
"Add SSRF detection to scanner/modules/bac.py:
- Look for URL parameters that accept URLs: any parameter named url, redirect, next, return, callback, link, src, dest, uri, path, continue, return_to, go, checkout_url, image_url
- Inject internal URLs: http://127.0.0.1, http://localhost, http://169.254.169.254/latest/meta-data/ (AWS metadata), http://[::1]
- Check the response for signs the server fetched the internal URL (response contains metadata content, internal page content, or different error messages)
- Also try: http://127.0.0.1:22 (SSH banner), http://127.0.0.1:3306 (MySQL)
- Mark as 'tentative' unless clear evidence of internal content in the response"
```

```
Phase 8.3 — Security misconfiguration:
"Create scanner/modules/misconfig.py:
1. HEADER CHECKS — for each discovered URL (sample the first 10):
   Check for missing security headers:
   - Strict-Transport-Security (HSTS)
   - Content-Security-Policy (CSP)
   - X-Content-Type-Options (should be 'nosniff')
   - X-Frame-Options (should be DENY or SAMEORIGIN)
   - Referrer-Policy
   - Permissions-Policy
   Report each missing header as a separate finding

2. EXPOSED FILE CHECKS — probe common sensitive paths from the base URL:
   /.env, /.env.local, /.env.production
   /.git/HEAD, /.git/config
   /backup.sql, /database.sql, /dump.sql
   /config.php, /config.php.bak, /wp-config.php
   /phpinfo.php
   /server-status, /server-info
   /.htaccess, /.htpasswd
   /robots.txt (check for Disallow entries pointing to sensitive paths)
   /sitemap.xml
   /crossdomain.xml
   /.well-known/security.txt
   - Only report files that return HTTP 200 with non-empty content
   - For .git/HEAD, check if content matches: ref: refs/heads/
   - For .env files, check if content contains KEY=VALUE patterns"
```

```
Phase 8.4 — Sensitive data exposure:
"Create scanner/modules/exposure.py:
- Scan response bodies from ALL crawled pages for exposed sensitive data patterns:
  - API keys: patterns like AKIA[0-9A-Z]{16} (AWS), sk_live_[a-zA-Z0-9]{24} (Stripe), key-[a-zA-Z0-9]{32}
  - Private keys: -----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----
  - Passwords in HTML: <input type='password'... value='...'> with pre-filled values
  - Connection strings: mongodb://, postgresql://, mysql://, redis://
  - JWT tokens: eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+
  - Internal IP addresses in responses: 10\.\d+\.\d+\.\d+, 172\.(1[6-9]|2\d|3[01])\.\d+\.\d+, 192\.168\.\d+\.\d+
- Use regex matching, report the match location but REDACT the actual secret in stored evidence (show first 4 chars + ****)"
```

---

### PHASE 9: Frontend Dashboard (Sprint 5)

```
Phase 9.1 — Progress page:
"Build ProgressPage.jsx:
- Polls GET /scans/{id} every 2 seconds (or uses SSE if implemented)
- Shows: scan status, target URL, progress bar (pages crawled / total queued)
- Shows live count: findings found so far, grouped by severity
- Shows a scrolling log of which module is currently running
- Cancel Scan button that calls POST /scans/{id}/cancel
- When status becomes 'completed', auto-redirect to results page
- When status becomes 'failed', show error message"
```

```
Phase 9.2 — Results page with findings table:
"Build ResultsPage.jsx:
- Fetches GET /scans/{id}/findings
- Displays a table with columns: Severity (colour badge), Vuln Type, Affected URL, Parameter, CVSS Score, OWASP Category
- Default sort: CVSS score descending (most critical first)
- Clickable column headers to change sort
- Filter dropdowns: Severity (Critical/High/Medium/Low), OWASP Category (A01-A10)
- Filters are combinable
- Shows total finding count and filtered count
- Click a row → navigates to FindingDetail page
- Export buttons: Download PDF, Download JSON

Severity colour scheme:
  Critical: red (#DC2626) — bg-red-100 text
  High: orange (#EA580C) — bg-orange-100 text
  Medium: yellow (#CA8A04) — bg-yellow-100 text
  Low: blue (#2563EB) — bg-blue-100 text
  Info: gray (#6B7280) — bg-gray-100 text"
```

```
Phase 9.3 — Finding detail page:
"Build FindingDetail.jsx:
- Shows full detail for one finding
- Sections:
  1. Header: severity badge, CVSS score, vuln type name, OWASP category tag
  2. Affected URL and parameter
  3. Evidence panel: collapsible sections for HTTP Request and HTTP Response, rendered in monospace with syntax highlighting
  4. Payload used: shown in a code block with the payload highlighted
  5. Remediation: rendered as formatted text with links to OWASP documentation
- Back button to return to results"
```

---

### PHASE 10: PDF Report Generator (Sprint 6)

```
Phase 10 — PDF report:
"Create reporting/pdf_generator.py:
- Uses WeasyPrint to generate a professional pentest-style PDF report
- HTML template at reporting/templates/report.html with CSS at report.css
- Report sections:
  1. Cover page: Tool name, target URL, scan date, total findings count by severity
  2. Executive Summary: one paragraph overview — total vulns found, breakdown by severity, highest risk areas
  3. Findings Summary Table: severity, type, URL, CVSS score, OWASP category
  4. Detailed Findings: for each finding (grouped by OWASP category, sorted by CVSS within each group):
     - Severity badge, CVSS score and vector, affected URL, parameter
     - Description of the vulnerability type
     - Evidence: HTTP request and response (truncated to 500 chars each in PDF)
     - Remediation steps
  5. Methodology: brief description of scanning approach, list of modules used
  6. Disclaimer: 'This scan was performed with authorisation. This tool is for authorised security assessment only.'
  7. Footer on every page: page number, scan date, 'CONFIDENTIAL'

CSS styling: clean professional look, use severity colours, monospace for code/evidence blocks
WeasyPrint converts the HTML+CSS to PDF"
```

---

### PHASE 11: JSON Export + Docker + Final Polish (Sprint 6)

```
Phase 11.1 — JSON export:
"Create reporting/json_exporter.py:
- Function export_json(scan, findings) → dict
- Output format:
  {
    'scan': { id, target_url, started_at, completed_at, status, total_findings },
    'summary': { critical: N, high: N, medium: N, low: N },
    'findings': [ { all finding fields } ]
  }
- Wire into GET /scans/{id}/report/json endpoint, return as a downloadable .json file"
```

```
Phase 11.2 — Docker Compose finalisation:
"Update docker-compose.yml with production-ready config:
- backend service: Dockerfile, environment variables, depends_on database
- frontend service: Dockerfile with nginx, proxy /api to backend
- database service: PostgreSQL (optional, SQLite still works for demo)
- test-targets service profile: DVWA container for testing, only starts with --profile test
- Volumes for persistent database storage
- Single command to start: docker-compose up --build
Add docker-compose instructions to README.md"
```

```
Phase 11.3 — README:
"Write a comprehensive README.md:
- Project title and one-paragraph description
- Features list
- Screenshots placeholder
- Quick Start: prerequisites, git clone, docker-compose up, open browser
- Manual install instructions (without Docker)
- Usage guide: how to run a scan, read results, export reports
- API documentation reference (link to /docs Swagger UI)
- Testing: how to run pytest, how to spin up DVWA
- Legal disclaimer about authorised use only
- Tech stack
- License (MIT)"
```

---

### PHASE 12: Testing Against DVWA (Sprint 5-6)

```
Phase 12 — Integration testing:
"Set up DVWA in Docker and test the scanner end-to-end:
1. docker run -d -p 8080:80 vulnerables/web-dvwa
2. Set DVWA security level to 'low' (easiest to detect)
3. Run a full scan against http://localhost:8080
4. Verify detections:
   - SQLi should detect the SQL injection on the login page and SQLi exercise page
   - Reflected XSS should detect XSS on the XSS (Reflected) exercise page
   - Stored XSS should detect XSS on the XSS (Stored) exercise page
   - Misconfig should detect missing security headers
5. Check that CVSS scores match expected values
6. Check that OWASP categories are correct
7. Generate PDF report and verify it looks professional
8. Export JSON and verify the schema

Write the results as integration test functions in tests/test_integration_dvwa.py
Mark these tests with @pytest.mark.integration so they only run when DVWA is available"
```

---

## Key Design Decisions

1. **Async everywhere.** FastAPI is async, httpx is async, the scan engine runs as an async background task. This lets the API stay responsive while a scan runs.

2. **One module = one file.** Each detection module is self-contained. Easy to add new modules later — just create a new file inheriting from BaseModule, register it in the engine.

3. **Separation of detection from scoring.** Modules produce RawFindings (what was found). The engine adds CVSS scores and OWASP mapping. This means scoring logic lives in one place.

4. **Background task, not Celery.** For a single-user tool, asyncio.create_task is enough. No need for Celery/Redis complexity. If this needed to handle concurrent scans from multiple users, switch to Celery + Redis.

5. **SQLite for dev, PostgreSQL for prod.** SQLAlchemy makes switching transparent. The docker-compose uses SQLite by default; a .env override switches to PostgreSQL.

6. **Rate limiting is mandatory.** The HTTP client enforces 10 req/s by default. This is both ethical (don't DOS the target) and a project requirement (NFR-06).

7. **Evidence capture.** Every finding stores the full HTTP request and response. This is what separates a real tool from a toy — pentesters need evidence to verify findings and write reports.

---

## Commands Cheat Sheet

```bash
# Start everything
docker-compose up --build

# Backend only (dev mode with auto-reload)
cd backend && uvicorn app.main:app --reload --port 8000

# Frontend only (dev mode with hot reload)
cd frontend && npm run dev

# Run tests
cd backend && pytest -v --cov=app --cov-report=term-missing

# Run only unit tests (no DVWA needed)
cd backend && pytest -v -m "not integration"

# Lint
cd backend && ruff check . && ruff format .
cd frontend && npx eslint src/ && npx prettier --check src/

# Start DVWA for testing
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa

# Run integration tests against DVWA
cd backend && pytest -v -m integration

# Generate a scan via API
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:8080", "authorisation_confirmed": true}'

# Check scan status
curl http://localhost:8000/api/v1/scans/{scan_id}

# Get findings
curl http://localhost:8000/api/v1/scans/{scan_id}/findings?sort_by=cvss_score&order=desc

# Download PDF report
curl -o report.pdf http://localhost:8000/api/v1/scans/{scan_id}/report/pdf
```

---

## Working with Claude CLI

When using Claude Code to build this project, reference this file:

```bash
# Start Claude Code in the project root
claude

# Tell Claude to read this file first
> Read CLAUDE.md and then do Phase 1.1

# Build phase by phase
> Do Phase 2.1 — URL validator with tests

# Ask Claude to run and verify
> Run the tests for the crawler module

# Ask Claude to check against requirements
> Check if the current code covers all Must-have functional requirements from CLAUDE.md
```

Tips for working with Claude CLI on this project:

- **One phase at a time.** Don't ask for the whole project at once. Build and test each phase before moving on.
- **Always run tests after each phase.** Ask Claude to write and run tests.
- **Reference this file.** Say "following the structure in CLAUDE.md" to keep Claude aligned.
- **Review the code.** Read what Claude writes. You need to understand it for your dissertation.
- **Commit after each phase.** `git add . && git commit -m "Phase 3: Web crawler"` — your ePortfolio needs evidence of progress.
- **Take screenshots.** Your dissertation needs screenshots of the tool working. Capture them as you go.

---

## Sprint-to-Phase Mapping

| Sprint | Dates | Phases | What Gets Built |
|--------|-------|--------|----------------|
| 1 | 27 Apr – 10 May | 1, 2 | Project skeleton, API, frontend shell, URL validation, HTTP client |
| 2 | 11 May – 24 May | 3, 4, 5 | Crawler, scan engine, SQL injection module |
| 3 | 25 May – 07 Jun | 6, 7 | All XSS modules, CVSS engine, OWASP mapper |
| 4 | 08 Jun – 21 Jun | 8 | IDOR, SSRF, misconfiguration, data exposure modules |
| 5 | 22 Jun – 05 Jul | 9 | Full frontend dashboard, progress page, results, evidence views |
| 6 | 06 Jul – 19 Jul | 10, 11, 12 | PDF report, JSON export, Docker, DVWA testing, polish |

---

## Definition of Done (Per Phase)

A phase is done when:
- [ ] Code is written and committed to Git
- [ ] Unit tests pass with no failures
- [ ] No ruff lint errors in Python code
- [ ] The feature works when tested manually
- [ ] Code follows the directory structure in this file
- [ ] Any new API endpoints are accessible via Swagger at /docs
