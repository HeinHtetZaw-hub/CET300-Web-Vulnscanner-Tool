# VulnScanner

**Automated Web Application Vulnerability Scanner with CVSS Risk Scoring and OWASP Top 10 Mapping**

VulnScanner is a black-box web application security scanner built as a CET300 Final Year Computing Project. It crawls a target website, runs seven detection modules covering the OWASP Top 10, scores every finding with CVSS v3.1, and produces professional PDF and JSON reports — all through a clean React dashboard.

> **Authorised use only.** See the [Legal Disclaimer](#legal-disclaimer) before scanning any target.

---

## Features

- **BFS web crawler** — discovers all pages, forms, and URL parameters within the target domain
- **Seven detection modules:**
  - SQL Injection (error-based, boolean-blind, time-blind)
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS (Selenium headless Chrome)
  - Broken Access Control — IDOR and SSRF
  - Security Misconfiguration — missing headers and exposed sensitive files
  - Sensitive Data Exposure — API keys, credentials, PEM keys, JWT tokens
- **CVSS v3.1 scoring** for every finding, mapped to OWASP Top 10
- **Live progress dashboard** — real-time module status, findings count by severity, activity log
- **Sortable / filterable results table** — filter by severity and OWASP category
- **Finding detail view** — HTTP request/response evidence with payload highlighting
- **PDF report** — stakeholder-ready: management summary, risk matrix, severity bar chart, compliance mapping (GDPR / PCI DSS / ISO 27001), per-finding business impact and OWASP Cheat Sheet links
- **JSON export** — structured export for integration with other tools
- **Rate limiting** — 10 req/s token bucket; never floods the target
- **Private IP blocking** — refuses to scan RFC 1918 / loopback addresses by default
- **Mandatory authorisation checkbox** — must confirm permission before any scan starts

---

## Screenshots

> _Screenshots will be added after integration testing against DVWA (Phase 12)._
>
> Pages: Scan Form · Live Progress · Results Table · Finding Detail · PDF Report

---

## Quick Start (Docker)

### Prerequisites

| Tool | Minimum version |
|---|---|
| Docker | 24.x |
| Docker Compose | v2.20 (included with Docker Desktop) |
| Git | any |

### 1 — Clone and configure

```bash
git clone <repo-url> vulnscanner
cd vulnscanner
cp .env.example .env          # optional — defaults work out of the box
```

### 2 — Start the stack

```bash
docker compose up --build -d
```

This builds the Python 3.11 backend (with Chromium for DOM XSS) and the nginx-served React frontend, then starts both services. The frontend waits for the backend health check before accepting traffic.

| Service | URL |
|---|---|
| App (React) | http://localhost |
| API (FastAPI) | http://localhost/api/v1 |
| Swagger UI | http://localhost/api/v1/docs |
| ReDoc | http://localhost/api/v1/redoc |

### 3 — Run a scan

1. Open **http://localhost**
2. Enter a target URL (e.g. `http://testphp.vulnweb.com`)
3. Read and tick the authorisation checkbox
4. Click **Start Scan** — you are redirected to the live progress page
5. When the scan completes (~2–10 minutes depending on site size), you land on the results page

### 4 — Stop

```bash
docker compose down           # stops containers, keeps the database volume
docker compose down -v        # stops containers AND deletes the database
```

---

## Manual Install (without Docker)

### Backend

**Requirements:** Python 3.11, Google Chrome + ChromeDriver (for DOM XSS module)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Create the data directory for SQLite
mkdir -p data

# Start the development server (auto-reloads on code changes)
uvicorn app.main:app --reload --port 8000
```

The API is now available at **http://localhost:8000**. Swagger UI is at **http://localhost:8000/docs**.

### Frontend

**Requirements:** Node.js 20+

```bash
cd frontend
npm install
npm run dev
```

The React app is now at **http://localhost:5173** with hot reload.  
It proxies `/api/` requests to the backend via Vite's dev proxy (configured in `vite.config.js`).

> **Note:** DOM XSS detection requires Chrome and ChromeDriver. If they are not installed the module skips gracefully and all other modules continue normally.

---

## Usage Guide

### Starting a scan

POST to the API directly (or use the web UI):

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "authorisation_confirmed": true,
    "config": {
      "modules": ["sqli", "xss_reflected", "xss_stored", "xss_dom",
                  "bac", "misconfig", "exposure"],
      "crawl_depth": 3
    }
  }'
```

Response includes a `scan_id`. Use it to poll progress:

```bash
# Poll status
curl http://localhost:8000/api/v1/scans/<scan_id>

# Poll with findings breakdown (used by the progress page)
curl http://localhost:8000/api/v1/scans/<scan_id>/progress

# Cancel a running scan
curl -X POST http://localhost:8000/api/v1/scans/<scan_id>/cancel
```

### Reading results

```bash
# All findings, sorted by CVSS score descending
curl "http://localhost:8000/api/v1/scans/<scan_id>/findings?sort_by=cvss_score&order=desc"

# Filter by severity
curl "http://localhost:8000/api/v1/scans/<scan_id>/findings?severity=critical"

# Filter by OWASP category
curl "http://localhost:8000/api/v1/scans/<scan_id>/findings?owasp_category=A03"

# Full detail for one finding (includes HTTP evidence)
curl "http://localhost:8000/api/v1/scans/<scan_id>/findings/<finding_id>"
```

### Exporting reports

```bash
# Download PDF report
curl -o report.pdf \
  "http://localhost:8000/api/v1/scans/<scan_id>/report/pdf"

# Download JSON export
curl -o report.json \
  "http://localhost:8000/api/v1/scans/<scan_id>/report/json"
```

> Reports are only available after a scan reaches `completed` status.

### Listing past scans

```bash
# All scans (newest first)
curl "http://localhost:8000/api/v1/scans"

# Filter by status
curl "http://localhost:8000/api/v1/scans?status=completed"
```

---

## API Reference

The full interactive API reference is auto-generated by FastAPI:

| Format | URL |
|---|---|
| Swagger UI | http://localhost/api/v1/docs |
| ReDoc | http://localhost/api/v1/redoc |
| OpenAPI JSON | http://localhost/api/v1/openapi.json |

### Endpoint summary

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check — `{ status, version }` |
| `POST` | `/api/v1/scans` | Start a new scan |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/scans/{id}` | Get scan details |
| `GET` | `/api/v1/scans/{id}/progress` | Progress + per-severity counts (SSE-friendly) |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel a running scan |
| `DELETE` | `/api/v1/scans/{id}` | Delete scan and all its findings |
| `GET` | `/api/v1/scans/{id}/findings` | List findings with filters and sort |
| `GET` | `/api/v1/scans/{id}/findings/{fid}` | Full finding detail with HTTP evidence |
| `GET` | `/api/v1/scans/{id}/report/pdf` | Download PDF report |
| `GET` | `/api/v1/scans/{id}/report/json` | Download JSON export |

---

## Testing

### Unit tests

```bash
cd backend

# All tests (excludes integration tests that need DVWA)
pytest -v -m "not integration"

# With coverage report
pytest -v -m "not integration" --cov=app --cov-report=term-missing

# Run a specific test file
pytest tests/test_sqli.py -v
```

### Integration tests against DVWA

Start DVWA first:

```bash
# Option A — via the main compose profile
docker compose --profile test up -d dvwa

# Option B — standalone
cd test-targets && docker compose up -d dvwa
```

Visit **http://localhost:8080**, log in with `admin` / `password`, navigate to **DVWA Security**, set the level to **Low**, and click **Submit**.

Then run the integration tests:

```bash
cd backend
pytest -v -m integration
```

### Linting

```bash
# Backend (Python)
cd backend
ruff check .
ruff format --check .

# Frontend (JavaScript)
cd frontend
npm run lint
```

### Test targets

| Target | URL | Notes |
|---|---|---|
| DVWA | http://localhost:8080 | Set security level to **Low** before scanning |
| OWASP Juice Shop | http://localhost:3000 | Start with `--profile test` |

---

## Environment Variables

Copy `.env.example` to `.env` in the project root and adjust as needed. All variables have safe defaults so `.env` is optional for a quick start.

| Variable | Default | Description |
|---|---|---|
| `FRONTEND_PORT` | `80` | Host port for the React app |
| `BACKEND_PORT` | `8000` | Host port for the FastAPI backend |
| `DVWA_PORT` | `8080` | Host port for DVWA (profile: test) |
| `JUICESHOP_PORT` | `3000` | Host port for Juice Shop (profile: test) |
| `RATE_LIMIT_RPS` | `10` | HTTP requests per second to target |
| `HTTP_TIMEOUT` | `10.0` | Per-request timeout in seconds |

The `DATABASE_URL` is managed by Docker Compose (SQLite stored in the `db_data` named volume). To switch to PostgreSQL, update the compose file and set your connection string.

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Backend framework | FastAPI | 0.115 |
| ASGI server | Uvicorn | 0.32 |
| Async HTTP client | httpx | 0.28 |
| HTML parser | BeautifulSoup4 | 4.12 |
| Headless browser | Selenium + Chromium | 4.27 |
| CVSS scoring | cvss | 2.6 |
| ORM | SQLAlchemy (async) | 2.0 |
| Database (dev) | SQLite via aiosqlite | — |
| PDF generation | fpdf2 | 2.8 |
| Frontend framework | React | 18 |
| Build tool | Vite | 6 |
| Styling | Tailwind CSS | 3 |
| HTTP (frontend) | Axios | 1.7 |
| Web server | nginx | alpine |
| Containers | Docker + Docker Compose | 24 / v2 |
| Testing | pytest + pytest-asyncio | 8.3 |
| Linting | ruff (Python), ESLint (JS) | 0.8 / 9 |

---

## Project Structure

```
vulnscanner/
├── docker-compose.yml           # Full stack: backend + frontend + test targets
├── .env.example                 # Environment variable template
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py              # FastAPI app, CORS, lifespan
│   │   ├── config.py            # Settings via pydantic-settings
│   │   ├── database.py          # SQLAlchemy engine + session
│   │   ├── models/              # Scan + Finding ORM models
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   ├── api/                 # Route handlers (scans, findings, reports)
│   │   ├── scanner/
│   │   │   ├── engine.py        # Scan orchestrator
│   │   │   ├── crawler.py       # BFS web crawler
│   │   │   └── modules/         # Detection modules (one file each)
│   │   ├── scoring/             # CVSS v3.1 engine
│   │   ├── mapping/             # OWASP Top 10 mapper + remediation text
│   │   └── reporting/           # PDF (fpdf2) + JSON report generators
│   └── tests/                   # pytest unit + integration tests
├── frontend/
│   ├── Dockerfile
│   ├── nginx.conf               # Reverse proxy + gzip + asset caching
│   └── src/
│       ├── pages/               # ScanPage, ProgressPage, ResultsPage, FindingDetail
│       └── components/          # FindingsTable, EvidencePanel, SeverityBadge, …
└── test-targets/
    └── docker-compose.yml       # DVWA + Juice Shop standalone
```

---

## Legal Disclaimer

**This tool is for authorised security testing only.**

Scanning web applications without the explicit written permission of the system owner may constitute a criminal offence under:

- **Computer Misuse Act 1990** (United Kingdom)
- **Myanmar Electronic Transactions Law 2004**
- Equivalent legislation in your jurisdiction

By using VulnScanner you confirm that:

1. You own the target system **or** have explicit written authorisation from the owner to test it.
2. You will use the findings solely to improve the security of the tested system.
3. You will not use this tool to attack, disrupt, or compromise any system without authorisation.

The authors accept no liability for misuse of this software.

---

## Academic Context

This project was developed as the CET300 Final Year Computing Project at the **University of Sunderland** (delivered via **BUC, Myanmar**).

| | |
|---|---|
| **Author** | Hein Htet Zaw |
| **Programme** | BSc (Hons) Computing |
| **Module** | CET300 Final Year Computing Project |
| **Supervisor** | U Tay Zar Thein |
| **Timeline** | February – August 2026 |

---

## License

MIT License — see [LICENSE](LICENSE) for the full text.

Copyright (c) 2026 Hein Htet Zaw
