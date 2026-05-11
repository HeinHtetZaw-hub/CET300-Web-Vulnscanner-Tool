# VulnScanner — Master Reference

## Quick Summary
Automated Web Application Vulnerability Scanner with CVSS Risk Scoring and OWASP Top 10 Mapping.
Python FastAPI backend + React frontend. Solo CET300 final year project by Hein Htet Zaw.
BSc (Hons) Computing — University of Sunderland via BUC, Myanmar. Supervisor: U Tay Zar Thein.

## Key Rules
- Follow the architecture and phases in PROJECT_PLAN.md
- One phase at a time, test after each phase
- Backend: Python 3.11, FastAPI, SQLAlchemy (async), httpx, BeautifulSoup4, Selenium, cvss library
- Frontend: React 18, Tailwind CSS, Axios, Vite
- Database: SQLite (dev), PostgreSQL (prod)
- All API endpoints under /api/v1
- Rate limit: 10 requests/second to targets
- Every finding needs: CVSS v3.1 score, OWASP Top 10:2025 category, full HTTP evidence
- Mandatory authorisation checkbox before any scan
- Block private IP scans by default
- Test against DVWA and OWASP Juice Shop only

## Tech Stack
| Layer | Tech |
|-------|------|
| Backend | Python 3.11 + FastAPI |
| HTTP client | httpx (async, rate-limited) |
| HTML parsing | BeautifulSoup4 |
| Headless browser | Selenium + ChromeDriver |
| CVSS scoring | cvss Python library |
| Database | SQLAlchemy 2.0 + SQLite/PostgreSQL |
| PDF reports | WeasyPrint |
| Frontend | React 18 + Vite + Tailwind CSS |
| Containers | Docker + Docker Compose |
| Testing | pytest + pytest-asyncio |

## Core Architecture
- backend/app/main.py → FastAPI entry point
- backend/app/models/ → SQLAlchemy ORM (scans + findings tables)
- backend/app/api/ → Route handlers (scans, findings, reports)
- backend/app/scanner/engine.py → Orchestrator: crawl → detect → score → save
- backend/app/scanner/crawler.py → BFS web crawler
- backend/app/scanner/modules/ → One file per detection module (sqli, xss, bac, misconfig, exposure)
- backend/app/scoring/ → CVSS v3.1 engine + pre-defined vectors
- backend/app/mapping/ → OWASP Top 10:2025 category mapper
- backend/app/reporting/ → PDF generator (WeasyPrint) + JSON exporter
- frontend/src/pages/ → ScanPage, ProgressPage, ResultsPage, FindingDetail
- frontend/src/components/ → ScanForm, FindingsTable, SeverityBadge, EvidencePanel

## How To Use This Project With Claude CLI
For full details on any phase, say: "Read PROJECT_PLAN.md and do Phase X"
PROJECT_PLAN.md contains: full directory tree, database schema, all API endpoints, CVSS vectors, OWASP mappings, detection logic, and step-by-step Claude CLI prompts for all 12 phases.

## Progress Log
- [ ] Phase 1.1 — Backend skeleton (FastAPI + health endpoint)
- [ ] Phase 1.2 — Database models (scans + findings)
- [ ] Phase 1.3 — API routes + Pydantic schemas
- [ ] Phase 1.4 — Frontend skeleton (React + Vite + Tailwind)
- [ ] Phase 1.5 — Verify everything runs
- [ ] Phase 2.1 — URL validator + private IP blocking
- [ ] Phase 2.2 — Rate-limited HTTP client
- [ ] Phase 3 — Web crawler (BFS, form extraction, parameter discovery)
- [ ] Phase 4.1 — Base detection module abstract class
- [ ] Phase 4.2 — Scan engine orchestrator
- [ ] Phase 5 — SQL injection module (error, boolean, time-based)
- [ ] Phase 6.1 — Reflected XSS module
- [ ] Phase 6.2 — Stored XSS module
- [ ] Phase 6.3 — DOM-based XSS module (Selenium)
- [ ] Phase 7 — CVSS scoring engine + OWASP mapper
- [ ] Phase 8.1 — IDOR detection
- [ ] Phase 8.2 — SSRF detection
- [ ] Phase 8.3 — Security misconfiguration (headers + exposed files)
- [ ] Phase 8.4 — Sensitive data exposure
- [ ] Phase 9.1 — Progress page (live scan monitoring)
- [ ] Phase 9.2 — Results page (sortable/filterable findings table)
- [ ] Phase 9.3 — Finding detail page (evidence viewer)
- [ ] Phase 10 — PDF report generator (WeasyPrint)
- [ ] Phase 11.1 — JSON export
- [ ] Phase 11.2 — Docker Compose finalisation
- [ ] Phase 11.3 — README
- [ ] Phase 12 — Integration testing against DVWA
