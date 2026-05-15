# VulnScanner PDF Report Enhancement — Master Prompt

You are a senior cybersecurity software engineer and PDF reporting architect.

Enhance my VulnScanner PDF reporting system to produce output comparable to modern commercial DAST scanners such as Burp Suite Enterprise, Nessus, Acunetix, and Invicti.

---

## Current Stack

- **Backend:** FastAPI + Python 3.11
- **PDF generation:** fpdf2 (not WeasyPrint — the project switched to fpdf2 in Phase 10)
- **Database:** SQLAlchemy 2.0 (async) + SQLite
- **Frontend:** React 18 + Vite + Tailwind CSS
- **Scanner outputs findings with:**
  - CVSS v3.1 base scoring via the `cvss` Python library
  - OWASP Top 10:2025 category mapping
  - Compliance mapping (GDPR, PCI DSS v4.0, ISO 27001)
  - Full HTTP request/response evidence
  - Confidence level (confirmed / tentative)

---

## Current Report Issues Identified (from real DVWA scan output)

The following problems were found by reviewing the actual PDF report generated from a scan of DVWA's `/vulnerabilities/xss_r/` page. All enhancements below must address these issues directly.

### Issue 1 — Finding Deduplication Failure
The report contains 6 separate full-page "Missing Security Header" findings for the same URL (`http://localhost:8081/vulnerabilities/xss_r`), each with identical descriptions, identical business impact text, and identical remediation steps. This inflates the report from ~6 pages to ~12 pages and looks unprofessional. Commercial scanners (Burp, ZAP, Acunetix) group these into a single finding with sub-items.

### Issue 2 — Risk Matrix Renders as Plain Text
The risk matrix on page 3 (Likelihood vs Impact grid) appears as plain-text numbers in a grid rather than a properly rendered colour-coded matrix. It is not visually useful.

### Issue 3 — Severity Distribution Has No Chart
The "Severity Distribution" section is text-only (e.g. `HIGH 1 14%`). There is no bar chart, pie chart, or donut chart. Stakeholders expect visual representations.

### Issue 4 — Cover Page is Plain Text Only
The cover page has no logo, no visual branding, no colour blocks — just plain text. It does not look enterprise-grade.

### Issue 5 — Evidence Sections Repeat Identical Content
The HTTP response evidence in all 6 missing-header findings contains the same DVWA login page HTML repeated verbatim. The report should truncate or deduplicate repeated response bodies.

### Issue 6 — No Remediation Code Examples
Remediation steps are bullet-point text only. No actual configuration or code examples are provided (e.g., nginx config to add headers, Apache .htaccess rules).

### Issue 7 — No CWE Mapping
Findings reference OWASP categories but lack CWE IDs. CWE mapping is expected in professional security reports and academic cybersecurity projects.

### Issue 8 — Possible False Positive Not Handled
The phpinfo.php finding received HTTP 200 but the response body contains DVWA's login page HTML — not actual phpinfo output. The detection logic should verify response body content, not just HTTP status codes.

---

## IMPORTANT CONSTRAINTS

- Do NOT rewrite the whole project.
- Only improve the **reporting system** (`backend/app/reporting/`) while keeping the existing architecture.
- The project uses **fpdf2**, not WeasyPrint. All PDF generation must use fpdf2.
- Keep implementation modular and suitable for a university final-year cybersecurity project (CET300, University of Sunderland).
- All code must be production-quality — no placeholder pseudo-code.

---

## Enhancement Requirements

### 1. Executive Dashboard Page

Add a visually modern dashboard as the first content page (after cover page) including:

- **Severity donut/pie chart** — rendered as an embedded image via matplotlib/Pillow, showing Critical/High/Medium/Low/Info with counts and percentages
- **OWASP category bar chart** — horizontal bar chart showing finding count per OWASP category (A01–A10)
- **CVSS score distribution histogram** — bucket scores into 0–3.9, 4.0–6.9, 7.0–8.9, 9.0–10.0
- **Overall security posture grade (A–F)** — large, colour-coded letter grade
- **Key metrics in a grid layout:**
  - Total findings by severity
  - Total risk score (sum of all CVSS scores)
  - Scan duration
  - URLs crawled
  - Requests sent
  - Forms tested
  - Parameters tested

Charts must be generated as PNG images in memory (using matplotlib + io.BytesIO) and embedded into the PDF via fpdf2's `image()` method. Use a professional colour palette.

### 2. Technology Fingerprinting Table

Add automatic technology detection and reporting for:

- **Web server** (e.g., Apache, nginx, IIS)
- **Programming language** (e.g., PHP, Python, Java, ASP.NET)
- **Framework** (e.g., Laravel, Django, Express.js, Spring)
- **CMS** (e.g., WordPress, Drupal, Joomla)
- **JavaScript libraries** (e.g., jQuery, React, Angular, Vue.js)

Display in a clean table:

| Technology | Version | Confidence |
|---|---|---|
| Apache | 2.4.25 | High (Server header) |
| PHP | 7.4 | High (X-Powered-By header) |
| WordPress | 6.4 | Medium (meta generator tag) |
| React | 18.2.0 | Medium (script src pattern) |
| jQuery | 3.7.1 | High (script src filename) |

Detection sources — extract from data already captured during scanning:
- `Server` response header → web server + version
- `X-Powered-By` header → programming language / framework
- `X-AspNet-Version`, `X-Generator` headers → framework / CMS
- HTML `<meta name="generator">` tags → CMS + version
- `<script src="...">` attributes → JavaScript libraries + versions (match filenames like `jquery-3.7.1.min.js`, `react.production.min.js`)
- HTML comments (e.g., `<!-- WordPress 6.4 -->`)
- Cookie names (e.g., `PHPSESSID` → PHP, `JSESSIONID` → Java, `ASP.NET_SessionId` → ASP.NET)
- Response body patterns (e.g., `wp-content/` → WordPress, `/static/admin/` → Django)

Create `backend/app/scanner/fingerprint.py` with a `TechnologyFingerprinter` class that:
1. Accepts the HTTP response headers and body from crawled pages
2. Runs all detection rules
3. Returns a list of `DetectedTechnology(name, category, version, confidence)` objects
4. Deduplicates and picks the highest-confidence detection per technology

Display as a clean table early in the report (after executive dashboard, before findings).

### 3. CWE Mapping

For every finding, add:
- **CWE ID** (e.g., CWE-79)
- **CWE Name** (e.g., Improper Neutralisation of Input During Web Page Generation)
- **MITRE reference URL**

Pre-defined CWE mapping dictionary:
```python
CWE_MAPPING = {
    "sqli_error":        {"id": "CWE-89",  "name": "SQL Injection"},
    "sqli_blind_boolean": {"id": "CWE-89",  "name": "SQL Injection"},
    "sqli_blind_time":   {"id": "CWE-89",  "name": "SQL Injection"},
    "xss_reflected":     {"id": "CWE-79",  "name": "Cross-site Scripting (Reflected)"},
    "xss_stored":        {"id": "CWE-79",  "name": "Cross-site Scripting (Stored)"},
    "xss_dom":           {"id": "CWE-79",  "name": "Cross-site Scripting (DOM-Based)"},
    "idor":              {"id": "CWE-639", "name": "Authorisation Bypass Through User-Controlled Key"},
    "ssrf":              {"id": "CWE-918", "name": "Server-Side Request Forgery"},
    "misconfig_header":  {"id": "CWE-16",  "name": "Configuration"},
    "misconfig_file":    {"id": "CWE-538", "name": "Insertion of Sensitive Information into Externally-Accessible File"},
    "data_exposure":     {"id": "CWE-200", "name": "Exposure of Sensitive Information"},
}
```

Display CWE in: finding summary table, detailed findings, and compliance section.

### 4. Finding Deduplication and Grouping

**This is a critical fix.** Replace the current logic that creates 6 separate "Missing Security Header" findings with grouped output:

**Before (current — broken):**
6 separate full-page findings, each with identical description, impact, and remediation.

**After (required):**
```
┌──────────────────────────────────────────────────────┐
│ MEDIUM  CVSS 5.3  Missing Security Headers           │
│ URL: http://localhost:8081/vulnerabilities/xss_r      │
│ CWE-16 Configuration | A05 Security Misconfiguration  │
│                                                       │
│ Missing Headers:                                      │
│  ✗ Strict-Transport-Security                         │
│  ✗ Content-Security-Policy                           │
│  ✗ X-Content-Type-Options                            │
│  ✗ X-Frame-Options                                   │
│  ✗ Referrer-Policy                                   │
│  ✗ Permissions-Policy                                │
│                                                       │
│ [Combined evidence, one remediation block, one        │
│  business impact — not repeated 6 times]              │
└──────────────────────────────────────────────────────┘
```

Grouping logic: findings with the same `vuln_type` AND same `affected_url` should be merged into a single report entry with sub-items listing each individual finding (e.g., each missing header name).

### 5. Enhanced Evidence Formatting

Improve HTTP request/response evidence rendering in fpdf2:

- **Monospace font** (Courier) for all evidence blocks
- **Light grey background** behind code blocks
- **Highlighted payloads** — the injected payload should be visually distinct (bold or colour)
- **Truncate long responses** — max 60 lines or 3000 characters, with a "[... truncated — N chars remaining]" note
- **Deduplicate identical response bodies** — if the same HTML appears in multiple findings, show it once and reference it: "Response identical to Finding #1"
- **Better spacing** — add padding inside evidence blocks, clear separation between request and response

### 6. Screenshot Capture (Optional Enhancement)

If Selenium is available, automatically capture browser screenshots for:
- Reflected XSS (showing the alert/payload rendered)
- Exposed sensitive files (showing the exposed content)
- Admin panels
- Vulnerable forms with pre-filled payloads

Embed screenshots as images in the detailed findings section. If Selenium is unavailable, skip gracefully — this feature is optional.

### 7. Remediation Code Examples

For each vulnerability type, provide concrete fix examples in code blocks:

**Missing Security Headers:**
```nginx
# nginx
add_header Content-Security-Policy "default-src 'self';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=()" always;
```

```apache
# Apache .htaccess
Header always set Content-Security-Policy "default-src 'self';"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
```

**SQL Injection:**
```python
# Parameterised query (Python + SQLAlchemy)
result = db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_input})
```

**XSS:**
```python
# Output encoding (Jinja2 auto-escaping)
{{ user_input | e }}
```

Render all code examples in monospace with syntax-appropriate formatting.

### 8. Risk Intelligence / Attack Chain Analysis

Add a "Risk Intelligence" section that generates contextual risk explanations based on finding combinations:

Examples:
- "Missing Content-Security-Policy combined with Reflected XSS findings significantly increases exploit reliability — CSP would block inline script execution."
- "Exposed phpinfo.php leaks PHP version, loaded modules, and server paths, enabling targeted exploitation of version-specific CVEs."
- "Absence of all six recommended security headers indicates no security hardening has been performed on the web server."

Generate these programmatically based on which findings are present in the scan.

### 9. Security Score System

Implement a weighted security scoring system:

```python
def calculate_grade(findings):
    score = 100  # Start at 100 (perfect)
    for finding in findings:
        if finding.severity == "critical":
            score -= 25
        elif finding.severity == "high":
            score -= 15
        elif finding.severity == "medium":
            score -= 5
        elif finding.severity == "low":
            score -= 2
    
    score = max(0, score)
    
    if score >= 90: return "A"
    elif score >= 75: return "B"
    elif score >= 60: return "C"
    elif score >= 40: return "D"
    else: return "F"
```

Display as a large colour-coded grade on the executive dashboard:
- A = Green (#22C55E)
- B = Blue (#3B82F6)
- C = Yellow (#EAB308)
- D = Orange (#F97316)
- F = Red (#EF4444)

### 10. Enhanced Scan Metadata

Expand the methodology section with a detailed metadata table:

| Field | Value |
|---|---|
| Scan Start | 14 May 2026 14:49:44 UTC |
| Scan End | 14 May 2026 14:50:00 UTC |
| Duration | 16 seconds |
| Scanner Version | VulnScanner 1.0.0 |
| Crawl Depth | 3 |
| Max Pages | 500 |
| Rate Limit | 10 req/s |
| URLs Crawled | 1 |
| Total Requests | 47 |
| Failed Requests | 3 |
| Average Response Time | 120ms |
| Forms Discovered | 1 |
| Parameters Tested | 2 |
| Auth Mode | Unauthenticated |
| Modules Enabled | sqli, xss_reflected, xss_stored, xss_dom, bac, misconfig, exposure |

This data should be tracked during the scan and stored in the `scans` database table (add columns if needed).

### 11. Visual Design Overhaul

Redesign the entire PDF styling using fpdf2:

**Cover Page:**
- Large colour block header (dark navy #1E293B or similar)
- "VulnScanner" title in white, bold, 28pt
- Subtitle: "Automated Web Application Security Assessment Report"
- Target URL, scan date, scan ID in a clean info box
- Severity summary badges (coloured circles/boxes with counts)
- "CONFIDENTIAL" watermark or footer

**Typography:**
- Headings: Helvetica Bold, navy colour
- Body: Helvetica Regular, 10pt, dark grey (#334155)
- Evidence: Courier, 8pt, on light grey background
- Consistent line spacing (1.3x)

**Colour Palette:**
- Primary: Navy #1E293B
- Critical: #DC2626
- High: #EA580C
- Medium: #EAB308
- Low: #3B82F6
- Info: #6B7280
- Background accents: #F8FAFC, #F1F5F9
- Borders: #E2E8F0

**Severity Badges:**
Render as small coloured rounded rectangles with white text (e.g., [CRITICAL] in red, [HIGH] in orange).

**Section Separators:**
Use thin coloured lines (navy) between major sections, not just whitespace.

**Page Headers/Footers:**
- Header: "VulnScanner | Security Assessment Report" (left-aligned, small, grey)
- Footer: "CONFIDENTIAL | {date} | Page {n}" (centred)

### 12. Scan Limitations Disclosure

Add a professional "Limitations" section before the disclaimer:

> **Scope Limitations**
>
> This automated assessment has inherent limitations that should be considered when interpreting results:
>
> - **No business logic testing** — Automated scanners cannot detect flaws in application-specific workflows (e.g., privilege escalation through business processes, payment bypass).
> - **No authentication testing** — This scan was performed unauthenticated. Vulnerabilities behind login pages were not tested.
> - **No race condition testing** — Time-of-check to time-of-use (TOCTOU) and concurrency vulnerabilities are not covered.
> - **Limited JavaScript analysis** — DOM-based vulnerabilities in heavily obfuscated or framework-rendered JavaScript may be missed.
> - **No API endpoint fuzzing** — REST/GraphQL API endpoints beyond those discovered through crawling were not tested.
> - **False positives possible** — Tentative findings should be manually verified before remediation.
>
> **Recommendation:** Complement automated scanning with annual manual penetration testing by a qualified security professional.

### 13. Future Roadmap Section

Add a brief "Future Capabilities" section at the end:

- Authenticated scanning (cookie/token-based session management)
- CI/CD pipeline integration (GitHub Actions, GitLab CI)
- WebSocket real-time progress updates
- AI-assisted remediation prioritisation
- SARIF export for IDE integration
- Jira/Azure DevOps ticket creation
- Historical trend comparison (scan-over-scan)
- Custom scan policies and module selection

---

## Output Requirements

Provide:

1. **Updated `backend/app/reporting/pdf_generator.py`** — complete rewrite of the PDF generation logic using fpdf2
2. **Chart generation helper** — `backend/app/reporting/charts.py` — matplotlib chart functions that return PNG bytes
3. **CWE mapping module** — `backend/app/mapping/cwe_mapper.py` — CWE lookup dictionary
4. **Finding grouping utility** — `backend/app/reporting/grouping.py` — deduplication/grouping logic
5. **Risk scoring module** — `backend/app/scoring/risk_score.py` — grade calculation
6. **Technology fingerprinting** — `backend/app/scanner/fingerprint.py` — header/HTML-based tech detection
7. **Risk intelligence** — `backend/app/reporting/risk_intelligence.py` — attack chain analysis text generation
8. **Updated database models** if new scan metadata fields are needed
9. **All code must be modular, clean, and production-ready**
10. **No placeholder pseudo-code — every function must be fully implemented**

---

## File Structure for New/Modified Files

```
backend/app/
├── reporting/
│   ├── pdf_generator.py       # REWRITE — full enhanced PDF report
│   ├── charts.py              # NEW — matplotlib chart generation
│   ├── grouping.py            # NEW — finding deduplication logic
│   ├── risk_intelligence.py   # NEW — attack chain analysis
│   └── json_exporter.py       # KEEP — no changes needed
├── scoring/
│   ├── cvss_engine.py         # KEEP
│   ├── vectors.py             # KEEP
│   └── risk_score.py          # NEW — overall grade calculation
├── mapping/
│   ├── owasp_mapper.py        # KEEP (add CWE cross-reference)
│   └── cwe_mapper.py          # NEW — CWE ID/name lookup
└── scanner/
    └── fingerprint.py         # NEW — technology detection
```
