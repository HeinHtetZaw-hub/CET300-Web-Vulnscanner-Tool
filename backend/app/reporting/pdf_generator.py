"""PDF report generator using fpdf2 (pure-Python, cross-platform).

Report structure:
  Cover page
  Management Executive Summary  (plain-language, one page)
  Technical Executive Summary   (bar chart, risk matrix, severity table)
  Remediation Prioritisation    (bucketed by timeline)
  Compliance Mapping            (GDPR / PCI DSS / ISO 27001)
  Findings Summary Table
  Detailed Findings             (per OWASP group, with business impact + OWASP links)
  Methodology
  Next Steps
  Disclaimer
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from app.models.finding import Finding
from app.models.scan import Scan

# ── Colour palette ────────────────────────────────────────────────────────────
_NAVY  = (15,  40,  80)
_GRAY  = (100, 100, 100)
_LGRAY = (220, 220, 220)
_WHITE = (255, 255, 255)
_BGRAY = (248, 249, 250)
_GREEN = (22, 163, 74)

_SEV_CFG: dict[str, tuple[tuple, tuple, str]] = {
    'critical': ((220, 38,  38),  _WHITE,       'CRITICAL'),
    'high':     ((234, 88,  12),  _WHITE,       'HIGH'),
    'medium':   ((202, 138, 4),   (40, 40, 40), 'MEDIUM'),
    'low':      ((37,  99,  235), _WHITE,       'LOW'),
    'info':     ((107, 114, 128), _WHITE,       'INFO'),
}

# Risk matrix cell colours (5x5, row=impact 1-5 bottom-to-top, col=likelihood 1-5)
_MATRIX_COLORS = [
    # likelihood: 1      2         3         4         5
    [(0,200,80), (0,200,80), (255,220,0), (255,150,0), (255,60,0)],   # impact 5
    [(0,200,80), (0,200,80), (255,220,0), (255,150,0), (255,60,0)],   # impact 4
    [(0,200,80), (255,220,0),(255,220,0), (255,150,0), (255,60,0)],   # impact 3
    [(0,200,80), (255,220,0),(255,220,0), (255,220,0), (255,150,0)],  # impact 2
    [(0,200,80), (0,200,80), (255,220,0), (255,220,0), (255,150,0)],  # impact 1
]

# Severity → (likelihood index 0-4, impact index 0-4)
_SEV_MATRIX = {
    'critical': (4, 0),  # likelihood=5, impact row 0 (=impact 5, top row)
    'high':     (3, 1),
    'medium':   (2, 2),
    'low':      (1, 3),
    'info':     (0, 4),
}

# ── Static content ────────────────────────────────────────────────────────────
_VULN_LABELS = {
    'sqli_error':         'SQL Injection (Error-based)',
    'sqli_blind_boolean': 'SQL Injection (Boolean Blind)',
    'sqli_blind_time':    'SQL Injection (Time Blind)',
    'xss_reflected':      'Reflected Cross-Site Scripting',
    'xss_stored':         'Stored Cross-Site Scripting',
    'xss_dom':            'DOM-based Cross-Site Scripting',
    'idor':               'Insecure Direct Object Reference (IDOR)',
    'ssrf':               'Server-Side Request Forgery (SSRF)',
    'misconfig_header':   'Missing Security Header',
    'misconfig_file':     'Exposed Sensitive File',
    'data_exposure':      'Sensitive Data Exposure',
}

_VULN_SHORT = {
    'sqli_error':         'SQLi (Error)',
    'sqli_blind_boolean': 'SQLi (Boolean)',
    'sqli_blind_time':    'SQLi (Time)',
    'xss_reflected':      'XSS (Reflected)',
    'xss_stored':         'XSS (Stored)',
    'xss_dom':            'XSS (DOM)',
    'idor':               'IDOR',
    'ssrf':               'SSRF',
    'misconfig_header':   'Missing Header',
    'misconfig_file':     'Exposed File',
    'data_exposure':      'Data Exposure',
}

_VULN_DESC = {
    'sqli_error': (
        'The application returned a database error in response to a crafted payload, '
        'confirming that user input is embedded directly into SQL queries without '
        'parameterisation or sanitisation.'
    ),
    'sqli_blind_boolean': (
        'The application produces different responses depending on whether an injected '
        'boolean condition is true or false, revealing unsanitised SQL construction '
        'even without visible error messages.'
    ),
    'sqli_blind_time': (
        'The application delayed its response when a time-delay SQL payload was injected, '
        'confirming unsanitised SQL query construction via observable response timing.'
    ),
    'xss_reflected': (
        'User-supplied input is echoed in the HTTP response without adequate output '
        'encoding, enabling crafted URLs that execute malicious scripts in a victim\'s browser.'
    ),
    'xss_stored': (
        'Malicious script payload submitted by an attacker is persisted and subsequently '
        'rendered to other users without sanitisation, enabling persistent browser-side '
        'script execution.'
    ),
    'xss_dom': (
        'Client-side JavaScript reads from an attacker-controllable source '
        '(e.g. location.hash) and writes it to a dangerous DOM sink (e.g. innerHTML) '
        'without sanitisation.'
    ),
    'idor': (
        'The application exposes sequential or predictable object identifiers. An attacker '
        'can enumerate these to access data or actions belonging to other users without '
        'any authentication bypass.'
    ),
    'ssrf': (
        'A user-controlled URL parameter causes the server to make HTTP requests to '
        'attacker-specified targets, potentially reaching internal services or cloud '
        'metadata endpoints not exposed publicly.'
    ),
    'misconfig_header': (
        'A required HTTP security response header is absent, removing a browser-enforced '
        'defence layer against clickjacking, MIME-type confusion, or XSS attacks.'
    ),
    'misconfig_file': (
        'A configuration, backup, or source-control file is directly accessible via the '
        'web server, potentially disclosing credentials, source code, or database details.'
    ),
    'data_exposure': (
        'Credentials, API keys, or cryptographic keys were detected within an HTTP '
        'response body, allowing an attacker to harvest them for privilege escalation.'
    ),
}

_BUSINESS_IMPACT = {
    'sqli_error': (
        'Complete database compromise. An attacker can extract all stored data, modify or '
        'delete records, and potentially execute OS commands. Mandatory breach notification '
        'and significant regulatory fines are likely consequences.'
    ),
    'sqli_blind_boolean': (
        'Systematic data exfiltration. All database content is at risk of exposure over '
        'time. Breach detection is difficult due to the absence of visible error messages.'
    ),
    'sqli_blind_time': (
        'Full database extraction is possible using automated tooling. The time-based '
        'channel is harder to detect in logs. Risk of complete data compromise.'
    ),
    'xss_reflected': (
        'Account takeover via session-cookie theft. Attackers can craft phishing links '
        'that hijack authenticated user sessions. Reputational damage and regulatory '
        'exposure if user data is compromised.'
    ),
    'xss_stored': (
        'Persistent malicious content delivered to all site visitors. Mass account '
        'compromise, malware distribution, and severe reputational damage are possible.'
    ),
    'xss_dom': (
        'Client-side data theft and session hijacking with no server-side trace. '
        'Account compromise with minimal evidence in server logs.'
    ),
    'idor': (
        'Unauthorised access to other users\' private records. Constitutes a personal '
        'data breach under GDPR, triggering mandatory reporting and potential fines.'
    ),
    'ssrf': (
        'Access to internal infrastructure and cloud provider metadata services. '
        'Can lead to full cloud environment compromise and significant financial exposure.'
    ),
    'misconfig_header': (
        'Reduced browser-side attack resistance. Increases the likelihood of successful '
        'XSS and clickjacking attacks against end users.'
    ),
    'misconfig_file': (
        'Direct exposure of credentials or internal paths enabling targeted follow-on '
        'attacks. A leaked .env file can grant full application-level access within minutes.'
    ),
    'data_exposure': (
        'Immediate credential or API key compromise enabling unauthorised access to '
        'integrated services. Direct financial loss and breach notification obligations.'
    ),
}

_REMEDIATION_DETAIL = {
    'sqli_error': [
        'Use parameterised queries / prepared statements for ALL database interactions.',
        'Use an ORM (e.g. SQLAlchemy, Hibernate) that handles parameterisation automatically.',
        'Apply strict input validation as a secondary defence layer.',
        'OWASP Cheat Sheet: SQL Injection Prevention',
    ],
    'sqli_blind_boolean': [
        'Use parameterised queries for all database calls (see SQL Injection Prevention CS).',
        'Disable verbose error messages in production to prevent information leakage.',
        'OWASP Cheat Sheet: SQL Injection Prevention',
    ],
    'sqli_blind_time': [
        'Use parameterised queries for all database calls.',
        'Enforce strict timeouts on all database queries to limit time-based exploitation.',
        'OWASP Cheat Sheet: SQL Injection Prevention',
    ],
    'xss_reflected': [
        'Apply context-aware output encoding for all user-supplied data (HTML, JS, URL, CSS).',
        'Implement a strict Content-Security-Policy (CSP) header.',
        'Use a templating engine with auto-escaping enabled (e.g. Jinja2, Twig).',
        'OWASP Cheat Sheet: XSS Prevention, DOM-based XSS Prevention',
    ],
    'xss_stored': [
        'Sanitise user input at point of storage using an allowlist-based sanitiser.',
        'Apply output encoding at the point of rendering, not storage.',
        'Implement Content-Security-Policy (CSP) to prevent execution of injected scripts.',
        'OWASP Cheat Sheet: XSS Prevention',
    ],
    'xss_dom': [
        'Avoid passing user-controlled data to dangerous DOM sinks (innerHTML, eval, etc.).',
        'Use safe DOM APIs: textContent instead of innerHTML, createElement instead of eval.',
        'Sanitise data from URL hash/query with a trusted library (e.g. DOMPurify).',
        'OWASP Cheat Sheet: DOM-based XSS Prevention',
    ],
    'idor': [
        'Implement server-side authorisation checks on every object access.',
        'Replace direct object IDs with indirect references mapped server-side per user.',
        'Enforce the principle of least privilege across all data access paths.',
        'OWASP Cheat Sheet: Insecure Direct Object Reference Prevention',
    ],
    'ssrf': [
        'Validate and allowlist all user-supplied URLs against a permitted domain list.',
        'Block requests to RFC 1918 private IP ranges and cloud metadata endpoints.',
        'Use a dedicated HTTP client that restricts outbound connectivity by default.',
        'OWASP Cheat Sheet: Server-Side Request Forgery Prevention',
    ],
    'misconfig_header': [
        'Add Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options,',
        'X-Frame-Options: DENY, and Referrer-Policy headers to all HTTP responses.',
        'Use the OWASP Secure Headers Project list as a configuration reference.',
        'OWASP: Secure Headers Project',
    ],
    'misconfig_file': [
        'Remove all sensitive files from the web root (backups, .env, .git/).',
        'Add server rules (nginx deny, .htaccess) to block access to sensitive paths.',
        'Rotate all credentials exposed in the file immediately.',
        'OWASP Cheat Sheet: Error Handling',
    ],
    'data_exposure': [
        'Remove secrets from all responses and code immediately.',
        'Rotate all exposed credentials, API keys, and certificates.',
        'Store secrets in environment variables or a secrets manager, never in source code.',
        'OWASP Cheat Sheet: Cryptographic Storage',
    ],
}

_OWASP_CS_LINKS = {
    'sqli_error':         'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    'sqli_blind_boolean': 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    'sqli_blind_time':    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    'xss_reflected':      'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    'xss_stored':         'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    'xss_dom':            'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
    'idor':               'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
    'ssrf':               'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
    'misconfig_header':   'https://owasp.org/www-project-secure-headers/',
    'misconfig_file':     'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
    'data_exposure':      'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
}

_COMPLIANCE: dict[str, dict[str, str]] = {
    'sqli_error': {
        'gdpr':    'Art. 5(1)(f), Art. 25, Art. 32, Art. 33',
        'pci_dss': 'Req 6.2.4, Req 6.3.1, Req 6.4.1',
        'iso27001':'A.14.2.5, A.14.2.8, A.12.6.1, A.18.1.3',
    },
    'sqli_blind_boolean': {
        'gdpr':    'Art. 5(1)(f), Art. 32, Art. 33',
        'pci_dss': 'Req 6.2.4, Req 6.4.1',
        'iso27001':'A.14.2.5, A.14.2.8, A.12.6.1',
    },
    'sqli_blind_time': {
        'gdpr':    'Art. 5(1)(f), Art. 32, Art. 33',
        'pci_dss': 'Req 6.2.4, Req 6.4.1',
        'iso27001':'A.14.2.5, A.14.2.8, A.12.6.1',
    },
    'xss_reflected': {
        'gdpr':    'Art. 5(1)(f), Art. 32',
        'pci_dss': 'Req 6.2.4, Req 6.4.1',
        'iso27001':'A.14.2.5, A.14.2.8',
    },
    'xss_stored': {
        'gdpr':    'Art. 5(1)(f), Art. 32, Art. 33',
        'pci_dss': 'Req 6.2.4, Req 6.4.1',
        'iso27001':'A.14.2.5, A.14.2.8',
    },
    'xss_dom': {
        'gdpr':    'Art. 5(1)(f), Art. 32',
        'pci_dss': 'Req 6.2.4, Req 6.4.1',
        'iso27001':'A.14.2.5, A.14.2.8',
    },
    'idor': {
        'gdpr':    'Art. 5(1)(f), Art. 25, Art. 32, Art. 33',
        'pci_dss': 'Req 7.1, Req 7.2, Req 8.3',
        'iso27001':'A.9.4.1, A.14.2.8, A.18.1.3',
    },
    'ssrf': {
        'gdpr':    'Art. 32, Art. 33',
        'pci_dss': 'Req 6.2.4, Req 6.4.1, Req 1.3',
        'iso27001':'A.13.1.3, A.14.2.8, A.12.6.1',
    },
    'misconfig_header': {
        'gdpr':    'Art. 25, Art. 32',
        'pci_dss': 'Req 2.2.1, Req 6.3.3',
        'iso27001':'A.12.1.2, A.14.2.2, A.14.2.8',
    },
    'misconfig_file': {
        'gdpr':    'Art. 25, Art. 32, Art. 33',
        'pci_dss': 'Req 2.2.1, Req 3.4, Req 6.3.3',
        'iso27001':'A.8.2.3, A.12.1.2, A.14.2.8',
    },
    'data_exposure': {
        'gdpr':    'Art. 5(1)(f), Art. 25, Art. 32, Art. 33',
        'pci_dss': 'Req 3.2, Req 3.4, Req 6.2.4',
        'iso27001':'A.8.2.1, A.10.1.1, A.18.1.3',
    },
}

_MODULE_DESC = {
    'sqli':          'SQL Injection detection (error-based, boolean-blind, time-blind)',
    'xss_reflected': 'Reflected Cross-Site Scripting',
    'xss_stored':    'Stored Cross-Site Scripting',
    'xss_dom':       'DOM-based XSS via Selenium headless Chrome',
    'bac':           'Broken Access Control (IDOR and SSRF)',
    'misconfig':     'Security Misconfiguration (headers and exposed files)',
    'exposure':      'Sensitive Data Exposure (API keys, credentials, PEM keys)',
}


# ── Text utilities ────────────────────────────────────────────────────────────

def _safe(text: str) -> str:
    """Replace non-Latin-1 characters for fpdf2 built-in font compatibility."""
    return (text
        .replace('•', '-').replace('—', ' - ').replace('–', ' - ')
        .replace('’', "'").replace('‘', "'")
        .replace('“', '"').replace('”', '"')
        .replace('…', '...')
    )


def _trunc(text: str, limit: int = 500) -> str:
    if not text:
        return ''
    text = text.strip()
    if len(text) <= limit:
        return _safe(text)
    return _safe(text[:limit]) + f'\n[... {len(text) - limit} chars truncated]'


def _fmt_date(dt: datetime | None) -> str:
    if dt is None:
        return 'N/A'
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime('%d %b %Y  %H:%M UTC')


# ── PDF class ─────────────────────────────────────────────────────────────────

class _ReportPDF(FPDF):
    def __init__(self, scan: Scan) -> None:
        super().__init__(orientation='P', unit='mm', format='A4')
        self._scan = scan
        self._scan_date = _fmt_date(scan.completed_at)
        self.set_margins(20, 20, 20)
        self.set_auto_page_break(auto=True, margin=28)

    # ── FPDF overrides ────────────────────────────────────────────────────────

    def header(self) -> None:
        if self.page_no() <= 2:  # skip on cover + management summary
            return
        self.set_font('Helvetica', 'B', 7)
        self.set_text_color(*_GRAY)
        self.cell(0, 5, 'VulnScanner | Security Assessment Report', align='L',
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*_LGRAY)
        self.line(20, self.get_y(), 190, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font('Helvetica', '', 7)
        self.set_text_color(*_GRAY)
        self.cell(0, 5,
                  f'CONFIDENTIAL | {self._scan_date} | Page {self.page_no()}',
                  align='C')

    # ── Layout primitives ─────────────────────────────────────────────────────

    def _section_title(self, text: str) -> None:
        self.ln(4)
        self.set_font('Helvetica', 'B', 13)
        self.set_text_color(*_NAVY)
        self.cell(0, 8, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*_NAVY)
        self.line(20, self.get_y(), 190, self.get_y())
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def _sub_heading(self, text: str) -> None:
        self.ln(2)
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(*_NAVY)
        self.cell(0, 6, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def _body(self, text: str) -> None:
        self.set_font('Helvetica', '', 9)
        self.multi_cell(0, 5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def _code_block(self, text: str) -> None:
        if not text:
            return
        self.set_fill_color(245, 245, 245)
        self.set_draw_color(*_LGRAY)
        self.set_font('Courier', '', 7)
        self.multi_cell(0, 4, _safe(text), border=1, fill=True,
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_fill_color(*_WHITE)
        self.ln(2)

    def _kv(self, label: str, value: str, mono: bool = False) -> None:
        self.set_font('Helvetica', 'B', 8)
        self.cell(40, 5, _safe(label) + ':', new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font('Courier' if mono else 'Helvetica', '', 8 if not mono else 7)
        self.multi_cell(0, 5, _safe(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def _sev_chip(self, sev: str, w: float = 22) -> None:
        bg, fg, label = _SEV_CFG.get(sev, _SEV_CFG['info'])
        self.set_fill_color(*bg)
        self.set_text_color(*fg)
        self.set_font('Helvetica', 'B', 7)
        self.cell(w, 5, label, fill=True, align='C',
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_fill_color(*_WHITE)
        self.set_text_color(0, 0, 0)

    # ── Table helpers ─────────────────────────────────────────────────────────

    def _th(self, headers: list[str], widths: list[float], row_h: float = 6) -> None:
        self.set_fill_color(*_NAVY)
        self.set_text_color(*_WHITE)
        self.set_font('Helvetica', 'B', 8)
        for txt, w in zip(headers, widths):
            self.cell(w, row_h, _safe(txt), border=0, fill=True,
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.ln(row_h)
        self.set_text_color(0, 0, 0)
        self.set_fill_color(*_WHITE)

    def _td(self, cells: list[str], widths: list[float],
            sev: str | None = None, row_h: float = 5,
            fill: bool = False) -> None:
        if fill:
            self.set_fill_color(*_BGRAY)
        self.set_font('Helvetica', '', 8)
        for i, (txt, w) in enumerate(zip(cells, widths)):
            if sev and i == 0:
                self._sev_chip(sev, w)
            else:
                self.set_draw_color(*_LGRAY)
                self.cell(w, row_h, _safe(txt), border='B', fill=fill,
                          new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.ln(row_h)
        if fill:
            self.set_fill_color(*_WHITE)

    # ── Chart: horizontal severity bar ────────────────────────────────────────

    def _severity_bar_chart(self, sev_counts: dict[str, int]) -> None:
        total = sum(sev_counts.values()) or 1
        bar_max = 85.0
        bar_h   = 6.5
        lbl_w   = 26.0
        cnt_w   = 12.0

        self.ln(2)
        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            count = sev_counts.get(sev, 0)
            if count == 0:
                continue
            bg, fg, label = _SEV_CFG[sev]

            self.set_font('Helvetica', 'B', 8)
            self.set_text_color(*_NAVY)
            self.cell(lbl_w, bar_h, label, new_x=XPos.RIGHT, new_y=YPos.TOP)

            self.set_text_color(0, 0, 0)
            self.cell(cnt_w, bar_h, str(count), align='R',
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(3, bar_h, '', new_x=XPos.RIGHT, new_y=YPos.TOP)

            bar_w = round((count / total) * bar_max, 1)
            self.set_fill_color(*bg)
            if bar_w > 0:
                self.cell(bar_w, bar_h, '', fill=True,
                          new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_fill_color(*_WHITE)
            self.set_font('Helvetica', '', 7)
            self.set_text_color(*_GRAY)
            self.cell(20, bar_h, f'  {count/total*100:.0f}%',
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_text_color(0, 0, 0)
        self.ln(3)

    # ── Chart: 5x5 risk matrix ────────────────────────────────────────────────

    def _risk_matrix(self, sev_counts: dict[str, int]) -> None:
        """Draw a 5x5 likelihood-vs-impact risk matrix and plot findings on it."""
        self.ln(2)
        cell_size = 10.0
        grid_x = self.get_x() + 25  # leave room for y-axis label
        grid_y = self.get_y()
        rows = 5
        cols = 5

        # Y-axis label
        self.set_font('Helvetica', 'B', 7)
        self.set_text_color(*_GRAY)
        self.set_xy(grid_x - 22, grid_y + rows * cell_size / 2 - 3)
        self.cell(20, 5, 'Impact', align='C')

        # Draw the 5x5 grid (row 0 = top = highest impact)
        for r in range(rows):
            for c in range(cols):
                color = _MATRIX_COLORS[r][c]
                self.set_fill_color(*color)
                self.set_draw_color(*_LGRAY)
                self.rect(grid_x + c * cell_size, grid_y + r * cell_size,
                          cell_size, cell_size, 'FD')

        # Y-axis tick labels (impact 5 at top, 1 at bottom)
        labels_y = ['5', '4', '3', '2', '1']
        self.set_font('Helvetica', '', 6)
        self.set_text_color(*_GRAY)
        for r, lbl in enumerate(labels_y):
            self.set_xy(grid_x - 6, grid_y + r * cell_size + cell_size / 2 - 2)
            self.cell(5, 4, lbl, align='R')

        # X-axis tick labels (likelihood 1-5 left to right)
        for c, lbl in enumerate(['1', '2', '3', '4', '5']):
            self.set_xy(grid_x + c * cell_size + cell_size / 2 - 3,
                        grid_y + rows * cell_size + 1)
            self.cell(6, 4, lbl, align='C')

        # Axis titles
        self.set_font('Helvetica', 'B', 7)
        self.set_xy(grid_x + (cols * cell_size / 2) - 12,
                    grid_y + rows * cell_size + 6)
        self.cell(24, 4, 'Likelihood', align='C')

        # Plot findings as small colored squares on the matrix
        for sev, (c_idx, r_idx) in _SEV_MATRIX.items():
            count = sev_counts.get(sev, 0)
            if count == 0:
                continue
            bg, fg, _ = _SEV_CFG[sev]
            dot_x = grid_x + c_idx * cell_size + 2
            dot_y = grid_y + r_idx * cell_size + 2
            self.set_fill_color(*bg)
            self.rect(dot_x, dot_y, 6, 6, 'F')
            self.set_font('Helvetica', 'B', 6)
            self.set_text_color(*fg)
            self.set_xy(dot_x, dot_y + 1)
            self.cell(6, 4, str(count), align='C')

        self.set_text_color(0, 0, 0)
        self.set_fill_color(*_WHITE)

        # Legend to the right of the matrix
        legend_x = grid_x + cols * cell_size + 8
        legend_y = grid_y
        self.set_font('Helvetica', 'B', 7)
        self.set_xy(legend_x, legend_y)
        self.cell(40, 5, 'Legend', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            bg, fg, label = _SEV_CFG[sev]
            self.set_fill_color(*bg)
            self.rect(legend_x, self.get_y(), 5, 5, 'F')
            self.set_font('Helvetica', '', 7)
            self.set_text_color(0, 0, 0)
            self.set_xy(legend_x + 7, self.get_y())
            self.cell(35, 5, label, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Advance past the matrix
        self.set_y(grid_y + rows * cell_size + 14)
        self.ln(3)

    # ── Page builders ─────────────────────────────────────────────────────────

    def build_cover(self, sev_counts: dict[str, int]) -> None:
        self.add_page()

        self.set_fill_color(*_NAVY)
        self.rect(0, 0, 210, 65, 'F')

        self.set_y(18)
        self.set_font('Helvetica', 'B', 32)
        self.set_text_color(*_WHITE)
        self.cell(0, 14, 'VulnScanner', align='C',
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_font('Helvetica', '', 12)
        self.set_text_color(180, 205, 235)
        self.cell(0, 8, 'Automated Web Application Security Assessment Report',
                  align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(140, 170, 210)
        self.cell(0, 7, 'CONFIDENTIAL - For authorised recipients only',
                  align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

        # Metadata
        self.set_y(80)
        self._kv('Target URL',    self._scan.target_url)
        self._kv('Report Date',   self._scan_date)
        self._kv('Scan ID',       str(self._scan.id))
        if self._scan.started_at and self._scan.completed_at:
            s = (self._scan.started_at.replace(tzinfo=timezone.utc)
                 if self._scan.started_at.tzinfo is None else self._scan.started_at)
            e = (self._scan.completed_at.replace(tzinfo=timezone.utc)
                 if self._scan.completed_at.tzinfo is None else self._scan.completed_at)
            secs = int((e - s).total_seconds())
            m, sec = divmod(secs, 60)
            self._kv('Scan Duration',   f'{m}m {sec}s')
        self._kv('URLs Crawled',  str(self._scan.total_urls_found))
        self._kv('Total Findings',str(self._scan.total_findings))
        self._kv('Tool Version',  'VulnScanner 1.0.0')
        self._kv('Scoring',       'CVSS v3.1 Base Score')
        self._kv('Classification','OWASP Top 10')

        # Severity boxes
        self.ln(6)
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(*_NAVY)
        self.cell(0, 5, 'Findings by Severity', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(3)

        box_w = 32.0
        gap   = 2.0
        x0    = 20.0
        y0    = self.get_y()

        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            count = sev_counts.get(sev, 0)
            bg, fg, label = _SEV_CFG[sev]
            self.set_fill_color(*bg)
            self.rect(x0, y0, box_w, 22, 'F')
            self.set_font('Helvetica', 'B', 20)
            self.set_text_color(*fg)
            self.set_xy(x0, y0 + 1)
            self.cell(box_w, 12, str(count), align='C',
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font('Helvetica', 'B', 7)
            self.set_xy(x0, y0 + 13)
            self.cell(box_w, 7, label, align='C',
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            x0 += box_w + gap

        self.set_text_color(0, 0, 0)

        # Risk headline
        self.set_y(y0 + 30)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(*_GRAY)
        crit = sev_counts.get('critical', 0)
        high = sev_counts.get('high', 0)
        if crit:
            stmt = f'CRITICAL risk: {crit} finding(s) require immediate remediation.'
        elif high:
            stmt = f'HIGH risk: {high} finding(s) require urgent attention within 30 days.'
        elif self._scan.total_findings:
            stmt = 'Medium/Low risks identified. Schedule remediation in upcoming sprints.'
        else:
            stmt = 'No exploitable vulnerabilities detected in this assessment.'
        self.cell(0, 5, stmt, align='C')
        self.set_text_color(0, 0, 0)

    def build_management_summary(self, sev_counts: dict[str, int],
                                  findings: list[Finding]) -> None:
        """One-page plain-language summary for management / non-technical stakeholders."""
        self.add_page()

        # Page-wide amber header band for management pages
        self.set_fill_color(*_NAVY)
        self.rect(0, 0, 210, 14, 'F')
        self.set_y(3)
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(*_WHITE)
        self.cell(0, 7, 'Management Executive Summary  -  For Non-Technical Readers',
                  align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_y(22)

        total = self._scan.total_findings
        crit  = sev_counts.get('critical', 0)
        high  = sev_counts.get('high', 0)
        med   = sev_counts.get('medium', 0)
        low   = sev_counts.get('low', 0)

        # What Was Done
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(*_NAVY)
        self.cell(0, 7, 'What Was Done', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self._body(
            f'An automated security scan of {self._scan.target_url} was completed on '
            f'{self._scan_date}. The VulnScanner tool tested {self._scan.total_urls_found} '
            'web pages and forms for common security weaknesses, using the same '
            'techniques that malicious attackers employ.'
        )

        # What Was Found - traffic light boxes
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(*_NAVY)
        self.cell(0, 7, 'What Was Found', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

        if total == 0:
            self.set_fill_color(220, 252, 231)
            self.set_draw_color(*_GREEN)
            self.set_font('Helvetica', 'B', 12)
            self.set_text_color(*_GREEN)
            self.multi_cell(0, 8, 'No security vulnerabilities were detected.',
                            border=1, fill=True, align='C',
                            new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(0, 0, 0)
            self.set_fill_color(*_WHITE)
        else:
            findings_summary = (
                f'{total} security vulnerabilit{"y" if total==1 else "ies"} '
                f'{"was" if total==1 else "were"} found'
            )
            parts = []
            if crit: parts.append(f'{crit} require immediate action')
            if high: parts.append(f'{high} require urgent attention')
            if med:  parts.append(f'{med} should be fixed soon')
            if low:  parts.append(f'{low} are low priority')
            if parts:
                findings_summary += ': ' + '; '.join(parts) + '.'

            self._body(findings_summary)

            # Top 3 business risks in plain language
            top_risks = findings[:3]
            for f in top_risks:
                bg, fg, label = _SEV_CFG.get(f.severity.value, _SEV_CFG['info'])
                self.set_fill_color(*bg)
                impact_short = _BUSINESS_IMPACT.get(f.vuln_type, '')
                impact_short = impact_short.split('.')[0] + '.' if impact_short else ''

                self.set_font('Helvetica', 'B', 8)
                self.set_text_color(*fg)
                self.cell(26, 6, label, fill=True, align='C',
                          new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.set_fill_color(*_WHITE)
                self.set_text_color(0, 0, 0)
                self.set_font('Helvetica', 'B', 8)
                vuln_label = _VULN_LABELS.get(f.vuln_type, f.vuln_type)
                self.cell(3, 6, '', new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.set_font('Helvetica', '', 8)
                self.multi_cell(0, 6, _safe(f'{vuln_label}: {impact_short}'),
                                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        # What Needs to Happen
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(*_NAVY)
        self.cell(0, 7, 'What Needs to Happen', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

        action_rows = []
        if crit:
            action_rows.append(('Immediate (now)', f'Fix {crit} Critical finding(s) before the application is accessible.', (220,38,38)))
        if high:
            action_rows.append(('Within 30 days', f'Fix {high} High severity finding(s) in the next sprint.', (234,88,12)))
        if med:
            action_rows.append(('Within 90 days', f'Schedule {med} Medium finding(s) for the next release cycle.', (202,138,4)))
        if low:
            action_rows.append(('Next cycle', f'Plan {low} Low/Info finding(s) as backlog items.', (37,99,235)))
        if not action_rows:
            action_rows.append(('Ongoing', 'Continue regular security assessments and monitoring.', (22,163,74)))
        action_rows.append(('Ongoing', 'Re-scan after each fix batch. Integrate VulnScanner into CI/CD.', (15,40,80)))

        cols_a = [38, 132]
        self._th(['Timeframe', 'Required Action'], cols_a, row_h=5)
        for timeline, action, color in action_rows:
            self.set_fill_color(*color)
            self.set_text_color(*_WHITE)
            self.set_font('Helvetica', 'B', 7)
            self.cell(cols_a[0], 5, timeline, fill=True,
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_fill_color(*_WHITE)
            self.set_text_color(0, 0, 0)
            self.set_font('Helvetica', '', 8)
            self.cell(cols_a[1], 5, _safe(action), border='B',
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(4)

        # Key message
        self.set_fill_color(230, 240, 255)
        self.set_draw_color(*_NAVY)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(*_NAVY)
        key_msg = (
            'The full technical details, evidence, and step-by-step remediation instructions '
            'are contained in the sections that follow this summary. '
            'Please share the full report with your development team.'
        )
        self.multi_cell(0, 5, _safe(key_msg), border=1, fill=True,
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_fill_color(*_WHITE)
        self.set_draw_color(*_LGRAY)

    def build_executive_summary(self, sev_counts: dict[str, int]) -> None:
        self._section_title('1. Technical Executive Summary')

        total = self._scan.total_findings
        crit  = sev_counts.get('critical', 0)
        high  = sev_counts.get('high', 0)
        med   = sev_counts.get('medium', 0)
        low   = sev_counts.get('low', 0)

        parts = [f'{n} {s.capitalize()}' for s, n in
                 [('critical', crit),('high', high),('medium', med),('low', low)] if n]
        breakdown = ', '.join(parts) if parts else 'no high-risk findings'

        if total == 0:
            para = (
                f'VulnScanner assessed {self._scan.target_url} on {self._scan_date}, '
                f'crawling {self._scan.total_urls_found} page(s). No exploitable '
                'vulnerabilities were detected within the scope of the enabled modules. '
                'Continued periodic assessments and manual penetration testing are recommended.'
            )
        else:
            para = (
                f'VulnScanner assessed {self._scan.target_url} on {self._scan_date}, '
                f'crawling {self._scan.total_urls_found} page(s). '
                f'{total} vulnerabilit{"y was" if total==1 else "ies were"} identified: {breakdown}. '
            )
            if crit:
                para += (f'{crit} Critical finding(s) require immediate remediation. ')
            if high:
                para += (f'{high} High severity finding(s) should be addressed within 30 days. ')

        self._body(para)

        # Two-column layout: bar chart left, risk matrix right
        self.ln(2)
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(*_NAVY)
        self.cell(95, 5, 'Severity Distribution', new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(75, 5, 'Risk Matrix (Likelihood vs Impact)', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

        # Save y, draw bar chart on left column manually
        y_start = self.get_y()
        self._severity_bar_chart(sev_counts)
        y_after_chart = self.get_y()

        # Draw risk matrix on the right starting at same y
        self.set_xy(110, y_start)
        self._risk_matrix_at(sev_counts, start_x=110, start_y=y_start)

        self.set_y(max(y_after_chart, y_start + 60))

        # Risk at a glance table
        self._sub_heading('Risk at a Glance')
        cols = [28, 16, 32, 94]
        self._th(['Severity', 'Count', 'Timeline', 'Business Risk Summary'], cols)
        risk_rows = {
            'critical': ('Immediate',   'Full compromise; regulatory breach; breach notification'),
            'high':     ('30 days',     'Targeted attack risk; data exposure; account compromise'),
            'medium':   ('90 days',     'Increased attack surface; defence-in-depth gaps'),
            'low':      ('Next cycle',  'Best-practice hardening recommended'),
            'info':     ('Advisory',    'Informational; no direct exploit risk'),
        }
        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            n = sev_counts.get(sev, 0)
            if n == 0:
                continue
            timeline, biz = risk_rows[sev]
            self._td([sev.upper(), str(n), timeline, biz], cols, sev=sev)
        self.ln(3)

    def _risk_matrix_at(self, sev_counts: dict[str, int],
                         start_x: float, start_y: float) -> None:
        """Draw the risk matrix at a specific (x, y) position."""
        cell_size = 8.0
        rows = cols = 5
        grid_x = start_x + 10
        grid_y = start_y + 4

        for r in range(rows):
            for c in range(cols):
                color = _MATRIX_COLORS[r][c]
                self.set_fill_color(*color)
                self.set_draw_color(*_LGRAY)
                self.rect(grid_x + c * cell_size, grid_y + r * cell_size,
                          cell_size, cell_size, 'FD')

        # Axis labels
        self.set_font('Helvetica', '', 5)
        self.set_text_color(*_GRAY)
        for r, lbl in enumerate(['5','4','3','2','1']):
            self.set_xy(grid_x - 5, grid_y + r * cell_size + cell_size/2 - 2)
            self.cell(4, 3, lbl, align='R')
        for c, lbl in enumerate(['1','2','3','4','5']):
            self.set_xy(grid_x + c * cell_size + 1,
                        grid_y + rows * cell_size + 1)
            self.cell(6, 3, lbl, align='C')

        self.set_font('Helvetica', 'B', 6)
        self.set_xy(grid_x - 10, grid_y + rows * cell_size / 2 - 3)
        self.cell(8, 4, 'Imp.', align='C')
        self.set_xy(grid_x + cols * cell_size / 2 - 5,
                    grid_y + rows * cell_size + 5)
        self.cell(20, 4, 'Likelihood', align='C')

        # Plot findings
        for sev, (c_idx, r_idx) in _SEV_MATRIX.items():
            count = sev_counts.get(sev, 0)
            if count == 0:
                continue
            bg, fg, _ = _SEV_CFG[sev]
            self.set_fill_color(*bg)
            dot_x = grid_x + c_idx * cell_size + 1
            dot_y = grid_y + r_idx * cell_size + 1
            self.rect(dot_x, dot_y, 6, 6, 'F')
            self.set_font('Helvetica', 'B', 6)
            self.set_text_color(*fg)
            self.set_xy(dot_x, dot_y + 1)
            self.cell(6, 4, str(count), align='C')

        self.set_text_color(0, 0, 0)
        self.set_fill_color(*_WHITE)

    def build_remediation_plan(self, findings: list[Finding]) -> None:
        self._section_title('2. Remediation Prioritisation')
        self._body(
            'Findings are grouped by recommended remediation priority. '
            'Timelines are guidelines and should be adjusted based on business '
            'context, available resources, and any compensating controls in place.'
        )

        buckets: dict[str, list[Finding]] = {
            'Immediate (24-48 hours)':   [],
            'Short-term (30 days)':      [],
            'Medium-term (90 days)':     [],
            'Long-term (next cycle)':    [],
            'Advisory':                  [],
        }
        bucket_map = {
            'critical': 'Immediate (24-48 hours)',
            'high':     'Short-term (30 days)',
            'medium':   'Medium-term (90 days)',
            'low':      'Long-term (next cycle)',
            'info':     'Advisory',
        }
        for f in findings:
            buckets[bucket_map.get(f.severity.value, 'Advisory')].append(f)

        cols = [22, 50, 50, 48]
        for bname, bfindings in buckets.items():
            if not bfindings:
                continue
            self._sub_heading(bname)
            self._th(['Sev.', 'Vulnerability', 'Affected URL', 'OWASP'], cols)
            for f in bfindings:
                url = f.affected_url
                if len(url) > 32: url = url[:29] + '...'
                owasp = f'{f.owasp_category} {f.owasp_name}' if f.owasp_category else '---'
                if len(owasp) > 30: owasp = owasp[:27] + '...'
                self._td(
                    [f.severity.value.upper(), _VULN_SHORT.get(f.vuln_type, f.vuln_type),
                     url, owasp],
                    cols, sev=f.severity.value,
                )
            self.ln(2)

    def build_compliance_mapping(self, findings: list[Finding]) -> None:
        self._section_title('3. Compliance Mapping')
        self._body(
            'The table below maps each identified finding to relevant regulatory and '
            'standards requirements. Organisations subject to these frameworks should '
            'treat the indicated requirements as directly affected and plan remediation '
            'accordingly. This mapping is provided as guidance; a qualified compliance '
            'officer or auditor should confirm the full regulatory impact.'
        )
        self.ln(2)

        # Deduplicate by vuln_type
        seen: set[str] = set()
        unique_findings: list[Finding] = []
        for f in findings:
            if f.vuln_type not in seen:
                seen.add(f.vuln_type)
                unique_findings.append(f)

        cols = [42, 40, 50, 38]
        self._th(['Vulnerability', 'GDPR Articles', 'PCI DSS v4.0', 'ISO 27001'], cols)
        for i, f in enumerate(unique_findings):
            comp = _COMPLIANCE.get(f.vuln_type, {})
            gdpr    = comp.get('gdpr', '---')
            pci     = comp.get('pci_dss', '---')
            iso     = comp.get('iso27001', '---')
            short   = _VULN_SHORT.get(f.vuln_type, f.vuln_type)
            self._td([short, gdpr, pci, iso], cols, fill=(i % 2 == 1))
        self.ln(4)

        # Brief framework descriptions
        self._sub_heading('Framework Reference')
        frames = [
            ('GDPR (EU)',
             'The General Data Protection Regulation requires organisations to implement '
             'appropriate technical measures to protect personal data (Art. 32) and report '
             'breaches within 72 hours (Art. 33). Many of the findings in this report '
             'constitute risks to GDPR compliance.'),
            ('PCI DSS v4.0',
             'The Payment Card Industry Data Security Standard mandates that all web '
             'applications handling cardholder data be protected against common attack '
             'vectors (Req 6.2.4, 6.4.1) and kept updated with security patches (Req 6.3.3).'),
            ('ISO/IEC 27001:2022',
             'The international information security management standard requires '
             'systematic identification and treatment of security vulnerabilities '
             '(A.12.6.1, A.14.2.8). Identified findings represent non-conformances '
             'against the standard\'s security controls.'),
        ]
        for title, desc in frames:
            self.set_font('Helvetica', 'B', 8)
            self.cell(0, 4, _safe(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self._body(desc)

    def build_findings_summary(self, findings: list[Finding]) -> None:
        self._section_title('4. Findings Summary')
        if not findings:
            self._body('No findings were recorded for this scan.')
            return

        cols = [20, 46, 56, 14, 34]
        self._th(['Sev.', 'Vulnerability', 'Affected URL', 'CVSS', 'OWASP'], cols)
        for i, f in enumerate(findings):
            url = f.affected_url
            if len(url) > 36: url = url[:33] + '...'
            owasp = f'{f.owasp_category} {f.owasp_name}' if f.owasp_category else '---'
            if len(owasp) > 24: owasp = owasp[:21] + '...'
            self._td(
                [f.severity.value.upper(), _VULN_SHORT.get(f.vuln_type, f.vuln_type),
                 url, f'{f.cvss_score:.1f}', owasp],
                cols, sev=f.severity.value, fill=(i % 2 == 1),
            )
        self.ln(3)

    def build_detailed_findings(self, findings: list[Finding]) -> None:
        self._section_title('5. Detailed Findings')
        if not findings:
            self._body('No findings were recorded for this scan.')
            return

        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            groups[f.owasp_category or 'Other'].append(f)

        for cat, group in sorted(groups.items()):
            name = group[0].owasp_name or cat
            self._sub_heading(f'{cat} - {name}')
            for f in group:
                self._finding_block(f)

    def _finding_block(self, f: Finding) -> None:
        # Header row
        self._sev_chip(f.severity.value)

        self.set_fill_color(240, 240, 240)
        self.set_text_color(50, 50, 50)
        self.set_font('Helvetica', 'B', 7)
        self.cell(26, 5, f'CVSS  {f.cvss_score:.1f}', fill=True, align='C',
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_fill_color(*_WHITE)

        # Priority badge
        pri_labels = {
            'critical': 'Immediate - 24-48h',
            'high':     'Urgent - 30 days',
            'medium':   'Scheduled - 90 days',
            'low':      'Long-term',
            'info':     'Advisory',
        }
        pri_colors = {
            'critical': (220,38,38), 'high': (234,88,12),
            'medium': (202,138,4),   'low':  (37,99,235), 'info': (107,114,128),
        }
        self.set_fill_color(*pri_colors.get(f.severity.value, (107,114,128)))
        self.set_text_color(*_WHITE)
        self.set_font('Helvetica', 'I', 7)
        self.cell(36, 5, pri_labels.get(f.severity.value, ''), fill=True, align='C',
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_fill_color(*_WHITE)
        self.set_text_color(0, 0, 0)

        self.set_font('Helvetica', 'B', 9)
        label = _VULN_LABELS.get(f.vuln_type, f.vuln_type)
        self.cell(0, 5, _safe(f'   {label}'), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

        # Metadata
        self._kv('URL',        f.affected_url,   mono=True)
        if f.affected_parameter:
            self._kv('Parameter', f.affected_parameter, mono=True)
        if f.cvss_vector:
            self._kv('CVSS Vector', f.cvss_vector, mono=True)
        self._kv('Confidence', f.confidence.value)

        # Compliance refs inline
        comp = _COMPLIANCE.get(f.vuln_type, {})
        if comp:
            self._kv('GDPR',      comp.get('gdpr', ''))
            self._kv('PCI DSS',   comp.get('pci_dss', ''))
            self._kv('ISO 27001', comp.get('iso27001', ''))
        self.ln(1)

        # Technical description
        desc = _VULN_DESC.get(f.vuln_type, '')
        if desc:
            self._body(desc)

        # Business impact box
        impact = _BUSINESS_IMPACT.get(f.vuln_type, '')
        if impact:
            self.set_fill_color(255, 248, 230)
            self.set_draw_color(202, 138, 4)
            self.set_font('Helvetica', 'B', 8)
            self.cell(0, 5, '  Business Impact', border='LT', fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font('Helvetica', '', 8)
            self.multi_cell(0, 4.5, _safe(f'  {impact}'), border='LB', fill=True,
                            new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_fill_color(*_WHITE)
            self.set_draw_color(*_LGRAY)
            self.ln(2)

        # Evidence
        if f.payload_used:
            self.set_font('Helvetica', 'B', 8)
            self.cell(0, 4, 'Payload Used', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self._code_block(f.payload_used)

        if f.evidence_request:
            self.set_font('Helvetica', 'B', 8)
            self.cell(0, 4, 'HTTP Request', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self._code_block(_trunc(f.evidence_request))

        if f.evidence_response:
            self.set_font('Helvetica', 'B', 8)
            self.cell(0, 4, 'HTTP Response', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self._code_block(_trunc(f.evidence_response))

        # Remediation steps (tailored per vuln type)
        rem_steps = _REMEDIATION_DETAIL.get(f.vuln_type, [])
        if not rem_steps and f.remediation:
            rem_steps = [s.strip() + '.' for s in f.remediation.split('. ') if s.strip()]

        if rem_steps:
            self.set_font('Helvetica', 'B', 8)
            self.cell(0, 4, 'Remediation Steps', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font('Helvetica', '', 8)
            for step in rem_steps:
                self.cell(5, 4, '', new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.multi_cell(0, 4, _safe(f'-  {step}'),
                                new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # OWASP Cheat Sheet link
        cs_url = _OWASP_CS_LINKS.get(f.vuln_type)
        if cs_url:
            self.ln(1)
            self.set_font('Helvetica', 'I', 7)
            self.set_text_color(37, 99, 235)
            self.cell(0, 4, f'OWASP Reference: {cs_url}', link=cs_url,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(0, 0, 0)

        # Divider
        self.ln(3)
        self.set_draw_color(*_LGRAY)
        self.line(20, self.get_y(), 190, self.get_y())
        self.ln(3)

    def build_methodology(self, config: dict) -> None:
        self._section_title('6. Methodology')
        self._body(
            'VulnScanner performs an automated black-box assessment modelled on the '
            'OWASP Testing Guide. A breadth-first crawler discovers all reachable pages, '
            'forms, and URL parameters. Detection modules then test every attack surface '
            'sequentially. Findings are scored with CVSS v3.1 and mapped to OWASP Top 10.'
        )

        self._sub_heading('Scan Configuration')
        self._kv('Tool',        'VulnScanner 1.0.0')
        self._kv('Target',      self._scan.target_url)
        self._kv('Crawl Depth', str(config.get('crawl_depth', 3)))
        self._kv('Max Pages',   str(config.get('max_pages', 500)))
        self._kv('Rate Limit',  '10 requests/second (token-bucket)')
        self._kv('HTTP Client', 'httpx async + Selenium WebDriver (DOM XSS)')
        self._kv('Scoring',     'CVSS v3.1 Base Score')
        self.ln(2)

        self._sub_heading('Detection Modules')
        for key in config.get('modules', []):
            desc = _MODULE_DESC.get(key, key)
            self.set_font('Helvetica', '', 9)
            self.cell(5, 5, '', new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(0, 5, _safe(f'-  {desc}'), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def build_next_steps(self) -> None:
        self._section_title('7. Next Steps')
        steps = [
            ('1. Remediate in priority order',
             'Fix Critical findings immediately, High within 30 days. Use the '
             'evidence in Section 5 to reproduce and verify each issue. Confirm '
             'fixes with the developer before closing.'),
            ('2. Re-scan after each fix batch',
             'Run a VulnScanner assessment after each remediation batch to verify '
             'fixes and catch any regressions. Target a clean scan before major releases.'),
            ('3. Integrate into CI/CD',
             'Add automated DAST scanning to your pipeline. Block deployments on '
             'Critical findings; alert on High. This prevents regressions from reaching '
             'production.'),
            ('4. Commission manual penetration testing',
             'Automated scanning cannot detect business-logic flaws or chained '
             'vulnerabilities. Engage a qualified tester annually or after major changes.'),
            ('5. Implement Secure Development Lifecycle',
             'Introduce security code reviews, threat modelling, and developer security '
             'training. Use a WAF as a compensating control while fixes are developed.'),
        ]
        for title, desc in steps:
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(*_NAVY)
            self.cell(0, 5, _safe(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(0, 0, 0)
            self._body(desc)

    def build_disclaimer(self) -> None:
        self._section_title('8. Disclaimer')
        self._body(
            'This assessment was performed with the explicit authorisation of the '
            'target system owner. VulnScanner is intended solely for authorised '
            'security assessment. Unauthorised use may violate the Computer Misuse '
            'Act 1990 (UK), Myanmar Electronic Transactions Law 2004, and equivalent '
            'legislation in other jurisdictions.\n\n'
            'This report is CONFIDENTIAL. Findings represent the state of the target '
            'at the time of the scan. Automated tools cannot substitute for expert '
            'manual review.\n\n'
            'VulnScanner 1.0.0 | CET300 Final Year Project | '
            'University of Sunderland (via BUC, Myanmar) | Author: Hein Htet Zaw'
        )


# ── Public API ────────────────────────────────────────────────────────────────

async def generate_pdf(scan: Scan, findings: list[Finding]) -> bytes:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _build, scan, findings)


def _build(scan: Scan, findings: list[Finding]) -> bytes:
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    sorted_findings = sorted(findings, key=lambda f: f.cvss_score, reverse=True)

    pdf = _ReportPDF(scan)
    pdf.build_cover(sev_counts)
    pdf.build_management_summary(sev_counts, sorted_findings)
    pdf.add_page()
    pdf.build_executive_summary(sev_counts)
    pdf.build_remediation_plan(sorted_findings)
    pdf.build_compliance_mapping(sorted_findings)
    pdf.build_findings_summary(sorted_findings)
    pdf.add_page()
    pdf.build_detailed_findings(sorted_findings)
    pdf.add_page()
    pdf.build_methodology(scan.config or {})
    pdf.build_next_steps()
    pdf.build_disclaimer()

    return bytes(pdf.output())
