"""Security misconfiguration detection module.

Two detection strategies run in sequence:

1. HEADER CHECKS
   Samples up to 10 crawled URLs and checks each response for the six
   mandatory security headers.  Results are deduplicated: each missing header
   type produces at most one finding, recorded against the first URL that
   exposed the gap.

2. EXPOSED FILE CHECKS
   Probes 19 well-known sensitive paths from the site root.
   A path is only reported when:
     • The server returns HTTP 200 with non-empty content, AND
     • The body passes a content-specific validator (e.g., KEY=VALUE for .env
       files, or 'ref: refs/heads/' for .git/HEAD).
"""
from __future__ import annotations

import itertools
import logging
import re
from urllib.parse import urlparse

import httpx

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.base import BaseModule, RawFinding
from app.utils.http_client import RateLimitedClient, ScannerHTTPError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security header definitions
# ---------------------------------------------------------------------------

_SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

_MAX_HEADER_SAMPLE: int = 10   # maximum URLs to fetch for header auditing

# ---------------------------------------------------------------------------
# Sensitive file paths
#
# Each tuple: (path_from_root, content_check_type)
#   "any"       — 200 + non-empty body → finding
#   "env"       — body must contain KEY=VALUE lines
#   "git_head"  — body must start with 'ref: refs/heads/'
#   "git_config"— body must contain '[core]' or '[remote'
#   "robots"    — body must have Disallow entries that reveal sensitive paths
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS: list[tuple[str, str]] = [
    ("/.env",             "env"),
    ("/.env.local",       "env"),
    ("/.env.production",  "env"),
    ("/.git/HEAD",        "git_head"),
    ("/.git/config",      "git_config"),
    ("/backup.sql",       "any"),
    ("/database.sql",     "any"),
    ("/dump.sql",         "any"),
    ("/config.php",       "any"),
    ("/config.php.bak",   "any"),
    ("/wp-config.php",    "any"),
    ("/phpinfo.php",      "any"),
    ("/server-status",    "any"),
    ("/server-info",      "any"),
    ("/.htaccess",        "any"),
    ("/.htpasswd",        "any"),
    ("/robots.txt",       "robots"),
    ("/sitemap.xml",      "any"),
    ("/crossdomain.xml",  "any"),
]

# .env: one or more lines of the form KEY=VALUE (or KEY=)
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE)

# robots.txt: Disallow entries whose path contains a sensitive keyword
_ROBOTS_SENSITIVE_RE = re.compile(
    r"Disallow:\s*/\S*"
    r"(?:admin|api|private|internal|config|backup|database|"
    r"wp-admin|wp-login|phpmyadmin|cpanel|manage|secret|"
    r"token|key|auth|login|register|dashboard|settings|"
    r"panel|console|upload|staging|dev|test)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _site_root(target_urls: set[str]) -> str | None:
    """Return 'scheme://host' extracted from any URL in the set."""
    if not target_urls:
        return None
    parsed = urlparse(next(iter(target_urls)))
    return f"{parsed.scheme}://{parsed.netloc}"


def _missing_headers(response: httpx.Response) -> list[str]:
    """Return the names of required security headers absent from *response*."""
    present = {h.lower() for h in response.headers}
    return [h for h in _SECURITY_HEADERS if h.lower() not in present]


def _validate_file_content(path: str, body: str, check: str) -> bool:
    """Return True if *body* is meaningful evidence of a misconfiguration."""
    if not body.strip():
        return False
    if check == "any":
        return True
    if check == "env":
        return bool(_ENV_RE.search(body))
    if check == "git_head":
        return body.strip().startswith("ref: refs/heads/")
    if check == "git_config":
        return "[core]" in body or "[remote" in body
    if check == "robots":
        return bool(_ROBOTS_SENSITIVE_RE.search(body))
    return True


def _req_evidence(url: str, method: str = "GET") -> str:
    p = urlparse(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    return f"{method} {path} HTTP/1.1\nHost: {p.netloc}"


def _resp_evidence(response: httpx.Response, note: str = "") -> str:
    try:
        body_snippet = response.text[:400]
    except Exception:
        body_snippet = "[binary content]"
    keep = {"content-type", "server", "x-powered-by"}
    headers_str = "\n".join(
        f"{k}: {v}" for k, v in response.headers.items() if k.lower() in keep
    )
    prefix = f"[{note}]\n\n" if note else ""
    return (
        f"{prefix}HTTP/1.1 {response.status_code} {response.reason_phrase}"
        f"\n{headers_str}\n\n{body_snippet}"
    )


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class MisconfigModule(BaseModule):
    """Detects missing security headers and exposed sensitive files."""

    @property
    def name(self) -> str:
        return "Security Misconfiguration"

    @property
    def vuln_types(self) -> list[str]:
        return ["misconfig_header", "misconfig_file"]

    async def run(
        self,
        target_urls: set[str],
        forms: list[FormData],
        parameters: list[ParameterData],
        http_client: RateLimitedClient,
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        findings.extend(await self._check_headers(target_urls, http_client))
        findings.extend(await self._check_exposed_files(target_urls, http_client))
        return findings

    # ------------------------------------------------------------------
    # Header audit
    # ------------------------------------------------------------------

    async def _check_headers(
        self, target_urls: set[str], http_client: RateLimitedClient
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        reported: set[str] = set()   # header names already recorded

        for url in itertools.islice(target_urls, _MAX_HEADER_SAMPLE):
            try:
                response = await http_client.get(url)
            except ScannerHTTPError:
                logger.debug("Misconfig: could not fetch %s for header check", url)
                continue

            for header in _missing_headers(response):
                if header in reported:
                    continue
                reported.add(header)
                findings.append(
                    RawFinding(
                        vuln_type="misconfig_header",
                        affected_url=url,
                        affected_parameter=header,
                        payload_used=f"[header absent] {header}",
                        evidence_request=_req_evidence(url),
                        evidence_response=_resp_evidence(
                            response,
                            note=f"Security header '{header}' is missing from this response",
                        ),
                        confidence="confirmed",
                    )
                )

            if len(reported) == len(_SECURITY_HEADERS):
                break   # all headers accounted for — no need to check more URLs

        return findings

    # ------------------------------------------------------------------
    # Exposed file audit
    # ------------------------------------------------------------------

    async def _check_exposed_files(
        self, target_urls: set[str], http_client: RateLimitedClient
    ) -> list[RawFinding]:
        root = _site_root(target_urls)
        if not root:
            return []

        findings: list[RawFinding] = []

        for path, check in _SENSITIVE_PATHS:
            probe_url = root + path
            try:
                response = await http_client.get(probe_url)
            except ScannerHTTPError:
                logger.debug("Misconfig: probe failed for %s", probe_url)
                continue

            if response.status_code != 200:
                continue

            try:
                body = response.text
            except Exception:
                continue

            if not _validate_file_content(path, body, check):
                continue

            findings.append(
                RawFinding(
                    vuln_type="misconfig_file",
                    affected_url=probe_url,
                    affected_parameter=path,
                    payload_used=probe_url,
                    evidence_request=_req_evidence(probe_url),
                    evidence_response=_resp_evidence(response),
                    confidence="confirmed",
                )
            )

        return findings
