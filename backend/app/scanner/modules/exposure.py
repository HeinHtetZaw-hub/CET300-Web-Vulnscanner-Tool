"""Sensitive data exposure detection module.

Scans the response body of every crawled page against a library of regex patterns
for common secret and credential types:

  • AWS Access Key IDs          (AKIA…)
  • Stripe live secret keys     (sk_live_…)
  • Generic API keys            (key-…)
  • PEM private key headers     (-----BEGIN RSA/DSA/EC/OPENSSH PRIVATE KEY-----)
  • Pre-filled HTML password inputs  (<input type="password" value="…">)
  • Database connection strings (mongodb://, postgresql://, mysql://, redis://)
  • JSON Web Tokens             (eyJ….eyJ….…)
  • RFC-1918 internal IP addresses (10.x, 172.16-31.x, 192.168.x)

Matched secrets are REDACTED in stored evidence — the finding shows only the
first four characters followed by ****. Internal IPs and PEM headers are not
redacted because the match itself is the evidence, not a secret value.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.base import BaseModule, RawFinding
from app.utils.http_client import RateLimitedClient, ScannerHTTPError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------


@dataclass
class _Pattern:
    name: str           # short key used for deduplication
    description: str    # human-readable label stored in the finding
    regex: re.Pattern   # compiled regular expression
    redact: bool        # whether to redact matched text in evidence
    confidence: str = field(default="confirmed")


_PATTERNS: list[_Pattern] = [
    _Pattern(
        name="aws_access_key",
        description="AWS Access Key ID",
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
        redact=True,
    ),
    _Pattern(
        name="stripe_secret_key",
        description="Stripe Live Secret Key",
        regex=re.compile(r"sk_live_[a-zA-Z0-9]{24}"),
        redact=True,
    ),
    _Pattern(
        name="generic_api_key",
        description="Generic API Key (key- prefix)",
        regex=re.compile(r"key-[a-zA-Z0-9]{32}"),
        redact=True,
    ),
    _Pattern(
        name="private_key_pem",
        description="PEM Private Key Header",
        regex=re.compile(
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
        ),
        redact=False,
    ),
    _Pattern(
        name="prefilled_password",
        description="Pre-filled HTML Password Input",
        # Lookahead confirms type="password" is present anywhere in the tag;
        # capturing group 1 holds the pre-filled value (the actual secret).
        regex=re.compile(
            r"<input(?=[^>]*\btype=[\"']password[\"'])[^>]*\bvalue=[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        redact=True,
    ),
    _Pattern(
        name="connection_string",
        description="Database Connection String",
        regex=re.compile(
            r"(?:mongodb|postgresql|mysql|redis)://[^\s<>\"']{3,}",
            re.IGNORECASE,
        ),
        redact=True,
    ),
    _Pattern(
        name="jwt_token",
        description="JSON Web Token (JWT)",
        regex=re.compile(
            r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
        ),
        redact=True,
    ),
    _Pattern(
        name="internal_ip_class_a",
        description="Internal IP Address (10.x.x.x)",
        regex=re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        redact=False,
        confidence="tentative",
    ),
    _Pattern(
        name="internal_ip_class_b",
        description="Internal IP Address (172.16–31.x.x)",
        regex=re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
        redact=False,
        confidence="tentative",
    ),
    _Pattern(
        name="internal_ip_class_c",
        description="Internal IP Address (192.168.x.x)",
        regex=re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        redact=False,
        confidence="tentative",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redact(text: str) -> str:
    """Return the first 4 characters of *text* followed by ****."""
    return text[:4] + "****" if len(text) > 4 else "****"


def _display_match(match: re.Match, redact: bool) -> str:
    """Return the match string with the sensitive portion redacted if requested.

    When the pattern has a capturing group, only that group is redacted and
    it is substituted back into the full match string (e.g. password inputs).
    """
    if not redact:
        return match.group(0)
    try:
        secret = match.group(1)
        if secret is not None:
            return match.group(0).replace(secret, _redact(secret), 1)
    except IndexError:
        pass
    return _redact(match.group(0))


def _req_evidence(url: str) -> str:
    p = urlparse(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    return f"GET {path} HTTP/1.1\nHost: {p.netloc}"


def _resp_evidence(
    response: httpx.Response,
    body: str,
    match: re.Match,
    pattern: _Pattern,
) -> str:
    displayed = _display_match(match, pattern.redact)

    start, end = match.span()
    ctx_start = max(0, start - 60)
    ctx_end = min(len(body), end + 60)
    snippet = body[ctx_start:ctx_end]
    if pattern.redact:
        snippet = snippet.replace(match.group(0), displayed, 1)

    try:
        status_line = f"HTTP/1.1 {response.status_code} {response.reason_phrase}"
    except Exception:
        status_line = f"HTTP/1.1 {response.status_code}"

    return (
        f"{status_line}\n\n"
        f"Pattern  : {pattern.description}\n"
        f"Match    : {displayed}\n\n"
        f"Context  :\n{snippet}"
    )


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class ExposureModule(BaseModule):
    """Scans every crawled page body for leaked secrets and internal addresses."""

    @property
    def name(self) -> str:
        return "Sensitive Data Exposure"

    @property
    def vuln_types(self) -> list[str]:
        return ["data_exposure"]

    async def run(
        self,
        target_urls: set[str],
        forms: list[FormData],
        parameters: list[ParameterData],
        http_client: RateLimitedClient,
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []

        for url in target_urls:
            try:
                response = await http_client.get(url)
                body = response.text
            except (ScannerHTTPError, Exception):
                logger.debug("Exposure: could not fetch %s", url)
                continue

            # Report the first occurrence of each pattern type per URL.
            reported: set[str] = set()

            for pattern in _PATTERNS:
                if pattern.name in reported:
                    continue

                match = pattern.regex.search(body)
                if match is None:
                    continue

                reported.add(pattern.name)
                findings.append(
                    RawFinding(
                        vuln_type="data_exposure",
                        affected_url=url,
                        affected_parameter=pattern.description,
                        payload_used=f"[regex] {pattern.description}",
                        evidence_request=_req_evidence(url),
                        evidence_response=_resp_evidence(response, body, match, pattern),
                        confidence=pattern.confidence,
                    )
                )

        return findings
