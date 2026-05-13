"""Broken Access Control detection module.

Phase 8.1 — IDOR (Insecure Direct Object Reference):
  Crawled URLs that contain numeric path segments are probed with adjacent IDs.
  If an adjacent ID returns HTTP 200 with meaningfully different content, the
  resource is accessible without proper authorisation checks.
  All IDOR findings are 'tentative' — confirmation requires an authenticated
  session to prove cross-user data access.

Phase 8.2 — SSRF (Server-Side Request Forgery):
  Parameters and form inputs whose names commonly accept URLs are injected with
  internal addresses (127.0.0.1, localhost, AWS metadata endpoint, IPv6 loopback,
  and common internal service ports).  The response body is scanned for known
  service banners or connection-error messages that indicate the server made an
  outbound request on behalf of the attacker.
  Findings are 'confirmed' when specific internal-service content is found, and
  'tentative' when the server's error output suggests it attempted the connection.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.base import BaseModule, RawFinding
from app.utils.http_client import RateLimitedClient, ScannerHTTPError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IDOR — numeric path-segment constants
# ---------------------------------------------------------------------------

# Matches a purely-numeric path segment preceded by '/'.
# Counter-example: /api/v1/ — '1' follows 'v', not '/', so NOT matched.
_NUMERIC_SEG_RE = re.compile(r"(?<=/)\d+(?=/|$)")

_ADJACENT_OFFSETS: list[int] = [1, 2, -1]

# Minimum body-length difference (bytes) to flag responses as "meaningfully different"
_MIN_DIFF_BYTES = 50

# ---------------------------------------------------------------------------
# SSRF — parameter-name allowlist and probe payloads
# ---------------------------------------------------------------------------

_SSRF_PARAM_NAMES: frozenset[str] = frozenset({
    "url", "redirect", "next", "return", "callback", "link", "src", "dest",
    "uri", "path", "continue", "return_to", "go", "checkout_url", "image_url",
})

_SSRF_PROBES: list[str] = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
]

# Response patterns that prove the server fetched an internal resource
_SSRF_CONFIRMED_PATTERNS: list[str] = [
    "ami-id",               # AWS EC2 metadata
    "instance-type",
    "security-credentials",
    "169.254.169.254",      # Raw metadata IP reflected back
    "SSH-2.0-",             # SSH service banner
    "SSH-1.",
    "mysql_native_password", # MySQL handshake
    "+PONG",                # Redis PING response
]

# Response patterns suggesting the server attempted an outbound connection
_SSRF_TENTATIVE_PATTERNS: list[str] = [
    "connection refused",
    "econnrefused",
    "could not connect to",
    "failed to connect",
    "network is unreachable",
    "no route to host",
    "connection timed out",
    "timed out after",
    "unable to connect",
    "socket error",
    "curl error",
    "getaddrinfo failed",
    "could not resolve",
]

# Input types that are never URL sinks
_SKIP_INPUT_TYPES: frozenset[str] = frozenset({
    "submit", "button", "image", "reset", "hidden", "checkbox", "radio", "file",
    "number", "range", "date", "time", "datetime-local", "month", "week", "color",
})


# ---------------------------------------------------------------------------
# IDOR helpers
# ---------------------------------------------------------------------------


def _numeric_segments(path: str) -> list[tuple[str, int]]:
    """Return ``(value, start_index_in_path)`` for every numeric segment in *path*."""
    return [(m.group(), m.start()) for m in _NUMERIC_SEG_RE.finditer(path)]


def _probe_url(original_url: str, seg_value: str, seg_start: int, new_id: int) -> str:
    """Return *original_url* with the numeric segment at *seg_start* replaced by *new_id*."""
    parsed = urlparse(original_url)
    path = parsed.path
    new_path = path[:seg_start] + str(new_id) + path[seg_start + len(seg_value):]
    return urlunparse(parsed._replace(path=new_path))


def _content_differs(r_orig: httpx.Response, r_probe: httpx.Response) -> bool:
    """True when the two responses have different content (more than minor variation)."""
    try:
        orig = r_orig.text
        probe = r_probe.text
        if orig == probe:
            return False
        return abs(len(orig) - len(probe)) > _MIN_DIFF_BYTES
    except Exception:
        return False


def _req_evidence(url: str) -> str:
    p = urlparse(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    return f"GET {path} HTTP/1.1\nHost: {p.netloc}"


def _resp_evidence(
    original_url: str,
    original_resp: httpx.Response,
    probe_url: str,
    probe_resp: httpx.Response,
) -> str:
    def _snippet(resp: httpx.Response) -> str:
        try:
            return resp.text[:300]
        except Exception:
            return "[unreadable]"

    return (
        f"[Original] {original_url}\n"
        f"Status: {original_resp.status_code}  Length: {len(original_resp.content)} bytes\n"
        f"{_snippet(original_resp)}\n\n"
        f"[Probe] {probe_url}\n"
        f"Status: {probe_resp.status_code}  Length: {len(probe_resp.content)} bytes\n"
        f"{_snippet(probe_resp)}"
    )


# ---------------------------------------------------------------------------
# SSRF helpers
# ---------------------------------------------------------------------------


def _is_ssrf_param(name: str) -> bool:
    """True when the parameter name is a known URL-accepting sink."""
    return name.lower() in _SSRF_PARAM_NAMES


def _inject_query_param(url: str, name: str, value: str) -> str:
    """Return *url* with query parameter *name* set to *value*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[name] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _check_ssrf_response(body: str) -> str | None:
    """Return 'confirmed', 'tentative', or None based on SSRF indicators in *body*."""
    lower = body.lower()
    if any(p.lower() in lower for p in _SSRF_CONFIRMED_PATTERNS):
        return "confirmed"
    if any(p.lower() in lower for p in _SSRF_TENTATIVE_PATTERNS):
        return "tentative"
    return None


def _ssrf_req_evidence(method: str, url: str, data: dict | None = None) -> str:
    p = urlparse(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    lines = [f"{method} {path} HTTP/1.1", f"Host: {p.netloc}"]
    if data:
        body = urlencode(data)
        lines += [
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            "",
            body,
        ]
    return "\n".join(lines)


def _ssrf_resp_evidence(response: httpx.Response) -> str:
    try:
        body_snippet = response.text[:500]
    except Exception:
        body_snippet = "[unreadable]"
    keep = {"content-type", "server", "x-powered-by"}
    headers = "\n".join(
        f"{k}: {v}" for k, v in response.headers.items() if k.lower() in keep
    )
    return f"HTTP/1.1 {response.status_code} {response.reason_phrase}\n{headers}\n\n{body_snippet}"


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class BACModule(BaseModule):
    """Broken Access Control: IDOR via adjacent numeric ID enumeration + SSRF detection."""

    @property
    def name(self) -> str:
        return "Broken Access Control"

    @property
    def vuln_types(self) -> list[str]:
        return ["idor", "ssrf"]

    async def run(
        self,
        target_urls: set[str],
        forms: list[FormData],
        parameters: list[ParameterData],
        http_client: RateLimitedClient,
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        findings.extend(await self._run_idor(target_urls, http_client))
        findings.extend(await self._run_ssrf(forms, parameters, http_client))
        return findings

    # ------------------------------------------------------------------
    # IDOR
    # ------------------------------------------------------------------

    async def _run_idor(
        self, target_urls: set[str], http_client: RateLimitedClient
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []

        for url in target_urls:
            parsed = urlparse(url)
            segments = _numeric_segments(parsed.path)
            if not segments:
                continue

            try:
                original_resp = await http_client.get(url)
            except ScannerHTTPError:
                logger.debug("IDOR: could not fetch original %s", url)
                continue

            if original_resp.status_code != 200:
                continue

            for seg_value, seg_start in segments:
                original_id = int(seg_value)
                found_for_segment = False

                for offset in _ADJACENT_OFFSETS:
                    if found_for_segment:
                        break

                    new_id = original_id + offset
                    if new_id <= 0:
                        continue

                    probed = _probe_url(url, seg_value, seg_start, new_id)

                    try:
                        probe_resp = await http_client.get(probed)
                    except ScannerHTTPError:
                        logger.debug("IDOR: probe failed for %s", probed)
                        continue

                    if probe_resp.status_code != 200:
                        continue

                    if not _content_differs(original_resp, probe_resp):
                        continue

                    findings.append(
                        RawFinding(
                            vuln_type="idor",
                            affected_url=url,
                            affected_parameter=f"path:{seg_value}",
                            payload_used=probed,
                            evidence_request=_req_evidence(probed),
                            evidence_response=_resp_evidence(
                                url, original_resp, probed, probe_resp
                            ),
                            confidence="tentative",
                        )
                    )
                    found_for_segment = True

        return findings

    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------

    async def _run_ssrf(
        self,
        forms: list[FormData],
        parameters: list[ParameterData],
        http_client: RateLimitedClient,
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []

        for param in parameters:
            if param.param_location == "query" and _is_ssrf_param(param.param_name):
                result = await self._test_ssrf_url_param(param, http_client)
                if result:
                    findings.append(result)

        for form in forms:
            for inp in form.inputs:
                if inp.type in _SKIP_INPUT_TYPES:
                    continue
                if _is_ssrf_param(inp.name):
                    result = await self._test_ssrf_form_input(form, inp.name, http_client)
                    if result:
                        findings.append(result)

        return findings

    async def _test_ssrf_url_param(
        self, param: ParameterData, client: RateLimitedClient
    ) -> RawFinding | None:
        best_finding: RawFinding | None = None

        for probe in _SSRF_PROBES:
            injected = _inject_query_param(param.url, param.param_name, probe)
            try:
                resp = await client.get(injected)
                body = resp.text
            except (ScannerHTTPError, Exception):
                continue

            confidence = _check_ssrf_response(body)
            if confidence == "confirmed":
                return RawFinding(
                    vuln_type="ssrf",
                    affected_url=param.url,
                    affected_parameter=param.param_name,
                    payload_used=probe,
                    evidence_request=_ssrf_req_evidence("GET", injected),
                    evidence_response=_ssrf_resp_evidence(resp),
                    confidence="confirmed",
                )
            if confidence == "tentative" and best_finding is None:
                best_finding = RawFinding(
                    vuln_type="ssrf",
                    affected_url=param.url,
                    affected_parameter=param.param_name,
                    payload_used=probe,
                    evidence_request=_ssrf_req_evidence("GET", injected),
                    evidence_response=_ssrf_resp_evidence(resp),
                    confidence="tentative",
                )

        return best_finding

    async def _test_ssrf_form_input(
        self, form: FormData, target_input: str, client: RateLimitedClient
    ) -> RawFinding | None:
        base = {inp.name: inp.value for inp in form.inputs if inp.name}
        method = form.method.upper()
        url = form.action_url
        best_finding: RawFinding | None = None

        for probe in _SSRF_PROBES:
            data = {**base, target_input: probe}
            try:
                if method == "POST":
                    resp = await client.post(url, data=data)
                    req_ev = _ssrf_req_evidence("POST", url, data)
                else:
                    injected = _inject_query_param(url, target_input, probe)
                    resp = await client.get(injected)
                    req_ev = _ssrf_req_evidence("GET", injected)
                body = resp.text
            except (ScannerHTTPError, Exception):
                continue

            confidence = _check_ssrf_response(body)
            if confidence == "confirmed":
                return RawFinding(
                    vuln_type="ssrf",
                    affected_url=form.action_url,
                    affected_parameter=target_input,
                    payload_used=probe,
                    evidence_request=req_ev,
                    evidence_response=_ssrf_resp_evidence(resp),
                    confidence="confirmed",
                )
            if confidence == "tentative" and best_finding is None:
                best_finding = RawFinding(
                    vuln_type="ssrf",
                    affected_url=form.action_url,
                    affected_parameter=target_input,
                    payload_used=probe,
                    evidence_request=req_ev,
                    evidence_response=_ssrf_resp_evidence(resp),
                    confidence="tentative",
                )

        return best_finding
