"""Reflected XSS detection module.

Strategy per parameter:
  1. Inject a unique alphanumeric canary to check whether the parameter is reflected.
  2. If the canary appears unencoded in the response, escalate to actual XSS payloads.
  3. A full payload reflected unencoded → confirmed.
     Canary reflected but all payloads are filtered/encoded → tentative.
"""
from __future__ import annotations

import logging
import random
import string
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.base import BaseModule, RawFinding
from app.utils.http_client import RateLimitedClient, ScannerHTTPError

logger = logging.getLogger(__name__)

_PAYLOAD_FILE = Path(__file__).parent.parent / "payloads" / "xss.txt"

_SKIP_INPUT_TYPES = frozenset(
    {"submit", "button", "image", "reset", "hidden", "checkbox", "radio", "file"}
)


def _load_payloads() -> list[str]:
    if not _PAYLOAD_FILE.exists():
        logger.warning("XSS payload file not found: %s", _PAYLOAD_FILE)
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\" onfocus=alert('XSS') autofocus=\"",
            "javascript:alert('XSS')",
        ]
    lines = _PAYLOAD_FILE.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def _generate_canary() -> str:
    """Return a unique 11-char marker: 'xSs' + 8 random alphanumeric chars."""
    suffix = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"xSs{suffix}"


def _inject_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[name] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _detect_context(html: str, marker: str) -> str:
    """Locate where *marker* appears in *html* and return the context label.

    Priority: 'script' > 'attribute' > 'body' > 'unknown'.
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        for script in soup.find_all("script"):
            if marker in (script.string or ""):
                return "script"
        for tag in soup.find_all(True):
            for val in tag.attrs.values():
                if isinstance(val, list):
                    val = " ".join(val)
                if marker in str(val):
                    return "attribute"
        if marker in soup.get_text():
            return "body"
    except Exception:
        pass
    return "unknown"


def _req_evidence(method: str, url: str, data: dict | None = None) -> str:
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


def _resp_evidence(response: httpx.Response) -> str:
    try:
        body_snippet = response.text[:500]
    except Exception:
        body_snippet = "[binary content]"
    keep = {"content-type", "server", "x-powered-by"}
    headers = "\n".join(
        f"{k}: {v}" for k, v in response.headers.items() if k.lower() in keep
    )
    return f"HTTP/1.1 {response.status_code} {response.reason_phrase}\n{headers}\n\n{body_snippet}"


class ReflectedXSSModule(BaseModule):
    """Canary-first reflected XSS scanner with context-aware payload escalation."""

    def __init__(self) -> None:
        self._payloads = _load_payloads()

    @property
    def name(self) -> str:
        return "Reflected XSS"

    @property
    def vuln_types(self) -> list[str]:
        return ["xss_reflected"]

    async def run(
        self,
        target_urls: set[str],
        forms: list[FormData],
        parameters: list[ParameterData],
        http_client: RateLimitedClient,
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []

        for param in parameters:
            if param.param_location == "query":
                result = await self._test_url_param(param, http_client)
                if result:
                    findings.append(result)

        for form in forms:
            for inp in form.inputs:
                if inp.type in _SKIP_INPUT_TYPES:
                    continue
                result = await self._test_form_input(form, inp.name, http_client)
                if result:
                    findings.append(result)

        return findings

    # ------------------------------------------------------------------
    # URL parameter path
    # ------------------------------------------------------------------

    async def _test_url_param(
        self, param: ParameterData, client: RateLimitedClient
    ) -> RawFinding | None:
        canary = _generate_canary()
        canary_url = _inject_param(param.url, param.param_name, canary)

        try:
            canary_resp = await client.get(canary_url)
            body = canary_resp.text
        except (ScannerHTTPError, Exception):
            return None

        if canary not in body:
            return None

        context = _detect_context(body, canary)

        for payload in self._payloads:
            payload_url = _inject_param(param.url, param.param_name, payload)
            try:
                payload_resp = await client.get(payload_url)
                payload_body = payload_resp.text
            except (ScannerHTTPError, Exception):
                continue
            if payload in payload_body:
                return RawFinding(
                    vuln_type="xss_reflected",
                    affected_url=param.url,
                    affected_parameter=param.param_name,
                    payload_used=payload,
                    evidence_request=_req_evidence("GET", payload_url),
                    evidence_response=_resp_evidence(payload_resp),
                    confidence="confirmed",
                )

        return RawFinding(
            vuln_type="xss_reflected",
            affected_url=param.url,
            affected_parameter=param.param_name,
            payload_used=f"[canary] {canary} (context: {context})",
            evidence_request=_req_evidence("GET", canary_url),
            evidence_response=_resp_evidence(canary_resp),
            confidence="tentative",
        )

    # ------------------------------------------------------------------
    # Form input path
    # ------------------------------------------------------------------

    async def _test_form_input(
        self, form: FormData, target_input: str, client: RateLimitedClient
    ) -> RawFinding | None:
        base = {inp.name: inp.value for inp in form.inputs if inp.name}
        method = form.method.upper()
        url = form.action_url
        canary = _generate_canary()

        try:
            if method == "POST":
                canary_resp = await client.post(url, data={**base, target_input: canary})
                canary_req_ev = _req_evidence("POST", url, {**base, target_input: canary})
            else:
                canary_url = _inject_param(url, target_input, canary)
                canary_resp = await client.get(canary_url)
                canary_req_ev = _req_evidence("GET", canary_url)
            body = canary_resp.text
        except (ScannerHTTPError, Exception):
            return None

        if canary not in body:
            return None

        context = _detect_context(body, canary)

        for payload in self._payloads:
            data = {**base, target_input: payload}
            try:
                if method == "POST":
                    payload_resp = await client.post(url, data=data)
                    req_ev = _req_evidence("POST", url, data)
                else:
                    p_url = _inject_param(url, target_input, payload)
                    payload_resp = await client.get(p_url)
                    req_ev = _req_evidence("GET", p_url)
                payload_body = payload_resp.text
            except (ScannerHTTPError, Exception):
                continue
            if payload in payload_body:
                return RawFinding(
                    vuln_type="xss_reflected",
                    affected_url=form.action_url,
                    affected_parameter=target_input,
                    payload_used=payload,
                    evidence_request=req_ev,
                    evidence_response=_resp_evidence(payload_resp),
                    confidence="confirmed",
                )

        return RawFinding(
            vuln_type="xss_reflected",
            affected_url=form.action_url,
            affected_parameter=target_input,
            payload_used=f"[canary] {canary} (context: {context})",
            evidence_request=canary_req_ev,
            evidence_response=_resp_evidence(canary_resp),
            confidence="tentative",
        )
