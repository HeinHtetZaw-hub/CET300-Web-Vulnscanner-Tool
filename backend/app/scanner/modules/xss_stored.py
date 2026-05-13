"""Stored XSS detection module.

Strategy:
  1. For each POST form, pick one injectable input at a time.
  2. Submit the form with a unique marker payload in that input.
     Marker format: <script>/*xSsStored_<12-hex-chars>*/</script>
     The 12-char UUID suffix makes each submission identifiable even if multiple
     forms share the same output page.
  3. Check the submission response first (some apps immediately render new content).
  4. Then re-fetch every URL the crawler discovered and look for the marker.
  5. If the marker appears unencoded → confirmed stored XSS.
"""
from __future__ import annotations

import logging
import uuid
from urllib.parse import urlencode, urlparse

import httpx

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.base import BaseModule, RawFinding
from app.utils.http_client import RateLimitedClient, ScannerHTTPError

logger = logging.getLogger(__name__)

_SKIP_INPUT_TYPES = frozenset(
    {"submit", "button", "image", "reset", "hidden", "checkbox", "radio", "file"}
)


def _generate_marker() -> str:
    """Return a unique stored XSS marker: <script>/*xSsStored_<12hex>*/</script>."""
    uid = uuid.uuid4().hex[:12]
    return f"<script>/*xSsStored_{uid}*/</script>"


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


def _resp_evidence(response: httpx.Response, *, display_url: str = "") -> str:
    try:
        body_snippet = response.text[:500]
    except Exception:
        body_snippet = "[binary content]"
    keep = {"content-type", "server", "x-powered-by"}
    headers = "\n".join(
        f"{k}: {v}" for k, v in response.headers.items() if k.lower() in keep
    )
    prefix = f"[Marker found at: {display_url}]\n\n" if display_url else ""
    return (
        f"{prefix}HTTP/1.1 {response.status_code} {response.reason_phrase}"
        f"\n{headers}\n\n{body_snippet}"
    )


class StoredXSSModule(BaseModule):
    """Submits unique markers into POST forms, then scans crawled pages for persistence."""

    @property
    def name(self) -> str:
        return "Stored XSS"

    @property
    def vuln_types(self) -> list[str]:
        return ["xss_stored"]

    async def run(
        self,
        target_urls: set[str],
        forms: list[FormData],
        parameters: list[ParameterData],
        http_client: RateLimitedClient,
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for form in forms:
            if form.method.upper() != "POST":
                continue
            for inp in form.inputs:
                if inp.type in _SKIP_INPUT_TYPES:
                    continue
                result = await self._test_form_input(form, inp.name, target_urls, http_client)
                if result:
                    findings.append(result)
        return findings

    async def _test_form_input(
        self,
        form: FormData,
        target_input: str,
        target_urls: set[str],
        client: RateLimitedClient,
    ) -> RawFinding | None:
        base = {inp.name: inp.value for inp in form.inputs if inp.name}
        marker = _generate_marker()
        data = {**base, target_input: marker}
        req_ev = _req_evidence("POST", form.action_url, data)

        try:
            submit_resp = await client.post(form.action_url, data=data)
        except ScannerHTTPError:
            return None

        # 1. Check if marker appears in the submission response itself.
        try:
            if marker in submit_resp.text:
                return RawFinding(
                    vuln_type="xss_stored",
                    affected_url=form.action_url,
                    affected_parameter=target_input,
                    payload_used=marker,
                    evidence_request=req_ev,
                    evidence_response=_resp_evidence(submit_resp),
                    confidence="confirmed",
                )
        except Exception:
            pass

        # 2. Re-fetch every crawled page and check for the marker.
        for url in target_urls:
            try:
                resp = await client.get(url)
                if marker in resp.text:
                    return RawFinding(
                        vuln_type="xss_stored",
                        affected_url=form.action_url,
                        affected_parameter=target_input,
                        payload_used=marker,
                        evidence_request=req_ev,
                        evidence_response=_resp_evidence(resp, display_url=url),
                        confidence="confirmed",
                    )
            except (ScannerHTTPError, Exception):
                logger.debug("Stored XSS scan: could not fetch %s — skipping", url)
                continue

        return None
