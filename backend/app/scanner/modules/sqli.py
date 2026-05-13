"""SQL injection detection module.

Tries three techniques per parameter, in order: error-based → boolean-blind → time-blind.
Stops as soon as a confirmed or tentative finding is returned for that parameter.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.base import BaseModule, RawFinding
from app.utils.http_client import RateLimitedClient, ScannerHTTPError

logger = logging.getLogger(__name__)

_PAYLOAD_FILE = Path(__file__).parent.parent / "payloads" / "sqli.txt"

# Lowercased error substrings — matched case-insensitively against response body.
_ERROR_SIGNATURES: list[str] = [
    # MySQL
    "you have an error in your sql syntax",
    "mysql_fetch",
    "warning: mysql",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query",
    "pg::syntaxerror",
    "unterminated quoted string",
    "pg_exec",
    "error: syntax error at or near",
    # SQLite
    "sqlite3::sqlexception",
    "sqlite_error",
    "unrecognized token",
    "sqlite3.operationalerror",
    # MSSQL
    "microsoft sql native client error",
    "unclosed quotation mark",
    "ole db provider for sql server",
    "sqlexception",
    # Generic
    "sql syntax",
    "sql error",
    "database error",
    "odbc sql server driver",
    "warning: pg_",
    "ora-",
    "db2 sql error",
    "java.sql.sqlexception",
    "com.mysql.jdbc",
]

_BOOLEAN_TRUE_PAYLOAD = "' OR '1'='1"
_BOOLEAN_FALSE_PAYLOAD = "' OR '1'='2"
_BOOLEAN_LEN_THRESHOLD = 50

_TIME_PAYLOADS = [
    "' OR SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "' OR 1=1; WAITFOR DELAY '0:0:5'--",
    "' OR BENCHMARK(10000000,SHA1('test'))--",
]
_TIME_THRESHOLD = 4.5
_TIME_TIMEOUT = 12.0

# Input types that should never be injected into.
_SKIP_INPUT_TYPES = frozenset(
    {"submit", "button", "image", "reset", "hidden", "checkbox", "radio", "file"}
)


def _load_payloads() -> list[str]:
    if not _PAYLOAD_FILE.exists():
        logger.warning("SQLi payload file not found: %s", _PAYLOAD_FILE)
        return ["'", "''", "' OR '1'='1", "' OR 1=1--", "1' ORDER BY 1--", "' UNION SELECT NULL--"]
    lines = _PAYLOAD_FILE.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def _inject_param(url: str, name: str, value: str) -> str:
    """Return *url* with query parameter *name* set to *value*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[name] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


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


def _has_db_error(text: str) -> bool:
    lower = text.lower()
    return any(sig in lower for sig in _ERROR_SIGNATURES)


def _boolean_differs(r_true: httpx.Response, r_false: httpx.Response) -> bool:
    if r_true.status_code != r_false.status_code:
        return True
    try:
        return abs(len(r_true.text) - len(r_false.text)) > _BOOLEAN_LEN_THRESHOLD
    except Exception:
        return False


async def _timed_get(client: RateLimitedClient, url: str) -> float | None:
    t0 = time.monotonic()
    try:
        await client.get(url, timeout=_TIME_TIMEOUT)
    except ScannerHTTPError:
        return None
    return time.monotonic() - t0


async def _timed_post(client: RateLimitedClient, url: str, data: dict) -> float | None:
    t0 = time.monotonic()
    try:
        await client.post(url, data=data, timeout=_TIME_TIMEOUT)
    except ScannerHTTPError:
        return None
    return time.monotonic() - t0


class SQLiModule(BaseModule):
    """Detects SQL injection via error-based, boolean-blind, and time-blind techniques."""

    def __init__(self) -> None:
        self._payloads = _load_payloads()

    @property
    def name(self) -> str:
        return "SQL Injection"

    @property
    def vuln_types(self) -> list[str]:
        return ["sqli_error", "sqli_blind_boolean", "sqli_blind_time"]

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
    # URL parameter testing
    # ------------------------------------------------------------------

    async def _test_url_param(self, param: ParameterData, client: RateLimitedClient) -> RawFinding | None:
        result = await self._error_url(param, client)
        if result:
            return result
        result = await self._boolean_url(param, client)
        if result:
            return result
        return await self._time_url(param, client)

    async def _error_url(self, param: ParameterData, client: RateLimitedClient) -> RawFinding | None:
        for payload in self._payloads:
            injected = _inject_param(param.url, param.param_name, payload)
            try:
                response = await client.get(injected)
                body = response.text
            except (ScannerHTTPError, Exception):
                continue
            if _has_db_error(body):
                return RawFinding(
                    vuln_type="sqli_error",
                    affected_url=param.url,
                    affected_parameter=param.param_name,
                    payload_used=payload,
                    evidence_request=_req_evidence("GET", injected),
                    evidence_response=_resp_evidence(response),
                    confidence="confirmed",
                )
        return None

    async def _boolean_url(self, param: ParameterData, client: RateLimitedClient) -> RawFinding | None:
        t_url = _inject_param(param.url, param.param_name, _BOOLEAN_TRUE_PAYLOAD)
        f_url = _inject_param(param.url, param.param_name, _BOOLEAN_FALSE_PAYLOAD)
        try:
            r_true = await client.get(t_url)
            r_false = await client.get(f_url)
        except ScannerHTTPError:
            return None
        if not _boolean_differs(r_true, r_false):
            return None
        return RawFinding(
            vuln_type="sqli_blind_boolean",
            affected_url=param.url,
            affected_parameter=param.param_name,
            payload_used=f"TRUE: {_BOOLEAN_TRUE_PAYLOAD} | FALSE: {_BOOLEAN_FALSE_PAYLOAD}",
            evidence_request=_req_evidence("GET", t_url),
            evidence_response=_resp_evidence(r_true),
            confidence="tentative",
        )

    async def _time_url(self, param: ParameterData, client: RateLimitedClient) -> RawFinding | None:
        for payload in _TIME_PAYLOADS:
            injected = _inject_param(param.url, param.param_name, payload)
            elapsed1 = await _timed_get(client, injected)
            if elapsed1 is None or elapsed1 < _TIME_THRESHOLD:
                continue
            elapsed2 = await _timed_get(client, injected)
            if elapsed2 is not None and elapsed2 >= _TIME_THRESHOLD:
                return RawFinding(
                    vuln_type="sqli_blind_time",
                    affected_url=param.url,
                    affected_parameter=param.param_name,
                    payload_used=payload,
                    evidence_request=_req_evidence("GET", injected),
                    evidence_response=(
                        f"[Time-based: response took {elapsed2:.1f}s with 5-second delay payload]"
                    ),
                    confidence="tentative",
                )
        return None

    # ------------------------------------------------------------------
    # Form input testing
    # ------------------------------------------------------------------

    async def _test_form_input(
        self, form: FormData, target_input: str, client: RateLimitedClient
    ) -> RawFinding | None:
        result = await self._error_form(form, target_input, client)
        if result:
            return result
        result = await self._boolean_form(form, target_input, client)
        if result:
            return result
        return await self._time_form(form, target_input, client)

    def _base_form_data(self, form: FormData) -> dict[str, str]:
        return {inp.name: inp.value for inp in form.inputs if inp.name}

    async def _error_form(
        self, form: FormData, target_input: str, client: RateLimitedClient
    ) -> RawFinding | None:
        base = self._base_form_data(form)
        method = form.method.upper()
        url = form.action_url
        for payload in self._payloads:
            data = {**base, target_input: payload}
            try:
                if method == "POST":
                    response = await client.post(url, data=data)
                    req_ev = _req_evidence("POST", url, data)
                else:
                    injected = _inject_param(url, target_input, payload)
                    response = await client.get(injected)
                    req_ev = _req_evidence("GET", injected)
                body = response.text
            except (ScannerHTTPError, Exception):
                continue
            if _has_db_error(body):
                return RawFinding(
                    vuln_type="sqli_error",
                    affected_url=form.action_url,
                    affected_parameter=target_input,
                    payload_used=payload,
                    evidence_request=req_ev,
                    evidence_response=_resp_evidence(response),
                    confidence="confirmed",
                )
        return None

    async def _boolean_form(
        self, form: FormData, target_input: str, client: RateLimitedClient
    ) -> RawFinding | None:
        base = self._base_form_data(form)
        method = form.method.upper()
        url = form.action_url
        try:
            if method == "POST":
                r_true = await client.post(url, data={**base, target_input: _BOOLEAN_TRUE_PAYLOAD})
                r_false = await client.post(url, data={**base, target_input: _BOOLEAN_FALSE_PAYLOAD})
                req_ev = _req_evidence("POST", url, {**base, target_input: _BOOLEAN_TRUE_PAYLOAD})
            else:
                t_url = _inject_param(url, target_input, _BOOLEAN_TRUE_PAYLOAD)
                f_url = _inject_param(url, target_input, _BOOLEAN_FALSE_PAYLOAD)
                r_true = await client.get(t_url)
                r_false = await client.get(f_url)
                req_ev = _req_evidence("GET", t_url)
        except ScannerHTTPError:
            return None
        if not _boolean_differs(r_true, r_false):
            return None
        return RawFinding(
            vuln_type="sqli_blind_boolean",
            affected_url=form.action_url,
            affected_parameter=target_input,
            payload_used=f"TRUE: {_BOOLEAN_TRUE_PAYLOAD} | FALSE: {_BOOLEAN_FALSE_PAYLOAD}",
            evidence_request=req_ev,
            evidence_response=_resp_evidence(r_true),
            confidence="tentative",
        )

    async def _time_form(
        self, form: FormData, target_input: str, client: RateLimitedClient
    ) -> RawFinding | None:
        base = self._base_form_data(form)
        method = form.method.upper()
        url = form.action_url
        for payload in _TIME_PAYLOADS:
            data = {**base, target_input: payload}
            if method == "POST":
                elapsed1 = await _timed_post(client, url, data)
                if elapsed1 is None or elapsed1 < _TIME_THRESHOLD:
                    continue
                elapsed2 = await _timed_post(client, url, data)
            else:
                injected = _inject_param(url, target_input, payload)
                elapsed1 = await _timed_get(client, injected)
                if elapsed1 is None or elapsed1 < _TIME_THRESHOLD:
                    continue
                elapsed2 = await _timed_get(client, injected)
            if elapsed2 is not None and elapsed2 >= _TIME_THRESHOLD:
                return RawFinding(
                    vuln_type="sqli_blind_time",
                    affected_url=form.action_url,
                    affected_parameter=target_input,
                    payload_used=payload,
                    evidence_request=_req_evidence(method, url, data if method == "POST" else None),
                    evidence_response=(
                        f"[Time-based: response took {elapsed2:.1f}s with 5-second delay payload]"
                    ),
                    confidence="tentative",
                )
        return None
