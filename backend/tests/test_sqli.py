"""Tests for the SQL injection detection module."""
from __future__ import annotations

from unittest.mock import patch
from urllib.parse import parse_qs

import httpx
import pytest

from app.scanner.crawler import FormData, FormInput, ParameterData
from app.scanner.modules.sqli import (
    SQLiModule,
    _BOOLEAN_FALSE_PAYLOAD,
    _BOOLEAN_TRUE_PAYLOAD,
    _boolean_differs,
    _has_db_error,
    _inject_param,
    _req_evidence,
)
from app.utils.http_client import RateLimitedClient


# ---------------------------------------------------------------------------
# Mock transports
# ---------------------------------------------------------------------------


class _DBErrorTransport(httpx.AsyncBaseTransport):
    """Always returns a MySQL error body."""

    BODY = b"You have an error in your SQL syntax near 'x'"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self.BODY, request=request)


class _CleanTransport(httpx.AsyncBaseTransport):
    """Always returns clean HTML with no DB errors."""

    BODY = b"<html><body>Welcome</body></html>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self.BODY, request=request)


class _BooleanVulnTransport(httpx.AsyncBaseTransport):
    """Returns a long body for the true-condition payload, short body for false.

    Uses httpx's decoded URL params and decoded POST body to identify payloads,
    so URL encoding is not an issue.
    """

    LONG_BODY = b"<html>" + b"x" * 200 + b"</html>"
    SHORT_BODY = b"<html>Invalid credentials</html>"

    def _is_true_payload(self, request: httpx.Request) -> bool | None:
        # Check URL query params (GET requests)
        for val in dict(request.url.params).values():
            if _BOOLEAN_TRUE_PAYLOAD in val:
                return True
            if _BOOLEAN_FALSE_PAYLOAD in val:
                return False
        # Check form-encoded POST body
        try:
            body_params = parse_qs(request.content.decode("utf-8"))
            for vals in body_params.values():
                for v in vals:
                    if _BOOLEAN_TRUE_PAYLOAD in v:
                        return True
                    if _BOOLEAN_FALSE_PAYLOAD in v:
                        return False
        except Exception:
            pass
        return None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        is_true = self._is_true_payload(request)
        body = self.LONG_BODY if is_true else self.SHORT_BODY
        return httpx.Response(200, content=body, request=request)


class _NetworkErrorTransport(httpx.AsyncBaseTransport):
    """Raises ConnectError for every request."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")


def _make_client(transport: httpx.AsyncBaseTransport) -> RateLimitedClient:
    return RateLimitedClient(rate_limit=100, timeout=5.0, _transport=transport)


# ---------------------------------------------------------------------------
# Error-based SQLi
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_based_url_param_detected():
    param = ParameterData(url="http://example.com/?id=1", param_name="id", param_location="query")
    async with _make_client(_DBErrorTransport()) as client:
        findings = await SQLiModule().run(set(), [], [param], client)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "sqli_error"
    assert f.confidence == "confirmed"
    assert f.affected_parameter == "id"
    assert f.affected_url == "http://example.com/?id=1"


@pytest.mark.asyncio
async def test_error_based_post_form_detected():
    form = FormData(
        action_url="http://example.com/login",
        method="POST",
        inputs=[
            FormInput(name="username", type="text"),
            FormInput(name="password", type="password"),
        ],
    )
    async with _make_client(_DBErrorTransport()) as client:
        findings = await SQLiModule().run(set(), [form], [], client)
    # Both text inputs are tested; both trigger the error
    assert len(findings) == 2
    assert all(f.vuln_type == "sqli_error" for f in findings)
    assert all(f.confidence == "confirmed" for f in findings)


@pytest.mark.asyncio
async def test_error_based_get_form_detected():
    form = FormData(
        action_url="http://example.com/search",
        method="GET",
        inputs=[FormInput(name="q", type="text")],
    )
    async with _make_client(_DBErrorTransport()) as client:
        findings = await SQLiModule().run(set(), [form], [], client)
    assert len(findings) == 1
    assert findings[0].vuln_type == "sqli_error"
    assert findings[0].affected_parameter == "q"


@pytest.mark.asyncio
async def test_clean_target_returns_no_findings():
    param = ParameterData(url="http://example.com/?id=1", param_name="id", param_location="query")
    form = FormData(
        action_url="http://example.com/search",
        method="GET",
        inputs=[FormInput(name="q", type="text")],
    )
    async with _make_client(_CleanTransport()) as client:
        findings = await SQLiModule().run(set(), [form], [param], client)
    assert findings == []


# ---------------------------------------------------------------------------
# Boolean-blind SQLi
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_boolean_blind_url_param_detected():
    param = ParameterData(url="http://example.com/?id=1", param_name="id", param_location="query")
    async with _make_client(_BooleanVulnTransport()) as client:
        findings = await SQLiModule().run(set(), [], [param], client)
    bool_findings = [f for f in findings if f.vuln_type == "sqli_blind_boolean"]
    assert len(bool_findings) == 1
    assert bool_findings[0].confidence == "tentative"
    assert _BOOLEAN_TRUE_PAYLOAD in bool_findings[0].payload_used


@pytest.mark.asyncio
async def test_boolean_blind_post_form_detected():
    form = FormData(
        action_url="http://example.com/login",
        method="POST",
        inputs=[FormInput(name="username", type="text")],
    )
    async with _make_client(_BooleanVulnTransport()) as client:
        findings = await SQLiModule().run(set(), [form], [], client)
    bool_findings = [f for f in findings if f.vuln_type == "sqli_blind_boolean"]
    assert len(bool_findings) == 1
    assert bool_findings[0].confidence == "tentative"


@pytest.mark.asyncio
async def test_boolean_same_response_returns_no_finding():
    """When true/false conditions return identical responses → no boolean finding."""
    param = ParameterData(url="http://example.com/?id=1", param_name="id", param_location="query")
    async with _make_client(_CleanTransport()) as client:
        findings = await SQLiModule().run(set(), [], [param], client)
    assert not any(f.vuln_type == "sqli_blind_boolean" for f in findings)


# ---------------------------------------------------------------------------
# Time-based blind SQLi
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_time_based_url_param_detected():
    """Two consecutive slow responses confirm a time-based finding."""
    param = ParameterData(url="http://example.com/?id=1", param_name="id", param_location="query")
    # Patch time.monotonic: first TIME_PAYLOAD → run1=5s, run2=5s → finding
    with patch("app.scanner.modules.sqli.time") as mock_time:
        mock_time.monotonic.side_effect = [0.0, 5.0, 0.0, 5.0]
        async with _make_client(_CleanTransport()) as client:
            findings = await SQLiModule().run(set(), [], [param], client)
    time_findings = [f for f in findings if f.vuln_type == "sqli_blind_time"]
    assert len(time_findings) == 1
    assert time_findings[0].confidence == "tentative"
    assert "5.0s" in time_findings[0].evidence_response


@pytest.mark.asyncio
async def test_time_based_single_slow_run_not_reported():
    """First run slow but second run fast → no finding (avoids false positives)."""
    param = ParameterData(url="http://example.com/?id=1", param_name="id", param_location="query")
    # Payload 1: run1=5s, run2=0.1s → not a finding
    # Payloads 2-4: run1=0.1s → skipped immediately
    with patch("app.scanner.modules.sqli.time") as mock_time:
        mock_time.monotonic.side_effect = [
            0.0, 5.0, 0.0, 0.1,   # payload 1: first slow, second fast
            0.0, 0.1,              # payload 2: fast
            0.0, 0.1,              # payload 3: fast
            0.0, 0.1,              # payload 4: fast
        ]
        async with _make_client(_CleanTransport()) as client:
            findings = await SQLiModule().run(set(), [], [param], client)
    assert not any(f.vuln_type == "sqli_blind_time" for f in findings)


@pytest.mark.asyncio
async def test_time_based_post_form_detected():
    form = FormData(
        action_url="http://example.com/login",
        method="POST",
        inputs=[FormInput(name="username", type="text")],
    )
    with patch("app.scanner.modules.sqli.time") as mock_time:
        mock_time.monotonic.side_effect = [0.0, 5.0, 0.0, 5.0]
        async with _make_client(_CleanTransport()) as client:
            findings = await SQLiModule().run(set(), [form], [], client)
    time_findings = [f for f in findings if f.vuln_type == "sqli_blind_time"]
    assert len(time_findings) == 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_network_error_is_skipped_gracefully():
    """ConnectError during testing must not crash the module."""
    param = ParameterData(url="http://example.com/?id=1", param_name="id", param_location="query")
    async with _make_client(_NetworkErrorTransport()) as client:
        findings = await SQLiModule().run(set(), [], [param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_non_injectable_input_types_are_skipped():
    """submit/button/hidden/checkbox inputs must not be tested."""
    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[
            FormInput(name="action", type="submit"),
            FormInput(name="_token", type="hidden"),
            FormInput(name="agree", type="checkbox"),
            FormInput(name="username", type="text"),
        ],
    )
    async with _make_client(_DBErrorTransport()) as client:
        findings = await SQLiModule().run(set(), [form], [], client)
    # Only 'username' (text) should produce a finding
    assert all(f.affected_parameter == "username" for f in findings)
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_path_location_params_are_skipped():
    """Only 'query' location parameters are tested; 'path' params are ignored."""
    path_param = ParameterData(
        url="http://example.com/user/1", param_name="id", param_location="path"
    )
    async with _make_client(_DBErrorTransport()) as client:
        findings = await SQLiModule().run(set(), [], [path_param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_error_found_skips_boolean_and_time():
    """Once error-based finds a confirmed finding, boolean/time are not tried."""
    param = ParameterData(url="http://example.com/?id=1", param_name="id", param_location="query")
    request_count = 0

    class _CountingDBErrorTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(
                200,
                content=b"You have an error in your SQL syntax",
                request=request,
            )

    async with _make_client(_CountingDBErrorTransport()) as client:
        findings = await SQLiModule().run(set(), [], [param], client)

    assert findings[0].vuln_type == "sqli_error"
    # Only one request is needed (first payload triggers the error)
    assert request_count == 1


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------


def test_has_db_error_mysql():
    assert _has_db_error("You have an error in your SQL syntax near '1'")


def test_has_db_error_postgres():
    assert _has_db_error("ERROR: syntax error at or near \"WHERE\"")


def test_has_db_error_sqlite():
    assert _has_db_error("SQLITE_ERROR: unrecognized token: \"''\"")


def test_has_db_error_mssql():
    assert _has_db_error("Unclosed quotation mark after the character string")


def test_has_db_error_case_insensitive():
    assert _has_db_error("DATABASE ERROR: connection failed")


def test_has_db_error_negative():
    assert not _has_db_error("<html><body>Hello world</body></html>")


def test_inject_param_replaces_existing_value():
    url = "http://example.com/page?id=1&cat=3"
    result = _inject_param(url, "id", "payload")
    assert "id=payload" in result
    assert "cat=3" in result


def test_inject_param_adds_new_param():
    url = "http://example.com/page"
    result = _inject_param(url, "search", "test")
    assert "search=test" in result


def test_inject_param_preserves_other_params():
    url = "http://example.com/page?a=1&b=2&c=3"
    result = _inject_param(url, "b", "PAYLOAD")
    assert "a=1" in result
    assert "b=PAYLOAD" in result
    assert "c=3" in result


def test_boolean_differs_by_length():
    class _R:
        def __init__(self, status: int, text: str) -> None:
            self.status_code = status
            self._text = text

        @property
        def text(self) -> str:
            return self._text

    assert _boolean_differs(_R(200, "a" * 200), _R(200, "b" * 10))


def test_boolean_same_length_not_different():
    class _R:
        def __init__(self, status: int, text: str) -> None:
            self.status_code = status
            self._text = text

        @property
        def text(self) -> str:
            return self._text

    assert not _boolean_differs(_R(200, "a" * 100), _R(200, "b" * 100))


def test_boolean_differs_by_status_code():
    class _R:
        def __init__(self, status: int) -> None:
            self.status_code = status
            self._text = "same content"

        @property
        def text(self) -> str:
            return self._text

    assert _boolean_differs(_R(200), _R(404))


def test_req_evidence_get_format():
    ev = _req_evidence("GET", "http://example.com/page?id=1%27")
    assert ev.startswith("GET /page?id=")
    assert "HTTP/1.1" in ev
    assert "Host: example.com" in ev


def test_req_evidence_post_includes_body():
    ev = _req_evidence("POST", "http://example.com/login", {"username": "test"})
    assert "POST /login HTTP/1.1" in ev
    assert "Content-Type: application/x-www-form-urlencoded" in ev
    assert "username=test" in ev


def test_module_metadata():
    module = SQLiModule()
    assert module.name == "SQL Injection"
    assert "sqli_error" in module.vuln_types
    assert "sqli_blind_boolean" in module.vuln_types
    assert "sqli_blind_time" in module.vuln_types
