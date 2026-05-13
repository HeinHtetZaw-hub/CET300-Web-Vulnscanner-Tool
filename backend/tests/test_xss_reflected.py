"""Tests for the reflected XSS detection module."""
from __future__ import annotations

import html as html_lib
from urllib.parse import parse_qs

import httpx
import pytest

from app.scanner.crawler import FormData, FormInput, ParameterData
from app.scanner.modules.xss_reflected import (
    ReflectedXSSModule,
    _detect_context,
    _generate_canary,
    _inject_param,
    _req_evidence,
)
from app.utils.http_client import RateLimitedClient


# ---------------------------------------------------------------------------
# Mock transports
# ---------------------------------------------------------------------------


class _ReflectingTransport(httpx.AsyncBaseTransport):
    """Reflects the injected parameter value in the response body.

    When *encode_html* is True, HTML-encodes the value before insertion
    (simulating a server that escapes output — canary reflects but XSS chars
    are neutralised).
    """

    def __init__(self, param_name: str, *, encode_html: bool = False) -> None:
        self._param_name = param_name
        self._encode_html = encode_html

    def _extract_value(self, request: httpx.Request) -> str:
        value = dict(request.url.params).get(self._param_name, "")
        if not value:
            try:
                body = parse_qs(request.content.decode("utf-8"))
                value = (body.get(self._param_name) or [""])[0]
            except Exception:
                pass
        return value

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        value = self._extract_value(request)
        if self._encode_html:
            value = html_lib.escape(value)
        content = f"<html><body><p>Result: {value}</p></body></html>".encode("utf-8")
        return httpx.Response(200, content=content, request=request)


class _AttributeReflectingTransport(httpx.AsyncBaseTransport):
    """Reflects the injected value inside an HTML attribute (not encoded)."""

    def __init__(self, param_name: str) -> None:
        self._param_name = param_name

    def _extract_value(self, request: httpx.Request) -> str:
        value = dict(request.url.params).get(self._param_name, "")
        if not value:
            try:
                body = parse_qs(request.content.decode("utf-8"))
                value = (body.get(self._param_name) or [""])[0]
            except Exception:
                pass
        return value

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        value = self._extract_value(request)
        content = f'<html><body><input value="{value}"></body></html>'.encode("utf-8")
        return httpx.Response(200, content=content, request=request)


class _NotReflectedTransport(httpx.AsyncBaseTransport):
    """Returns static HTML that never contains the injected value."""

    BODY = b"<html><body><p>No results found.</p></body></html>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self.BODY, request=request)


class _NetworkErrorTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")


def _make_client(transport: httpx.AsyncBaseTransport) -> RateLimitedClient:
    return RateLimitedClient(rate_limit=100, timeout=5.0, _transport=transport)


# ---------------------------------------------------------------------------
# URL parameter tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reflected_url_param_confirmed():
    param = ParameterData(url="http://example.com/?q=hello", param_name="q", param_location="query")
    async with _make_client(_ReflectingTransport("q")) as client:
        findings = await ReflectedXSSModule().run(set(), [], [param], client)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "xss_reflected"
    assert f.confidence == "confirmed"
    assert f.affected_parameter == "q"
    assert f.affected_url == "http://example.com/?q=hello"
    assert "<" in f.payload_used  # it's an actual XSS tag, not the canary


@pytest.mark.asyncio
async def test_reflected_url_param_tentative_when_html_encoded():
    """Canary reflects safely (alphanumeric), but all XSS payloads are HTML-encoded → tentative."""
    param = ParameterData(url="http://example.com/?q=hello", param_name="q", param_location="query")
    async with _make_client(_ReflectingTransport("q", encode_html=True)) as client:
        findings = await ReflectedXSSModule().run(set(), [], [param], client)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "xss_reflected"
    assert f.confidence == "tentative"
    assert f.payload_used.startswith("[canary]")


@pytest.mark.asyncio
async def test_not_reflected_returns_no_finding():
    param = ParameterData(url="http://example.com/?q=hello", param_name="q", param_location="query")
    async with _make_client(_NotReflectedTransport()) as client:
        findings = await ReflectedXSSModule().run(set(), [], [param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_reflected_in_attribute_confirmed():
    """XSS payload reflected inside an unencoded HTML attribute → confirmed."""
    param = ParameterData(url="http://example.com/?q=hello", param_name="q", param_location="query")
    async with _make_client(_AttributeReflectingTransport("q")) as client:
        findings = await ReflectedXSSModule().run(set(), [], [param], client)
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"


# ---------------------------------------------------------------------------
# Form input tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reflected_post_form_confirmed():
    form = FormData(
        action_url="http://example.com/search",
        method="POST",
        inputs=[FormInput(name="username", type="text")],
    )
    async with _make_client(_ReflectingTransport("username")) as client:
        findings = await ReflectedXSSModule().run(set(), [form], [], client)
    assert len(findings) == 1
    assert findings[0].vuln_type == "xss_reflected"
    assert findings[0].confidence == "confirmed"
    assert findings[0].affected_parameter == "username"


@pytest.mark.asyncio
async def test_reflected_get_form_confirmed():
    form = FormData(
        action_url="http://example.com/search",
        method="GET",
        inputs=[FormInput(name="q", type="text")],
    )
    async with _make_client(_ReflectingTransport("q")) as client:
        findings = await ReflectedXSSModule().run(set(), [form], [], client)
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"


@pytest.mark.asyncio
async def test_post_form_tentative_when_html_encoded():
    form = FormData(
        action_url="http://example.com/search",
        method="POST",
        inputs=[FormInput(name="q", type="text")],
    )
    async with _make_client(_ReflectingTransport("q", encode_html=True)) as client:
        findings = await ReflectedXSSModule().run(set(), [form], [], client)
    assert len(findings) == 1
    assert findings[0].confidence == "tentative"


@pytest.mark.asyncio
async def test_form_not_reflected_returns_no_finding():
    form = FormData(
        action_url="http://example.com/search",
        method="POST",
        inputs=[FormInput(name="q", type="text")],
    )
    async with _make_client(_NotReflectedTransport()) as client:
        findings = await ReflectedXSSModule().run(set(), [form], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_multiple_form_inputs_each_tested():
    """Two injectable inputs in one form should each generate a finding."""
    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[
            FormInput(name="first_name", type="text"),
            FormInput(name="last_name", type="text"),
        ],
    )
    async with _make_client(_ReflectingTransport("first_name")) as client:
        # first_name is reflected; last_name is not (transport only reflects first_name)
        findings = await ReflectedXSSModule().run(set(), [form], [], client)
    # Only first_name produces a finding
    assert any(f.affected_parameter == "first_name" for f in findings)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_network_error_skipped_gracefully():
    param = ParameterData(url="http://example.com/?q=hello", param_name="q", param_location="query")
    async with _make_client(_NetworkErrorTransport()) as client:
        findings = await ReflectedXSSModule().run(set(), [], [param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_non_injectable_input_types_skipped():
    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[
            FormInput(name="submit_btn", type="submit"),
            FormInput(name="csrf", type="hidden"),
            FormInput(name="agree", type="checkbox"),
            FormInput(name="search", type="text"),
        ],
    )
    async with _make_client(_ReflectingTransport("search")) as client:
        findings = await ReflectedXSSModule().run(set(), [form], [], client)
    # Only 'search' (text) is tested and reflected
    assert all(f.affected_parameter == "search" for f in findings)


@pytest.mark.asyncio
async def test_path_location_params_skipped():
    path_param = ParameterData(
        url="http://example.com/user/1", param_name="id", param_location="path"
    )
    async with _make_client(_ReflectingTransport("id")) as client:
        findings = await ReflectedXSSModule().run(set(), [], [path_param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_empty_inputs_returns_empty_findings():
    async with _make_client(_NotReflectedTransport()) as client:
        findings = await ReflectedXSSModule().run(set(), [], [], client)
    assert findings == []


# ---------------------------------------------------------------------------
# _detect_context unit tests
# ---------------------------------------------------------------------------


def test_detect_context_body():
    html = "<html><body><p>Hello xSsAbCdEf12 world</p></body></html>"
    assert _detect_context(html, "xSsAbCdEf12") == "body"


def test_detect_context_attribute():
    html = '<html><body><input type="text" value="xSsAbCdEf12"></body></html>'
    assert _detect_context(html, "xSsAbCdEf12") == "attribute"


def test_detect_context_script():
    html = "<html><body><script>var q = 'xSsAbCdEf12';</script></body></html>"
    assert _detect_context(html, "xSsAbCdEf12") == "script"


def test_detect_context_script_takes_priority_over_body():
    """If the marker is in both script and text, 'script' wins."""
    html = "<html><body><script>var x = 'xSsAbCdEf12';</script><p>xSsAbCdEf12</p></body></html>"
    assert _detect_context(html, "xSsAbCdEf12") == "script"


def test_detect_context_unknown_when_not_present():
    html = "<html><body><p>Nothing here</p></body></html>"
    assert _detect_context(html, "xSsNotHere99") == "unknown"


def test_detect_context_does_not_raise_on_malformed_html():
    assert _detect_context("<<<<broken", "marker") in ("body", "attribute", "script", "unknown")


# ---------------------------------------------------------------------------
# _generate_canary unit tests
# ---------------------------------------------------------------------------


def test_generate_canary_starts_with_xSs():
    assert _generate_canary().startswith("xSs")


def test_generate_canary_length():
    assert len(_generate_canary()) == 11  # "xSs" + 8 chars


def test_generate_canary_alphanumeric_suffix():
    canary = _generate_canary()
    suffix = canary[3:]
    assert suffix.isalnum()


def test_generate_canary_unique():
    canaries = {_generate_canary() for _ in range(50)}
    assert len(canaries) > 1  # extremely unlikely to collide 50 times


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


def test_inject_param_adds_param():
    url = "http://example.com/search"
    result = _inject_param(url, "q", "<script>")
    assert "q=" in result


def test_inject_param_replaces_existing():
    url = "http://example.com/?q=original&page=2"
    result = _inject_param(url, "q", "PAYLOAD")
    assert "q=PAYLOAD" in result
    assert "page=2" in result


def test_req_evidence_get_format():
    ev = _req_evidence("GET", "http://example.com/search?q=xSsTest")
    assert ev.startswith("GET /search?q=")
    assert "Host: example.com" in ev


def test_req_evidence_post_includes_body():
    ev = _req_evidence("POST", "http://example.com/search", {"q": "test"})
    assert "POST /search HTTP/1.1" in ev
    assert "Content-Type: application/x-www-form-urlencoded" in ev
    assert "q=test" in ev


def test_module_metadata():
    m = ReflectedXSSModule()
    assert m.name == "Reflected XSS"
    assert m.vuln_types == ["xss_reflected"]
