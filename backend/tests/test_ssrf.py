"""Tests for the SSRF detection portion of the BACModule."""
from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from app.scanner.crawler import FormData, FormInput, ParameterData
from app.scanner.modules.bac import (
    BACModule,
    _check_ssrf_response,
    _inject_query_param,
    _is_ssrf_param,
    _SSRF_PROBES,
)
from app.utils.http_client import RateLimitedClient


# ---------------------------------------------------------------------------
# Mock transports
# ---------------------------------------------------------------------------


def _has_internal_url(request: httpx.Request) -> bool:
    """Return True if any request parameter contains an SSRF probe URL."""
    _MARKERS = ("127.0.0.1", "localhost", "169.254.169.254", "[::1]")
    for val in dict(request.url.params).values():
        if any(m in val for m in _MARKERS):
            return True
    try:
        body = parse_qs(request.content.decode("utf-8", errors="replace"))
        for vals in body.values():
            for v in vals:
                if any(m in v for m in _MARKERS):
                    return True
    except Exception:
        pass
    return False


class _SSRFConfirmedTransport(httpx.AsyncBaseTransport):
    """Returns AWS-metadata-like content when an internal URL is injected."""

    SSRF_BODY = b"ami-id=ami-0abcdef1234567890\ninstance-type=t2.micro\nsecurity-credentials=my-iam-role"
    SAFE_BODY = b"<html><body><p>Normal response</p></body></html>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = self.SSRF_BODY if _has_internal_url(request) else self.SAFE_BODY
        return httpx.Response(200, content=body, request=request)


class _SSRFTentativeTransport(httpx.AsyncBaseTransport):
    """Returns a 'connection refused' error body when an internal URL is injected."""

    SSRF_BODY = b"Error: Connection refused while connecting to http://127.0.0.1:80"
    SAFE_BODY = b"<html><body><p>Normal response</p></body></html>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = self.SSRF_BODY if _has_internal_url(request) else self.SAFE_BODY
        return httpx.Response(200, content=body, request=request)


class _CleanTransport(httpx.AsyncBaseTransport):
    """Always returns clean HTML — simulates a server that ignores the URL param."""

    BODY = b"<html><body><p>Clean response, no SSRF.</p></body></html>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self.BODY, request=request)


class _NetworkErrorTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")


def _make_client(transport: httpx.AsyncBaseTransport) -> RateLimitedClient:
    return RateLimitedClient(rate_limit=100, timeout=5.0, _transport=transport)


def _ssrf_param(name: str = "url") -> ParameterData:
    return ParameterData(
        url=f"http://example.com/fetch?{name}=https://example.com",
        param_name=name,
        param_location="query",
    )


# ---------------------------------------------------------------------------
# URL parameter — confirmed SSRF
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssrf_confirmed_url_param():
    """SSRF probe gets AWS metadata back → confirmed finding."""
    param = _ssrf_param("url")
    async with _make_client(_SSRFConfirmedTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "ssrf"
    assert f.confidence == "confirmed"
    assert f.affected_parameter == "url"
    assert f.affected_url == param.url
    assert any(probe in f.payload_used for probe in _SSRF_PROBES)


@pytest.mark.asyncio
async def test_ssrf_confirmed_uses_first_matching_probe():
    """Module stops at the first probe that returns confirmed indicators."""
    param = _ssrf_param("redirect")
    async with _make_client(_SSRFConfirmedTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)
    assert findings[0].confidence == "confirmed"
    # The evidence request should contain one of the internal probe URLs
    assert "127.0.0.1" in findings[0].evidence_request or "localhost" in findings[0].evidence_request


@pytest.mark.asyncio
async def test_ssrf_confirmed_common_param_names():
    """All canonical SSRF-prone parameter names trigger SSRF detection."""
    prone_names = ["url", "redirect", "next", "callback", "src", "dest", "image_url"]
    for name in prone_names:
        param = _ssrf_param(name)
        async with _make_client(_SSRFConfirmedTransport()) as client:
            findings = await BACModule().run(set(), [], [param], client)
        assert len(findings) == 1, f"Expected finding for param {name!r}"
        assert findings[0].vuln_type == "ssrf"


# ---------------------------------------------------------------------------
# URL parameter — tentative SSRF
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssrf_tentative_url_param():
    """SSRF probe triggers 'connection refused' error → tentative finding."""
    param = _ssrf_param("url")
    async with _make_client(_SSRFTentativeTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)
    assert len(findings) == 1
    assert findings[0].vuln_type == "ssrf"
    assert findings[0].confidence == "tentative"


@pytest.mark.asyncio
async def test_ssrf_tentative_stops_trying_after_first_tentative():
    """Once a tentative finding is recorded the module keeps trying for confirmed."""
    call_count = 0

    class _CountingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if _has_internal_url(request):
                return httpx.Response(200, content=b"connection refused", request=request)
            return httpx.Response(200, content=b"normal", request=request)

    param = _ssrf_param("url")
    async with _make_client(_CountingTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)

    # All probes are tried (trying to upgrade tentative to confirmed)
    assert call_count == len(_SSRF_PROBES)
    assert findings[0].confidence == "tentative"


# ---------------------------------------------------------------------------
# URL parameter — no finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssrf_clean_response_no_finding():
    """Server ignores the URL param and returns clean HTML → no finding."""
    param = _ssrf_param("url")
    async with _make_client(_CleanTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_ssrf_non_prone_param_name_skipped():
    """Parameters not in the SSRF-prone names list are not tested."""
    param = ParameterData(
        url="http://example.com/search?q=hello",
        param_name="q",
        param_location="query",
    )
    async with _make_client(_SSRFConfirmedTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_ssrf_path_location_param_skipped():
    """Path-location parameters are not tested for SSRF."""
    param = ParameterData(
        url="http://example.com/fetch/https%3A%2F%2Fexample.com",
        param_name="url",
        param_location="path",
    )
    async with _make_client(_SSRFConfirmedTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)
    assert findings == []


# ---------------------------------------------------------------------------
# Form input — SSRF
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssrf_confirmed_post_form():
    """POST form with SSRF-prone input name → confirmed finding."""
    form = FormData(
        action_url="http://example.com/proxy",
        method="POST",
        inputs=[FormInput(name="url", type="text")],
    )
    async with _make_client(_SSRFConfirmedTransport()) as client:
        findings = await BACModule().run(set(), [form], [], client)
    assert len(findings) == 1
    assert findings[0].vuln_type == "ssrf"
    assert findings[0].confidence == "confirmed"
    assert findings[0].affected_parameter == "url"
    assert "POST" in findings[0].evidence_request


@pytest.mark.asyncio
async def test_ssrf_tentative_post_form():
    form = FormData(
        action_url="http://example.com/proxy",
        method="POST",
        inputs=[FormInput(name="callback", type="text")],
    )
    async with _make_client(_SSRFTentativeTransport()) as client:
        findings = await BACModule().run(set(), [form], [], client)
    assert len(findings) == 1
    assert findings[0].confidence == "tentative"


@pytest.mark.asyncio
async def test_ssrf_confirmed_get_form():
    """GET form with SSRF-prone input name → confirmed finding (sent as query param)."""
    form = FormData(
        action_url="http://example.com/proxy",
        method="GET",
        inputs=[FormInput(name="redirect", type="text")],
    )
    async with _make_client(_SSRFConfirmedTransport()) as client:
        findings = await BACModule().run(set(), [form], [], client)
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"
    assert "GET" in findings[0].evidence_request


@pytest.mark.asyncio
async def test_ssrf_non_injectable_form_types_skipped():
    """submit/hidden/etc. inputs must never be tested for SSRF."""
    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[
            FormInput(name="url", type="submit"),
            FormInput(name="callback", type="hidden"),
            FormInput(name="src", type="checkbox"),
            FormInput(name="dest", type="text"),   # only this should be tested
        ],
    )
    async with _make_client(_SSRFConfirmedTransport()) as client:
        findings = await BACModule().run(set(), [form], [], client)
    assert all(f.affected_parameter == "dest" for f in findings)
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_ssrf_form_clean_response_no_finding():
    form = FormData(
        action_url="http://example.com/proxy",
        method="POST",
        inputs=[FormInput(name="url", type="text")],
    )
    async with _make_client(_CleanTransport()) as client:
        findings = await BACModule().run(set(), [form], [], client)
    assert findings == []


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssrf_network_error_skipped_gracefully():
    """ConnectError on every probe → no crash, no finding."""
    param = _ssrf_param("url")
    async with _make_client(_NetworkErrorTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_ssrf_partial_probe_failure_continues():
    """ConnectError on some probes → module continues to remaining probes."""

    class _FailThenSucceedTransport(httpx.AsyncBaseTransport):
        _calls = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self._calls += 1
            if self._calls <= 2 and _has_internal_url(request):
                raise httpx.ConnectError("refused")
            if _has_internal_url(request):
                return httpx.Response(
                    200,
                    content=b"ami-id=ami-12345\nsecurity-credentials=role",
                    request=request,
                )
            return httpx.Response(200, content=b"normal", request=request)

    param = _ssrf_param("url")
    async with _make_client(_FailThenSucceedTransport()) as client:
        findings = await BACModule().run(set(), [], [param], client)
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"


# ---------------------------------------------------------------------------
# IDOR and SSRF run together
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_idor_and_ssrf_both_detected():
    """run() reports findings from both IDOR (target_urls) and SSRF (parameters)."""

    class _CombinedTransport(httpx.AsyncBaseTransport):
        _SEG = __import__("re").compile(r"/(\d+)(?=/|$)")

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if _has_internal_url(request):
                return httpx.Response(
                    200, content=b"ami-id=ami-test\nsecurity-credentials=role", request=request
                )
            m = self._SEG.search(request.url.path)
            if m:
                uid = int(m.group(1))
                return httpx.Response(
                    200, content=(f"<html>{'x' * uid * 100}</html>").encode(), request=request
                )
            return httpx.Response(200, content=b"<html>normal</html>", request=request)

    target_urls = {"http://example.com/users/42"}
    parameters = [_ssrf_param("url")]
    async with _make_client(_CombinedTransport()) as client:
        findings = await BACModule().run(target_urls, [], parameters, client)

    vuln_types = {f.vuln_type for f in findings}
    assert "idor" in vuln_types
    assert "ssrf" in vuln_types


# ---------------------------------------------------------------------------
# _check_ssrf_response unit tests
# ---------------------------------------------------------------------------


def test_check_ssrf_confirmed_aws_metadata():
    assert _check_ssrf_response("ami-id=ami-12345\ninstance-type=t2.micro") == "confirmed"


def test_check_ssrf_confirmed_security_credentials():
    assert _check_ssrf_response("security-credentials: my-role") == "confirmed"


def test_check_ssrf_confirmed_ssh_banner():
    assert _check_ssrf_response("SSH-2.0-OpenSSH_8.2") == "confirmed"


def test_check_ssrf_confirmed_mysql_banner():
    assert _check_ssrf_response("mysql_native_password\x00some binary data") == "confirmed"


def test_check_ssrf_tentative_connection_refused():
    assert _check_ssrf_response("Error: Connection refused while connecting") == "tentative"


def test_check_ssrf_tentative_could_not_connect():
    assert _check_ssrf_response("Could not connect to the remote server") == "tentative"


def test_check_ssrf_tentative_curl_error():
    assert _check_ssrf_response("cURL error 7: Failed to connect to 127.0.0.1") == "tentative"


def test_check_ssrf_none_clean_response():
    assert _check_ssrf_response("<html><body>Welcome</body></html>") is None


def test_check_ssrf_case_insensitive():
    assert _check_ssrf_response("CONNECTION REFUSED by remote host") == "tentative"
    assert _check_ssrf_response("AMI-ID: ami-abc123") == "confirmed"


# ---------------------------------------------------------------------------
# _is_ssrf_param unit tests
# ---------------------------------------------------------------------------


def test_is_ssrf_param_known_names():
    for name in ("url", "redirect", "next", "callback", "src", "dest", "image_url"):
        assert _is_ssrf_param(name), f"{name!r} should be flagged"


def test_is_ssrf_param_unknown_names():
    for name in ("q", "search", "page", "sort", "filter", "id", "name", "email"):
        assert not _is_ssrf_param(name), f"{name!r} should NOT be flagged"


def test_is_ssrf_param_case_insensitive():
    assert _is_ssrf_param("URL")
    assert _is_ssrf_param("Redirect")
    assert _is_ssrf_param("CALLBACK")


# ---------------------------------------------------------------------------
# _inject_query_param unit tests
# ---------------------------------------------------------------------------


def test_inject_query_param_replaces_existing():
    result = _inject_query_param("http://example.com/?url=https://example.com", "url", "http://127.0.0.1")
    assert "url=" in result
    assert "127.0.0.1" in result


def test_inject_query_param_adds_new_param():
    result = _inject_query_param("http://example.com/proxy", "url", "http://127.0.0.1")
    assert "url=" in result
    assert "127.0.0.1" in result


def test_inject_query_param_preserves_other_params():
    result = _inject_query_param("http://example.com/?id=5&url=https://x.com", "url", "http://localhost")
    assert "id=5" in result
    assert "localhost" in result


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------


def test_vuln_types_includes_ssrf():
    assert "ssrf" in BACModule().vuln_types


def test_vuln_types_still_includes_idor():
    assert "idor" in BACModule().vuln_types


def test_module_name():
    assert BACModule().name == "Broken Access Control"
