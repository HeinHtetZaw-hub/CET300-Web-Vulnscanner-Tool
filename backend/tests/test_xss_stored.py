"""Tests for the stored XSS detection module."""
from __future__ import annotations

import html as html_lib
from urllib.parse import parse_qs

import httpx
import pytest

from app.scanner.crawler import FormData, FormInput, ParameterData
from app.scanner.modules.xss_stored import StoredXSSModule, _generate_marker, _req_evidence
from app.utils.http_client import RateLimitedClient


# ---------------------------------------------------------------------------
# Mock transports
# ---------------------------------------------------------------------------


class _StoringTransport(httpx.AsyncBaseTransport):
    """Stateful transport: stores the submitted value on POST; serves it on all GET requests.

    The POST response itself is clean ("Comment posted.") — the marker only
    appears when a GET request is made to a discovered URL.
    """

    def __init__(self, param_name: str) -> None:
        self._param_name = param_name
        self._stored: str = ""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            try:
                body_params = parse_qs(request.content.decode("utf-8"))
                self._stored = (body_params.get(self._param_name) or [""])[0]
            except Exception:
                pass
            return httpx.Response(
                200, content=b"<html><body>Comment posted.</body></html>", request=request
            )
        content = f"<html><body><div>{self._stored}</div></body></html>".encode("utf-8")
        return httpx.Response(200, content=content, request=request)


class _ImmediateDisplayTransport(httpx.AsyncBaseTransport):
    """POST response immediately includes the submitted value (e.g. forum preview)."""

    def __init__(self, param_name: str) -> None:
        self._param_name = param_name

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        value = ""
        if request.method == "POST":
            try:
                body_params = parse_qs(request.content.decode("utf-8"))
                value = (body_params.get(self._param_name) or [""])[0]
            except Exception:
                pass
        content = f"<html><body><p>You posted: {value}</p></body></html>".encode("utf-8")
        return httpx.Response(200, content=content, request=request)


class _HtmlEncodingTransport(httpx.AsyncBaseTransport):
    """Stores value but HTML-encodes it in every response (safe output)."""

    def __init__(self, param_name: str) -> None:
        self._param_name = param_name
        self._stored: str = ""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            try:
                body_params = parse_qs(request.content.decode("utf-8"))
                self._stored = (body_params.get(self._param_name) or [""])[0]
            except Exception:
                pass
            return httpx.Response(200, content=b"Saved.", request=request)
        safe = html_lib.escape(self._stored)
        content = f"<html><body>{safe}</body></html>".encode("utf-8")
        return httpx.Response(200, content=content, request=request)


class _CleanTransport(httpx.AsyncBaseTransport):
    """Always returns clean HTML with no stored content."""

    BODY = b"<html><body><p>Nothing here.</p></body></html>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self.BODY, request=request)


class _PostFailsTransport(httpx.AsyncBaseTransport):
    """Raises ConnectError on POST, returns clean HTML on GET."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, content=b"<html><body>OK</body></html>", request=request)


class _SelectiveGetFailTransport(httpx.AsyncBaseTransport):
    """Stores on POST; fails on the first GET URL, succeeds on the second.

    Used to verify that a GET failure is skipped and scanning continues.
    """

    def __init__(self, param_name: str, fail_url: str) -> None:
        self._param_name = param_name
        self._fail_url = fail_url
        self._stored: str = ""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            try:
                body_params = parse_qs(request.content.decode("utf-8"))
                self._stored = (body_params.get(self._param_name) or [""])[0]
            except Exception:
                pass
            return httpx.Response(200, content=b"Saved.", request=request)
        if str(request.url) == self._fail_url:
            raise httpx.ConnectError("refused")
        content = f"<html><body>{self._stored}</body></html>".encode("utf-8")
        return httpx.Response(200, content=content, request=request)


def _make_client(transport: httpx.AsyncBaseTransport) -> RateLimitedClient:
    return RateLimitedClient(rate_limit=100, timeout=5.0, _transport=transport)


# ---------------------------------------------------------------------------
# Core detection tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_marker_found_on_discovered_url():
    """Marker stored on POST; appears on a crawled GET page → confirmed."""
    form = FormData(
        action_url="http://example.com/comments",
        method="POST",
        inputs=[FormInput(name="comment", type="text")],
    )
    target_urls = {"http://example.com/", "http://example.com/posts"}
    async with _make_client(_StoringTransport("comment")) as client:
        findings = await StoredXSSModule().run(target_urls, [form], [], client)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "xss_stored"
    assert f.confidence == "confirmed"
    assert f.affected_parameter == "comment"
    assert f.affected_url == "http://example.com/comments"
    assert "xSsStored_" in f.payload_used
    assert "[Marker found at:" in f.evidence_response


@pytest.mark.asyncio
async def test_marker_found_in_submission_response():
    """POST response itself immediately contains the submitted marker → confirmed."""
    form = FormData(
        action_url="http://example.com/guestbook",
        method="POST",
        inputs=[FormInput(name="message", type="text")],
    )
    async with _make_client(_ImmediateDisplayTransport("message")) as client:
        findings = await StoredXSSModule().run(set(), [form], [], client)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "xss_stored"
    assert f.confidence == "confirmed"
    assert f.affected_parameter == "message"
    # submission response has no display_url prefix
    assert "[Marker found at:" not in f.evidence_response


@pytest.mark.asyncio
async def test_html_encoded_output_no_finding():
    """Server HTML-encodes stored data → marker unrecognisable → no finding."""
    form = FormData(
        action_url="http://example.com/comments",
        method="POST",
        inputs=[FormInput(name="comment", type="text")],
    )
    target_urls = {"http://example.com/"}
    async with _make_client(_HtmlEncodingTransport("comment")) as client:
        findings = await StoredXSSModule().run(target_urls, [form], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_clean_server_no_finding():
    """Server never stores or echoes the marker → no finding."""
    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[FormInput(name="field", type="text")],
    )
    target_urls = {"http://example.com/", "http://example.com/page"}
    async with _make_client(_CleanTransport()) as client:
        findings = await StoredXSSModule().run(target_urls, [form], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_multiple_inputs_each_tested_independently():
    """Each injectable input gets its own unique marker and its own submission."""
    form = FormData(
        action_url="http://example.com/profile",
        method="POST",
        inputs=[
            FormInput(name="bio", type="text"),
            FormInput(name="website", type="text"),
        ],
    )
    # Storing transport reflects the LAST stored value; since each input is
    # tested separately, both will produce findings.
    target_urls = {"http://example.com/profiles"}
    async with _make_client(_StoringTransport("bio")) as client:
        # bio transport only reflects 'bio'; website injection won't be reflected.
        # So only bio → 1 finding.
        findings = await StoredXSSModule().run(target_urls, [form], [], client)
    assert len(findings) == 1
    assert findings[0].affected_parameter == "bio"


@pytest.mark.asyncio
async def test_both_inputs_vulnerable():
    """When both inputs are reflected, both generate findings."""

    class _ReflectAllTransport(httpx.AsyncBaseTransport):
        """Stores whatever is posted and reflects it regardless of param name."""

        def __init__(self) -> None:
            self._stored: str = ""

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                try:
                    body_params = parse_qs(request.content.decode("utf-8"))
                    for vals in body_params.values():
                        for v in vals:
                            if "xSsStored_" in v:
                                self._stored = v
                except Exception:
                    pass
                return httpx.Response(200, content=b"Saved.", request=request)
            content = f"<html><body>{self._stored}</body></html>".encode()
            return httpx.Response(200, content=content, request=request)

    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[
            FormInput(name="name", type="text"),
            FormInput(name="comment", type="text"),
        ],
    )
    target_urls = {"http://example.com/"}
    async with _make_client(_ReflectAllTransport()) as client:
        findings = await StoredXSSModule().run(target_urls, [form], [], client)
    assert len(findings) == 2
    params = {f.affected_parameter for f in findings}
    assert params == {"name", "comment"}


# ---------------------------------------------------------------------------
# Input filtering tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_forms_are_skipped():
    """GET forms are not tested — only POST forms can store data server-side."""
    form = FormData(
        action_url="http://example.com/search",
        method="GET",
        inputs=[FormInput(name="q", type="text")],
    )
    async with _make_client(_ImmediateDisplayTransport("q")) as client:
        findings = await StoredXSSModule().run(set(), [form], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_non_injectable_input_types_skipped():
    """submit/hidden/checkbox/radio/file inputs must not be tested."""
    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[
            FormInput(name="submit_btn", type="submit"),
            FormInput(name="_token", type="hidden"),
            FormInput(name="agree", type="checkbox"),
            FormInput(name="photo", type="file"),
            FormInput(name="comment", type="text"),
        ],
    )
    target_urls = {"http://example.com/"}
    async with _make_client(_StoringTransport("comment")) as client:
        findings = await StoredXSSModule().run(target_urls, [form], [], client)
    assert all(f.affected_parameter == "comment" for f in findings)


@pytest.mark.asyncio
async def test_url_parameters_are_ignored():
    """Stored XSS module only tests forms; URL parameters are not its concern."""
    param = ParameterData(url="http://example.com/?q=test", param_name="q", param_location="query")
    async with _make_client(_ImmediateDisplayTransport("q")) as client:
        findings = await StoredXSSModule().run(set(), [], [param], client)
    assert findings == []


@pytest.mark.asyncio
async def test_no_forms_returns_empty():
    async with _make_client(_CleanTransport()) as client:
        findings = await StoredXSSModule().run({"http://example.com/"}, [], [], client)
    assert findings == []


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_network_error_on_post_skipped_gracefully():
    """ConnectError during form submission → no crash, no finding."""
    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[FormInput(name="comment", type="text")],
    )
    async with _make_client(_PostFailsTransport()) as client:
        findings = await StoredXSSModule().run({"http://example.com/"}, [form], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_get_failure_skipped_scans_remaining_urls():
    """A ConnectError on one discovered URL must not abort scanning the rest."""
    form = FormData(
        action_url="http://example.com/form",
        method="POST",
        inputs=[FormInput(name="comment", type="text")],
    )
    fail_url = "http://example.com/broken"
    good_url = "http://example.com/works"
    transport = _SelectiveGetFailTransport("comment", fail_url)
    # target_urls order is non-deterministic (set), so include both
    target_urls = {fail_url, good_url}
    async with _make_client(transport) as client:
        findings = await StoredXSSModule().run(target_urls, [form], [], client)
    # The good_url should still be checked and the marker found there
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# _generate_marker unit tests
# ---------------------------------------------------------------------------


def test_generate_marker_format():
    marker = _generate_marker()
    assert marker.startswith("<script>/*xSsStored_")
    assert marker.endswith("*/</script>")


def test_generate_marker_unique():
    markers = {_generate_marker() for _ in range(50)}
    assert len(markers) > 1


def test_generate_marker_id_is_hex():
    marker = _generate_marker()
    # Extract the ID between "xSsStored_" and "*/"
    uid = marker.removeprefix("<script>/*xSsStored_").removesuffix("*/</script>")
    assert len(uid) == 12
    assert all(c in "0123456789abcdef" for c in uid)


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


def test_req_evidence_post_format():
    ev = _req_evidence("POST", "http://example.com/form", {"comment": "hello"})
    assert "POST /form HTTP/1.1" in ev
    assert "Host: example.com" in ev
    assert "Content-Type: application/x-www-form-urlencoded" in ev
    assert "comment=hello" in ev


def test_module_metadata():
    m = StoredXSSModule()
    assert m.name == "Stored XSS"
    assert m.vuln_types == ["xss_stored"]
