"""Tests for the IDOR detection portion of the BACModule."""
from __future__ import annotations

import re

import httpx
import pytest

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.bac import (
    BACModule,
    _content_differs,
    _numeric_segments,
    _probe_url,
    _req_evidence,
)
from app.utils.http_client import RateLimitedClient


# ---------------------------------------------------------------------------
# Mock transports
# ---------------------------------------------------------------------------


class _IDORTransport(httpx.AsyncBaseTransport):
    """Simulates IDOR: returns content unique to each numeric ID in the path.

    Body length = sum(all numeric segments) * 100 bytes of padding, ensuring
    that any single-ID change produces a >50-byte difference even for small IDs.
    """

    _SEG = re.compile(r"/(\d+)(?=/|$)")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        total = sum(int(m.group(1)) for m in self._SEG.finditer(path)) or 1
        body = (f"<html><body>{'x' * (total * 100)}</body></html>").encode()
        return httpx.Response(200, content=body, request=request)


class _AccessControlTransport(httpx.AsyncBaseTransport):
    """Returns 200 for one specific ID, 403 Forbidden for all others."""

    def __init__(self, allowed_id: int = 42) -> None:
        self._allowed = allowed_id
        self._SEG = re.compile(r"/(\d+)(?=/|$)")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        m = self._SEG.search(request.url.path)
        uid = int(m.group(1)) if m else -1
        if uid == self._allowed:
            return httpx.Response(
                200, content=b"<html><body>Your profile</body></html>", request=request
            )
        return httpx.Response(403, content=b"Forbidden", request=request)


class _SameContentTransport(httpx.AsyncBaseTransport):
    """Always returns identical content regardless of URL (e.g. a public listing)."""

    BODY = b"<html><body><p>Public listing page with lots of padding content here.</p></body></html>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self.BODY, request=request)


class _NotFoundTransport(httpx.AsyncBaseTransport):
    """Returns 200 for the base ID, 404 for adjacent IDs."""

    def __init__(self, base_id: int = 42) -> None:
        self._base = base_id
        self._SEG = re.compile(r"/(\d+)(?=/|$)")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        m = self._SEG.search(request.url.path)
        uid = int(m.group(1)) if m else -1
        if uid == self._base:
            return httpx.Response(200, content=b"<html>Item 42</html>", request=request)
        return httpx.Response(404, content=b"Not Found", request=request)


class _NetworkErrorTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")


class _OriginalFailsProbeSucceedsTransport(httpx.AsyncBaseTransport):
    """Fails the first request (the original URL fetch), succeeds on probes."""

    def __init__(self) -> None:
        self._calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._calls += 1
        if self._calls == 1:
            raise httpx.ConnectError("refused")
        return httpx.Response(200, content=b"<html>ok</html>", request=request)


def _make_client(transport: httpx.AsyncBaseTransport) -> RateLimitedClient:
    return RateLimitedClient(rate_limit=100, timeout=5.0, _transport=transport)


# ---------------------------------------------------------------------------
# Core IDOR detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_idor_detected_for_numeric_id_in_path():
    """Adjacent ID returns 200 with different content → tentative IDOR finding."""
    urls = {"http://example.com/users/42"}
    async with _make_client(_IDORTransport()) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "idor"
    assert f.confidence == "tentative"
    assert f.affected_url == "http://example.com/users/42"
    assert "path:42" in f.affected_parameter
    assert "/users/" in f.payload_used        # probe URL recorded
    assert "42" not in f.payload_used.split("/users/")[1].split("/")[0]  # ID was changed


@pytest.mark.asyncio
async def test_idor_finding_contains_both_urls_in_evidence():
    urls = {"http://example.com/profile/10"}
    async with _make_client(_IDORTransport()) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert len(findings) >= 1
    ev = findings[0].evidence_response
    assert "http://example.com/profile/10" in ev
    assert "[Original]" in ev
    assert "[Probe]" in ev


@pytest.mark.asyncio
async def test_access_control_blocks_adjacent_id_no_finding():
    """403 returned for adjacent IDs → access control works, no finding."""
    urls = {"http://example.com/users/42"}
    async with _make_client(_AccessControlTransport(allowed_id=42)) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_same_content_for_all_ids_no_finding():
    """Identical body for original and probe → not flagged as IDOR."""
    urls = {"http://example.com/items/5"}
    async with _make_client(_SameContentTransport()) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_404_for_adjacent_id_no_finding():
    """Probe returns 404 (resource doesn't exist) → not an IDOR finding."""
    urls = {"http://example.com/posts/42"}
    async with _make_client(_NotFoundTransport(base_id=42)) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_original_non_200_is_skipped():
    """If the original URL doesn't return 200, skip it entirely."""
    urls = {"http://example.com/users/99"}
    # Access control transport returns 403 for ID 99 (only allows 42)
    async with _make_client(_AccessControlTransport(allowed_id=42)) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_url_without_numeric_segment_skipped():
    """URLs with no numeric path segments produce no findings."""
    urls = {"http://example.com/about", "http://example.com/users/profile/settings"}
    async with _make_client(_IDORTransport()) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_empty_target_urls_returns_empty():
    async with _make_client(_IDORTransport()) as client:
        findings = await BACModule().run(set(), [], [], client)
    assert findings == []


# ---------------------------------------------------------------------------
# Adjacent offset behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_negative_id_not_probed():
    """ID=1, offset=-1 gives ID=0 which must be skipped (IDs ≤ 0 are invalid)."""
    urls = {"http://example.com/users/1"}
    async with _make_client(_IDORTransport()) as client:
        findings = await BACModule().run(urls, [], [], client)
    # Offsets +1 and +2 are valid; -1 gives 0 and is skipped
    probed_ids = [int(re.search(r"/users/(\d+)", f.payload_used).group(1)) for f in findings]
    assert 0 not in probed_ids


@pytest.mark.asyncio
async def test_one_finding_per_segment_stops_after_first_hit():
    """Once one adjacent ID triggers a finding, the remaining offsets are not probed."""
    request_count = 0

    class _CountingTransport(httpx.AsyncBaseTransport):
        _SEG = re.compile(r"/(\d+)(?=/|$)")

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            m = self._SEG.search(request.url.path)
            uid = int(m.group(1)) if m else 1
            body = (f"<html>{'x' * uid * 100}</html>").encode()
            return httpx.Response(200, content=body, request=request)

    urls = {"http://example.com/item/10"}
    async with _make_client(_CountingTransport()) as client:
        findings = await BACModule().run(urls, [], [], client)
    # Only 1 finding per segment; the second and third offsets should NOT be probed
    assert len(findings) == 1
    # original (1) + first successful probe (1) = 2 requests total
    assert request_count == 2


# ---------------------------------------------------------------------------
# Multiple URLs and multiple segments
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multiple_urls_each_tested_independently():
    urls = {"http://example.com/users/10", "http://example.com/posts/20"}
    async with _make_client(_IDORTransport()) as client:
        findings = await BACModule().run(urls, [], [], client)
    affected = {f.affected_url for f in findings}
    assert "http://example.com/users/10" in affected
    assert "http://example.com/posts/20" in affected


@pytest.mark.asyncio
async def test_multiple_numeric_segments_each_tested():
    """A URL like /users/42/posts/7 should test both segments."""
    url = "http://example.com/users/42/posts/7"
    async with _make_client(_IDORTransport()) as client:
        findings = await BACModule().run({url}, [], [], client)
    params = {f.affected_parameter for f in findings}
    # Both segments should produce a finding
    assert "path:42" in params
    assert "path:7" in params


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_network_error_on_original_fetch_skipped():
    """ConnectError fetching the original URL → no crash, no finding."""
    urls = {"http://example.com/users/42"}
    async with _make_client(_NetworkErrorTransport()) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_network_error_on_probe_skipped_continues():
    """ConnectError on a probe → skip that probe, try next offset."""

    class _ProbeFailsAfterOriginal(httpx.AsyncBaseTransport):
        _SEG = re.compile(r"/(\d+)(?=/|$)")
        _calls = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self._calls += 1
            if self._calls == 1:
                # Original fetch succeeds
                return httpx.Response(
                    200, content=b"<html><body>original</body></html>", request=request
                )
            if self._calls == 2:
                # First probe fails
                raise httpx.ConnectError("refused")
            # Second probe returns clearly different content (>50 bytes longer than original)
            return httpx.Response(
                200,
                content=b"<html><body>" + b"x" * 200 + b"</body></html>",
                request=request,
            )

    urls = {"http://example.com/items/5"}
    async with _make_client(_ProbeFailsAfterOriginal()) as client:
        findings = await BACModule().run(urls, [], [], client)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# _numeric_segments unit tests
# ---------------------------------------------------------------------------


def test_numeric_segments_simple_id():
    segs = _numeric_segments("/users/42")
    assert len(segs) == 1
    assert segs[0] == ("42", 7)


def test_numeric_segments_multiple():
    segs = _numeric_segments("/users/42/posts/7")
    values = [s[0] for s in segs]
    assert "42" in values
    assert "7" in values


def test_numeric_segments_none():
    assert _numeric_segments("/users/profile/settings") == []


def test_numeric_segments_version_not_matched():
    """Numeric segment in /api/v1/ is NOT preceded by '/', so NOT matched."""
    segs = _numeric_segments("/api/v1/users/99")
    values = [s[0] for s in segs]
    assert "1" not in values
    assert "99" in values


def test_numeric_segments_trailing_id():
    segs = _numeric_segments("/product/123")
    assert segs[0][0] == "123"


def test_numeric_segments_preserves_start_position():
    segs = _numeric_segments("/a/10/b/20")
    assert segs[0] == ("10", 3)
    assert segs[1] == ("20", 8)


# ---------------------------------------------------------------------------
# _probe_url unit tests
# ---------------------------------------------------------------------------


def test_probe_url_replaces_segment():
    result = _probe_url("http://example.com/users/42", "42", 7, 43)
    assert result == "http://example.com/users/43"


def test_probe_url_preserves_query_string():
    result = _probe_url("http://example.com/items/10?page=2", "10", 7, 11)
    assert result == "http://example.com/items/11?page=2"


def test_probe_url_replaces_first_segment_only():
    result = _probe_url("http://example.com/users/5/posts/5", "5", 7, 6)
    assert result == "http://example.com/users/6/posts/5"


def test_probe_url_replaces_second_segment():
    # /users/5/posts/5 — second '5' is at path index 15 (after '/posts/')
    result = _probe_url("http://example.com/users/5/posts/5", "5", 15, 6)
    assert result == "http://example.com/users/5/posts/6"


# ---------------------------------------------------------------------------
# _content_differs unit tests
# ---------------------------------------------------------------------------


def _fake_response(body: bytes) -> httpx.Response:
    req = httpx.Request("GET", "http://example.com/")
    return httpx.Response(200, content=body, request=req)


def test_content_differs_large_length_gap():
    r1 = _fake_response(b"x" * 200)
    r2 = _fake_response(b"y" * 20)
    assert _content_differs(r1, r2)


def test_content_same_not_different():
    body = b"<html>Same content</html>"
    assert not _content_differs(_fake_response(body), _fake_response(body))


def test_content_differs_small_gap_not_flagged():
    r1 = _fake_response(b"a" * 100)
    r2 = _fake_response(b"a" * 110)  # only 10-byte difference
    assert not _content_differs(r1, r2)


def test_content_differs_exact_threshold():
    r1 = _fake_response(b"a" * 100)
    r2 = _fake_response(b"b" * 151)  # 51 bytes difference → flagged
    assert _content_differs(r1, r2)


# ---------------------------------------------------------------------------
# _req_evidence unit tests
# ---------------------------------------------------------------------------


def test_req_evidence_format():
    ev = _req_evidence("http://example.com/users/43")
    assert ev.startswith("GET /users/43 HTTP/1.1")
    assert "Host: example.com" in ev


def test_req_evidence_includes_query():
    ev = _req_evidence("http://example.com/items/5?sort=asc")
    assert "?sort=asc" in ev


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------


def test_module_metadata():
    m = BACModule()
    assert m.name == "Broken Access Control"
    assert "idor" in m.vuln_types
