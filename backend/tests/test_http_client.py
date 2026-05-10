import asyncio
from unittest.mock import patch

import httpx
import pytest

from app.utils.http_client import RateLimitedClient, ScannerHTTPError, _TokenBucket

# ---------------------------------------------------------------------------
# Mock transports
# ---------------------------------------------------------------------------

class _StaticTransport(httpx.AsyncBaseTransport):
    """Returns a fixed response for every request."""

    def __init__(self, status_code: int = 200, content: bytes = b"OK") -> None:
        self._status_code = status_code
        self._content = content
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self._status_code, content=self._content, request=request)


class _ErrorTransport(httpx.AsyncBaseTransport):
    """Raises a given exception for every request."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise self._exc


def _client(transport: httpx.AsyncBaseTransport, rate_limit: int = 100) -> RateLimitedClient:
    """Create a fast client (high rate limit) backed by a mock transport."""
    return RateLimitedClient(rate_limit=rate_limit, timeout=5.0, _transport=transport)


# ---------------------------------------------------------------------------
# Basic HTTP methods
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_returns_response():
    transport = _StaticTransport(200, b"hello")
    async with _client(transport) as c:
        response = await c.get("http://example.com")
    assert response.status_code == 200
    assert response.content == b"hello"


@pytest.mark.asyncio
async def test_post_returns_response():
    transport = _StaticTransport(201, b"created")
    async with _client(transport) as c:
        response = await c.post("http://example.com/items", data={"key": "val"})
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_head_returns_response():
    transport = _StaticTransport(200, b"")
    async with _client(transport) as c:
        response = await c.head("http://example.com")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_4xx_response_is_returned_not_raised():
    """HTTP 4xx are valid responses, not exceptions — the caller decides what to do."""
    async with _client(_StaticTransport(404)) as c:
        response = await c.get("http://example.com/missing")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_5xx_response_is_returned_not_raised():
    async with _client(_StaticTransport(500)) as c:
        response = await c.get("http://example.com/error")
    assert response.status_code == 500


# ---------------------------------------------------------------------------
# User-Agent header
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_user_agent_header_is_sent():
    transport = _StaticTransport()
    async with RateLimitedClient(
        rate_limit=100, timeout=5.0, user_agent="TestAgent/9", _transport=transport
    ) as c:
        await c.get("http://example.com")
    assert transport.requests[0].headers["user-agent"] == "TestAgent/9"


@pytest.mark.asyncio
async def test_default_user_agent_contains_vulnscanner():
    transport = _StaticTransport()
    async with RateLimitedClient(rate_limit=100, timeout=5.0, _transport=transport) as c:
        await c.get("http://example.com")
    assert "VulnScanner" in transport.requests[0].headers["user-agent"]


# ---------------------------------------------------------------------------
# Network error handling → ScannerHTTPError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_timeout_raises_scanner_http_error():
    transport = _ErrorTransport(httpx.ReadTimeout("timed out", request=None))
    async with _client(transport) as c:
        with pytest.raises(ScannerHTTPError, match="timed out"):
            await c.get("http://example.com")


@pytest.mark.asyncio
async def test_connect_error_raises_scanner_http_error():
    transport = _ErrorTransport(httpx.ConnectError("refused"))
    async with _client(transport) as c:
        with pytest.raises(ScannerHTTPError, match="Connection failed"):
            await c.get("http://example.com")


@pytest.mark.asyncio
async def test_too_many_redirects_raises_scanner_http_error():
    transport = _ErrorTransport(httpx.TooManyRedirects("redirect loop", request=None))
    async with _client(transport) as c:
        with pytest.raises(ScannerHTTPError, match="Too many redirects"):
            await c.get("http://example.com")


@pytest.mark.asyncio
async def test_scanner_http_error_carries_url():
    transport = _ErrorTransport(httpx.ConnectError("refused"))
    async with _client(transport) as c:
        with pytest.raises(ScannerHTTPError) as exc_info:
            await c.get("http://example.com/path")
    assert exc_info.value.url == "http://example.com/path"


@pytest.mark.asyncio
async def test_scanner_http_error_carries_cause():
    original = httpx.ConnectError("refused")
    transport = _ErrorTransport(original)
    async with _client(transport) as c:
        with pytest.raises(ScannerHTTPError) as exc_info:
            await c.get("http://example.com")
    assert exc_info.value.cause is original


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_async_context_manager_closes_client():
    transport = _StaticTransport()
    client = _client(transport)
    async with client as c:
        await c.get("http://example.com")
    # After exit the underlying httpx client should be closed
    assert c._client.is_closed


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limit_calls_sleep_when_bucket_empty():
    """With rate_limit=1, a second back-to-back request must trigger asyncio.sleep."""
    transport = _StaticTransport()
    sleep_calls: list[float] = []

    original_sleep = asyncio.sleep

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)
        # Don't actually sleep in tests
        await original_sleep(0)

    client = RateLimitedClient(rate_limit=1, timeout=5.0, _transport=transport)
    with patch("app.utils.http_client.asyncio.sleep", side_effect=fake_sleep):
        async with client as c:
            await c.get("http://example.com")   # consumes the 1 token
            await c.get("http://example.com")   # bucket empty → should sleep

    assert len(sleep_calls) >= 1
    assert sleep_calls[0] > 0


@pytest.mark.asyncio
async def test_high_rate_limit_does_not_sleep():
    """With rate_limit=1000, rapid requests should not trigger sleep."""
    transport = _StaticTransport()
    sleep_calls: list[float] = []

    original_sleep = asyncio.sleep

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)
        await original_sleep(0)

    client = RateLimitedClient(rate_limit=1000, timeout=5.0, _transport=transport)
    with patch("app.utils.http_client.asyncio.sleep", side_effect=fake_sleep):
        async with client as c:
            for _ in range(5):
                await c.get("http://example.com")

    assert sleep_calls == []


# ---------------------------------------------------------------------------
# TokenBucket unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_token_bucket_allows_first_request_immediately():
    bucket = _TokenBucket(rate=1.0, capacity=1.0)
    slept: list[float] = []

    async def fake_sleep(d: float) -> None:
        slept.append(d)

    with patch("app.utils.http_client.asyncio.sleep", side_effect=fake_sleep):
        await bucket.acquire()

    assert slept == []


@pytest.mark.asyncio
async def test_token_bucket_sleeps_when_empty():
    bucket = _TokenBucket(rate=1.0, capacity=1.0)
    slept: list[float] = []

    async def fake_sleep(d: float) -> None:
        slept.append(d)

    with patch("app.utils.http_client.asyncio.sleep", side_effect=fake_sleep):
        await bucket.acquire()  # consumes the 1 token
        await bucket.acquire()  # should sleep

    assert len(slept) == 1
    assert 0.9 <= slept[0] <= 1.1  # approximately 1 second


@pytest.mark.asyncio
async def test_token_bucket_capacity_caps_burst():
    """Even after a long idle, tokens never exceed capacity."""
    bucket = _TokenBucket(rate=10.0, capacity=5.0)
    # Simulate a long idle by rewinding _last
    bucket._tokens = 5.0
    bucket._last -= 100.0  # "100 seconds ago"

    slept: list[float] = []

    async def fake_sleep(d: float) -> None:
        slept.append(d)  # pragma: no cover

    with patch("app.utils.http_client.asyncio.sleep", side_effect=fake_sleep):
        for _ in range(5):
            await bucket.acquire()  # all 5 should be free

    assert slept == []
    # 6th request should need to sleep
    with patch("app.utils.http_client.asyncio.sleep", side_effect=fake_sleep):
        await bucket.acquire()
    assert len(slept) == 1


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------

def test_create_client_returns_rate_limited_client():
    from app.utils.http_client import create_client
    client = create_client(rate_limit=5, timeout=3.0)
    assert isinstance(client, RateLimitedClient)
    # bucket rate should match what was passed
    assert client._bucket._rate == 5
