import asyncio
import time
from types import TracebackType
from typing import Any

import httpx

from app.config import settings


class ScannerHTTPError(Exception):
    """Raised when a network-level error prevents a response from being received."""

    def __init__(self, message: str, url: str = "", cause: Exception | None = None) -> None:
        super().__init__(message)
        self.url = url
        self.cause = cause


class _TokenBucket:
    """Asyncio-safe token bucket for rate limiting.

    Tokens refill continuously at *rate* per second up to *capacity*.
    Each request consumes one token; if none are available the caller
    sleeps until one becomes available.
    """

    def __init__(self, rate: float, capacity: float) -> None:
        self._rate = rate
        self._capacity = capacity
        self._tokens: float = capacity
        self._last: float = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
            else:
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
                self._last = time.monotonic()


class RateLimitedClient:
    """httpx.AsyncClient wrapper that enforces a per-second request rate limit.

    Usage::

        async with RateLimitedClient() as client:
            response = await client.get("https://example.com")

    Args:
        rate_limit: Maximum requests per second (default: settings.RATE_LIMIT_RPS).
        timeout:    Per-request timeout in seconds (default: settings.HTTP_TIMEOUT).
        user_agent: Value for the User-Agent header.
        _transport: Inject a custom httpx transport — used in tests only.
    """

    def __init__(
        self,
        rate_limit: int = 0,
        timeout: float = 0.0,
        user_agent: str = "",
        _transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        rps = rate_limit or settings.RATE_LIMIT_RPS
        tmo = timeout or settings.HTTP_TIMEOUT
        ua = user_agent or settings.USER_AGENT

        self._bucket = _TokenBucket(rate=rps, capacity=rps)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(tmo),
            headers={"User-Agent": ua},
            follow_redirects=True,
            transport=_transport,
        )

    # ------------------------------------------------------------------
    # Public request methods
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, data: Any = None, **kwargs: Any) -> httpx.Response:
        return await self._request("POST", url, data=data, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("HEAD", url, **kwargs)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        await self._bucket.acquire()
        try:
            return await self._client.request(method, url, **kwargs)
        except httpx.TimeoutException as exc:
            raise ScannerHTTPError(f"Request timed out: {url}", url=url, cause=exc) from exc
        except httpx.ConnectError as exc:
            raise ScannerHTTPError(
                f"Connection failed: {url}", url=url, cause=exc
            ) from exc
        except httpx.TooManyRedirects as exc:
            raise ScannerHTTPError(
                f"Too many redirects: {url}", url=url, cause=exc
            ) from exc
        except httpx.HTTPError as exc:
            raise ScannerHTTPError(
                f"HTTP error for {url}: {exc}", url=url, cause=exc
            ) from exc

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "RateLimitedClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.aclose()


def create_client(
    rate_limit: int = 0,
    timeout: float = 0.0,
    user_agent: str = "",
) -> RateLimitedClient:
    """Factory that creates a RateLimitedClient from application settings."""
    return RateLimitedClient(rate_limit=rate_limit, timeout=timeout, user_agent=user_agent)
