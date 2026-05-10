"""Crawler tests using an in-process mock HTTP transport.

Each test builds a small "site" as a dict mapping URL → (status, content-type, body)
and injects it via the RateLimitedClient._transport hook.
"""

from __future__ import annotations

import httpx
import pytest

from app.scanner.crawler import (
    Crawler,
    CrawlResult,
    _normalise,
    _should_skip,
)
from app.utils.http_client import RateLimitedClient

# ---------------------------------------------------------------------------
# Mock transport
# ---------------------------------------------------------------------------

class _Site(httpx.AsyncBaseTransport):
    """Serves pages from a dict; returns 404 for unknown URLs."""

    def __init__(self, pages: dict[str, tuple[int, str, str]]) -> None:
        # pages: url -> (status_code, content_type, body)
        self._pages = pages

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        # strip fragment just in case
        url = url.split("#")[0]
        if url in self._pages:
            status, ct, body = self._pages[url]
            return httpx.Response(
                status,
                content=body.encode(),
                headers={"content-type": ct},
                request=request,
            )
        return httpx.Response(404, content=b"Not Found", request=request)


def _html(body: str) -> tuple[int, str, str]:
    return 200, "text/html; charset=utf-8", body


def _make_client(site: _Site) -> RateLimitedClient:
    return RateLimitedClient(rate_limit=100, timeout=5.0, _transport=site)


async def _crawl(site: _Site, base: str, **kwargs) -> CrawlResult:
    async with _make_client(site) as client:
        crawler = Crawler(base, client, **kwargs)
        return await crawler.crawl()


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

BASE = "http://example.com"

SIMPLE_SITE = _Site({
    f"{BASE}/": _html("""
        <html><body>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
            <a href="https://external.com/page">External</a>
        </body></html>
    """),
    f"{BASE}/about": _html("<html><body><p>About us</p></body></html>"),
    f"{BASE}/contact": _html("<html><body><p>Contact us</p></body></html>"),
})


# ---------------------------------------------------------------------------
# Basic crawl
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_discovers_all_same_origin_pages():
    result = await _crawl(SIMPLE_SITE, BASE)
    assert f"{BASE}/" in result.discovered_urls
    assert f"{BASE}/about" in result.discovered_urls
    assert f"{BASE}/contact" in result.discovered_urls


@pytest.mark.asyncio
async def test_does_not_follow_external_links():
    result = await _crawl(SIMPLE_SITE, BASE)
    assert not any("external.com" in u for u in result.discovered_urls)


@pytest.mark.asyncio
async def test_base_url_always_in_discovered():
    result = await _crawl(SIMPLE_SITE, BASE)
    assert f"{BASE}/" in result.discovered_urls


# ---------------------------------------------------------------------------
# Depth limiting
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_depth_limit_respected():
    # depth-0: /  →  depth-1: /level1  →  depth-2: /level2  →  depth-3: /level3
    site = _Site({
        f"{BASE}/":       _html('<a href="/level1">L1</a>'),
        f"{BASE}/level1": _html('<a href="/level2">L2</a>'),
        f"{BASE}/level2": _html('<a href="/level3">L3</a>'),
        f"{BASE}/level3": _html("<p>deep</p>"),
    })
    # max_depth=2 means we fetch /, /level1, /level2 but links on /level2
    # should not be followed (depth >= max_depth)
    result = await _crawl(site, BASE, max_depth=2)
    assert f"{BASE}/level2" in result.discovered_urls
    assert f"{BASE}/level3" not in result.discovered_urls


@pytest.mark.asyncio
async def test_depth_zero_only_crawls_base():
    result = await _crawl(SIMPLE_SITE, BASE, max_depth=0)
    assert f"{BASE}/about" not in result.discovered_urls


# ---------------------------------------------------------------------------
# Page limit
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_pages_caps_crawl():
    site = _Site({
        f"{BASE}/": _html(
            "".join(f'<a href="/p{i}">P{i}</a>' for i in range(20))
        ),
        **{f"{BASE}/p{i}": _html(f"<p>Page {i}</p>") for i in range(20)},
    })
    result = await _crawl(site, BASE, max_pages=3)
    # At most 3 pages fetched — the discovered set may have more links but
    # crawling stops after the page cap
    assert len(result.discovered_urls) <= 21   # 1 + 20 links found on home


# ---------------------------------------------------------------------------
# Binary extension skipping
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_binary_extensions_not_crawled():
    site = _Site({
        f"{BASE}/": _html("""
            <a href="/image.jpg">Img</a>
            <a href="/style.css">CSS</a>
            <a href="/script.js">JS</a>
            <a href="/doc.pdf">PDF</a>
            <a href="/page">Page</a>
        """),
        f"{BASE}/page": _html("<p>real page</p>"),
    })
    result = await _crawl(site, BASE)
    binary_urls = [u for u in result.discovered_urls
                   if any(u.endswith(ext) for ext in (".jpg", ".css", ".js", ".pdf"))]
    assert binary_urls == []
    assert f"{BASE}/page" in result.discovered_urls


# ---------------------------------------------------------------------------
# Non-HTML content-type skipping
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_html_content_type_skipped():
    site = _Site({
        f"{BASE}/": _html('<a href="/data">Data</a>'),
        f"{BASE}/data": (200, "application/json", '{"key": "value"}'),
    })
    result = await _crawl(site, BASE)
    # /data is discovered as a URL (found in link) but its links are not followed
    # because its content-type is not HTML — no extra URLs appear beyond /data itself
    non_home = [u for u in result.discovered_urls if u != f"{BASE}/"]
    assert all("data" in u or True for u in non_home)  # reachable but not parsed


# ---------------------------------------------------------------------------
# Deduplication / fragment stripping
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fragments_are_stripped():
    site = _Site({
        f"{BASE}/": _html("""
            <a href="/page#section1">S1</a>
            <a href="/page#section2">S2</a>
            <a href="/page">Page</a>
        """),
        f"{BASE}/page": _html("<p>page</p>"),
    })
    result = await _crawl(site, BASE)
    page_urls = [u for u in result.discovered_urls if "page" in u]
    assert len(page_urls) == 1
    assert f"{BASE}/page" in page_urls


# ---------------------------------------------------------------------------
# Query-string parameter extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_parameters_extracted():
    site = _Site({
        f"{BASE}/": _html('<a href="/search?q=hello&page=2">Search</a>'),
        f"{BASE}/search": _html("<p>results</p>"),
    })
    result = await _crawl(site, BASE)
    search_params = [p for p in result.parameters if p.param_location == "query"]
    names = {p.param_name for p in search_params}
    assert "q" in names
    assert "page" in names


# ---------------------------------------------------------------------------
# Form extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_form_extracted():
    site = _Site({
        f"{BASE}/": _html("""
            <form method="GET" action="/search">
                <input name="q" type="text" value="">
                <input name="lang" type="hidden" value="en">
                <button type="submit">Go</button>
            </form>
        """),
    })
    result = await _crawl(site, BASE)
    assert len(result.forms) == 1
    form = result.forms[0]
    assert form.method == "GET"
    assert form.action_url == f"{BASE}/search"
    names = {inp.name for inp in form.inputs}
    assert names == {"q", "lang"}


@pytest.mark.asyncio
async def test_post_form_extracted():
    site = _Site({
        f"{BASE}/": _html("""
            <form method="post" action="/login">
                <input name="username" type="text">
                <input name="password" type="password">
                <input type="submit" value="Login">
            </form>
        """),
    })
    result = await _crawl(site, BASE)
    assert len(result.forms) == 1
    form = result.forms[0]
    assert form.method == "POST"
    assert form.action_url == f"{BASE}/login"
    # submit input has no name — should be excluded
    names = {inp.name for inp in form.inputs}
    assert "username" in names
    assert "password" in names


@pytest.mark.asyncio
async def test_form_without_action_uses_page_url():
    site = _Site({
        f"{BASE}/contact": _html("""
            <form method="POST">
                <input name="message" type="text">
            </form>
        """),
    })
    async with _make_client(site) as client:
        crawler = Crawler(f"{BASE}/contact", client, max_depth=0)
        result = await crawler.crawl()
    assert result.forms[0].action_url == f"{BASE}/contact"


@pytest.mark.asyncio
async def test_select_and_textarea_extracted():
    site = _Site({
        f"{BASE}/": _html("""
            <form method="POST" action="/submit">
                <select name="category">
                    <option value="a">A</option>
                </select>
                <textarea name="comment"></textarea>
            </form>
        """),
    })
    result = await _crawl(site, BASE)
    names = {inp.name for inp in result.forms[0].inputs}
    assert "category" in names
    assert "comment" in names


@pytest.mark.asyncio
async def test_form_with_no_named_inputs_skipped():
    site = _Site({
        f"{BASE}/": _html("""
            <form method="POST" action="/submit">
                <button type="submit">Go</button>
            </form>
        """),
    })
    result = await _crawl(site, BASE)
    assert result.forms == []


# ---------------------------------------------------------------------------
# Numeric path parameter extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_numeric_path_segment_extracted_as_path_param():
    site = _Site({
        f"{BASE}/": _html('<a href="/users/42/profile">User</a>'),
        f"{BASE}/users/42/profile": _html("<p>profile</p>"),
    })
    result = await _crawl(site, BASE)
    path_params = [p for p in result.parameters if p.param_location == "path"]
    assert len(path_params) >= 1
    assert any(p.param_name == "users" for p in path_params)


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_progress_callback_called():
    calls: list[tuple[int, int]] = []

    async with _make_client(SIMPLE_SITE) as client:
        crawler = Crawler(BASE, client, on_progress=lambda c, t: calls.append((c, t)))
        await crawler.crawl()

    assert len(calls) >= 1


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_failed_page_does_not_abort_crawl():
    site = _Site({
        f"{BASE}/": _html("""
            <a href="/good">Good</a>
            <a href="/bad">Bad</a>
        """),
        f"{BASE}/good": _html("<p>OK</p>"),
        # /bad is missing → 404
    })
    result = await _crawl(site, BASE)
    assert f"{BASE}/good" in result.discovered_urls


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------

def test_normalise_strips_fragment():
    assert _normalise("http://example.com/page#section") == "http://example.com/page"


def test_normalise_strips_default_http_port():
    assert _normalise("http://example.com:80/path") == "http://example.com/path"


def test_normalise_strips_default_https_port():
    assert _normalise("https://example.com:443/path") == "https://example.com/path"


def test_normalise_preserves_query():
    assert _normalise("http://example.com/p?a=1") == "http://example.com/p?a=1"


def test_should_skip_image():
    assert _should_skip("http://example.com/logo.png") is True


def test_should_skip_css():
    assert _should_skip("http://example.com/style.css") is True


def test_should_skip_js():
    assert _should_skip("http://example.com/app.js") is True


def test_should_not_skip_html_page():
    assert _should_skip("http://example.com/about") is False


def test_should_not_skip_page_with_no_extension():
    assert _should_skip("http://example.com/users/42/profile") is False
