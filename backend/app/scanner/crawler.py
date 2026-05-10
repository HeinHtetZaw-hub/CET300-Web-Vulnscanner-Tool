from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from app.utils.http_client import RateLimitedClient, ScannerHTTPError

# File extensions that are never HTML — skip without fetching
_SKIP_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".js", ".ts", ".map",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dmg", ".pkg", ".deb", ".rpm",
    ".xml", ".json", ".csv", ".txt",
})

# Regex: a pure-numeric path segment  (e.g. /users/42/posts)
_NUMERIC_SEGMENT = re.compile(r"^\d+$")


@dataclass
class FormInput:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class FormData:
    action_url: str
    method: str           # "GET" or "POST"
    inputs: list[FormInput] = field(default_factory=list)


@dataclass
class ParameterData:
    url: str
    param_name: str
    param_location: str   # "query" | "path"


@dataclass
class CrawlResult:
    discovered_urls: set[str] = field(default_factory=set)
    forms: list[FormData] = field(default_factory=list)
    parameters: list[ParameterData] = field(default_factory=list)


class Crawler:
    """BFS web crawler that discovers URLs, forms, and injectable parameters.

    Args:
        base_url:    Starting point; only same-origin URLs are followed.
        http_client: Rate-limited httpx wrapper (injected for testability).
        max_depth:   Maximum link depth from base_url (default 3).
        max_pages:   Hard cap on total pages fetched (default 500).
        on_progress: Optional callback ``fn(pages_crawled, total_queued)``.
    """

    def __init__(
        self,
        base_url: str,
        http_client: RateLimitedClient,
        max_depth: int = 3,
        max_pages: int = 500,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._origin = _origin(base_url)
        self._client = http_client
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._on_progress = on_progress

    async def crawl(self) -> CrawlResult:
        result = CrawlResult()
        visited: set[str] = set()

        queue: deque[tuple[str, int]] = deque()
        start = _normalise(self._base_url)
        queue.append((start, 0))
        visited.add(start)
        result.discovered_urls.add(start)

        pages_crawled = 0

        while queue:
            url, depth = queue.popleft()

            if pages_crawled >= self._max_pages:
                break

            if self._on_progress:
                self._on_progress(pages_crawled, len(queue) + pages_crawled + 1)

            # Fetch the page
            try:
                response = await self._client.get(url)
            except ScannerHTTPError:
                continue

            if not _is_html(response.headers.get("content-type", "")):
                continue

            pages_crawled += 1
            _extract_parameters(url, result)

            if response.status_code not in range(200, 400):
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            _extract_forms(url, soup, result)

            if depth >= self._max_depth:
                continue

            for link in _extract_links(url, soup, self._origin):
                norm = _normalise(link)
                if norm not in visited:
                    visited.add(norm)
                    result.discovered_urls.add(norm)
                    _extract_parameters(norm, result)
                    queue.append((norm, depth + 1))

        if self._on_progress:
            self._on_progress(pages_crawled, pages_crawled)

        return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _origin(url: str) -> str:
    """Return scheme + netloc, e.g. 'https://example.com'."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _normalise(url: str) -> str:
    """Strip fragment; lowercase scheme and host; remove default ports; ensure path."""
    p = urlparse(url)
    netloc = p.netloc.lower()
    # strip default port numbers
    if (p.scheme == "http" and netloc.endswith(":80")) or \
       (p.scheme == "https" and netloc.endswith(":443")):
        netloc = netloc.rsplit(":", 1)[0]
    path = p.path if p.path else "/"   # bare host → always at least "/"
    return urlunparse((p.scheme.lower(), netloc, path, p.params, p.query, ""))


def _is_html(content_type: str) -> bool:
    ct = content_type.lower()
    return "text/html" in ct or "application/xhtml" in ct


def _should_skip(url: str) -> bool:
    path = urlparse(url).path.lower()
    dot = path.rfind(".")
    if dot != -1:
        ext = path[dot:]
        return ext in _SKIP_EXTENSIONS
    return False


def _extract_links(page_url: str, soup: BeautifulSoup, origin: str) -> list[str]:
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absolute = urljoin(page_url, href)
        p = urlparse(absolute)
        if f"{p.scheme}://{p.netloc}" != origin:
            continue
        if _should_skip(absolute):
            continue
        links.append(absolute)
    return links


def _extract_forms(page_url: str, soup: BeautifulSoup, result: CrawlResult) -> None:
    for form_tag in soup.find_all("form"):
        action = form_tag.get("action", "")
        action_url = urljoin(page_url, action) if action else page_url
        method = (form_tag.get("method", "GET") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        inputs: list[FormInput] = []
        for tag in form_tag.find_all(["input", "select", "textarea"]):
            name = tag.get("name", "").strip()
            if not name:
                continue
            inputs.append(FormInput(
                name=name,
                type=(tag.get("type") or "text").lower(),
                value=tag.get("value", ""),
            ))

        # Skip forms with no testable inputs
        if inputs:
            result.forms.append(FormData(
                action_url=action_url,
                method=method,
                inputs=inputs,
            ))


def _extract_parameters(url: str, result: CrawlResult) -> None:
    p = urlparse(url)

    # Query-string parameters
    for name in parse_qs(p.query, keep_blank_values=True):
        result.parameters.append(ParameterData(
            url=url, param_name=name, param_location="query"
        ))

    # Numeric path segments → potential IDOR targets
    segments = [s for s in p.path.split("/") if s]
    for i, seg in enumerate(segments):
        if _NUMERIC_SEGMENT.match(seg):
            label = segments[i - 1] if i > 0 else "id"
            result.parameters.append(ParameterData(
                url=url, param_name=label, param_location="path"
            ))
