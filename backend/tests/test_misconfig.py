"""Tests for the security misconfiguration detection module."""
from __future__ import annotations

import re

import httpx
import pytest

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.misconfig import (
    MisconfigModule,
    _MAX_HEADER_SAMPLE,
    _SECURITY_HEADERS,
    _missing_headers,
    _site_root,
    _validate_file_content,
)
from app.utils.http_client import RateLimitedClient

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_ALL_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


# ---------------------------------------------------------------------------
# Mock transports
# ---------------------------------------------------------------------------


class _HeadersTransport(httpx.AsyncBaseTransport):
    """Returns a fixed set of response headers for every request."""

    def __init__(self, headers: dict[str, str] | None = None) -> None:
        self._headers = headers or {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=self._headers,
            content=b"<html><body>Page content</body></html>",
            request=request,
        )


class _FileTransport(httpx.AsyncBaseTransport):
    """Returns pre-set bodies for specific URL paths; 404 for everything else."""

    def __init__(self, exposed: dict[str, bytes]) -> None:
        self._exposed = exposed   # path → body bytes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = self._exposed.get(path)
        if body is None:
            return httpx.Response(404, content=b"Not Found", request=request)
        return httpx.Response(200, content=body, request=request)


class _NetworkErrorTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")


def _make_client(transport: httpx.AsyncBaseTransport) -> RateLimitedClient:
    return RateLimitedClient(rate_limit=100, timeout=5.0, _transport=transport)


_BASE_URL = "http://example.com"
_PAGES = {f"{_BASE_URL}/page{i}" for i in range(5)}


# ---------------------------------------------------------------------------
# Header checks — each missing header is detected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing_header", _SECURITY_HEADERS)
@pytest.mark.asyncio
async def test_each_missing_header_is_reported(missing_header: str):
    """Removing any one security header from the response produces a finding."""
    present = {k: v for k, v in _ALL_SECURITY_HEADERS.items() if k != missing_header}
    async with _make_client(_HeadersTransport(present)) as client:
        findings = await MisconfigModule().run(_PAGES, [], [], client)
    header_findings = [f for f in findings if f.vuln_type == "misconfig_header"]
    reported_headers = {f.affected_parameter for f in header_findings}
    assert missing_header in reported_headers


@pytest.mark.asyncio
async def test_all_headers_present_no_header_finding():
    """No finding when all six security headers are present."""
    async with _make_client(_HeadersTransport(_ALL_SECURITY_HEADERS)) as client:
        findings = await MisconfigModule().run(_PAGES, [], [], client)
    assert not any(f.vuln_type == "misconfig_header" for f in findings)


@pytest.mark.asyncio
async def test_no_headers_produces_six_findings():
    """A response with no security headers produces exactly six misconfig_header findings."""
    async with _make_client(_HeadersTransport({})) as client:
        findings = await MisconfigModule().run(_PAGES, [], [], client)
    header_findings = [f for f in findings if f.vuln_type == "misconfig_header"]
    assert len(header_findings) == len(_SECURITY_HEADERS)


@pytest.mark.asyncio
async def test_header_findings_deduplicated_across_urls():
    """The same missing header reported by multiple URLs must appear only once."""
    # 5 URLs, all missing every security header
    async with _make_client(_HeadersTransport({})) as client:
        findings = await MisconfigModule().run(_PAGES, [], [], client)
    header_findings = [f for f in findings if f.vuln_type == "misconfig_header"]
    reported = [f.affected_parameter for f in header_findings]
    assert len(reported) == len(set(reported)), "Duplicate header findings detected"


@pytest.mark.asyncio
async def test_header_check_samples_at_most_max_urls():
    """Module fetches at most _MAX_HEADER_SAMPLE pages for header auditing."""
    page_paths_fetched: list[str] = []

    class _CountingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            path = request.url.path
            # Page URLs match /pageN; file probes start with /. or are SQL/PHP paths
            if re.match(r"^/page\d+$", path):
                page_paths_fetched.append(path)
            return httpx.Response(
                200,
                headers=_ALL_SECURITY_HEADERS,   # no header findings
                content=b"<html>ok</html>",
                request=request,
            )

    # 20 page URLs — well above the limit
    target_urls = {f"{_BASE_URL}/page{i}" for i in range(20)}
    async with _make_client(_CountingTransport()) as client:
        await MisconfigModule().run(target_urls, [], [], client)

    assert len(page_paths_fetched) <= _MAX_HEADER_SAMPLE


@pytest.mark.asyncio
async def test_header_check_stops_early_when_all_found():
    """If all six headers are found missing on the first URL, no further pages are fetched."""
    page_fetches = 0

    class _EarlyStopTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal page_fetches
            if re.match(r"^/page\d+$", request.url.path):
                page_fetches += 1
            return httpx.Response(200, content=b"<html>ok</html>", request=request)

    target_urls = {f"{_BASE_URL}/page{i}" for i in range(10)}
    async with _make_client(_EarlyStopTransport()) as client:
        await MisconfigModule().run(target_urls, [], [], client)

    # Once all 6 headers are reported from page0, the loop should break early
    assert page_fetches == 1


@pytest.mark.asyncio
async def test_header_finding_has_correct_fields():
    headers = {k: v for k, v in _ALL_SECURITY_HEADERS.items() if k != "Content-Security-Policy"}
    async with _make_client(_HeadersTransport(headers)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    f = next(x for x in findings if x.affected_parameter == "Content-Security-Policy")
    assert f.vuln_type == "misconfig_header"
    assert f.confidence == "confirmed"
    assert "example.com" in f.affected_url
    assert "Content-Security-Policy" in f.evidence_response


@pytest.mark.asyncio
async def test_network_error_skips_url_for_header_check():
    """ConnectError on a URL → skip it, no crash."""
    async with _make_client(_NetworkErrorTransport()) as client:
        findings = await MisconfigModule().run(_PAGES, [], [], client)
    assert not any(f.vuln_type == "misconfig_header" for f in findings)


@pytest.mark.asyncio
async def test_empty_target_urls_no_header_findings():
    async with _make_client(_HeadersTransport({})) as client:
        findings = await MisconfigModule().run(set(), [], [], client)
    assert not any(f.vuln_type == "misconfig_header" for f in findings)


# ---------------------------------------------------------------------------
# Exposed file checks — env files
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_env_file_with_key_value_found():
    exposed = {"/.env": b"DB_HOST=localhost\nDB_PASS=secret123\nAPP_KEY=abc"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    file_findings = [f for f in findings if f.vuln_type == "misconfig_file"]
    assert any("/.env" in f.affected_parameter for f in file_findings)


@pytest.mark.asyncio
async def test_env_file_without_key_value_not_found():
    """An .env file returning plain HTML (e.g. soft-404) is not reported."""
    exposed = {"/.env": b"<html><body>Not Found</body></html>"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    file_findings = [f for f in findings if f.vuln_type == "misconfig_file"]
    assert not any("/.env" == f.affected_parameter for f in file_findings)


@pytest.mark.asyncio
async def test_env_local_file_found():
    exposed = {"/.env.local": b"API_SECRET=supersecret\nDEBUG=true"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert any("/.env.local" in f.affected_parameter for f in findings)


# ---------------------------------------------------------------------------
# Exposed file checks — git files
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_git_head_with_ref_found():
    exposed = {"/.git/HEAD": b"ref: refs/heads/main\n"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert any("/.git/HEAD" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_git_head_wrong_format_not_found():
    """A /.git/HEAD file that doesn't start with 'ref: refs/heads/' is skipped."""
    exposed = {"/.git/HEAD": b"<html>404 Not Found</html>"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert not any("/.git/HEAD" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_git_config_with_core_section_found():
    config = b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com"
    exposed = {"/.git/config": config}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert any("/.git/config" in f.affected_parameter for f in findings)


# ---------------------------------------------------------------------------
# Exposed file checks — SQL / PHP files
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backup_sql_found():
    exposed = {"/backup.sql": b"-- MySQL dump 10.13\nCREATE TABLE users (id INT, name VARCHAR(100));"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert any("/backup.sql" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_wp_config_found():
    exposed = {"/wp-config.php": b"<?php define('DB_NAME', 'wordpress'); define('DB_PASSWORD', 'secret');"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert any("/wp-config.php" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_phpinfo_found():
    exposed = {"/phpinfo.php": b"<?php phpinfo(); ?>"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert any("/phpinfo.php" in f.affected_parameter for f in findings)


# ---------------------------------------------------------------------------
# Exposed file checks — robots.txt
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_robots_txt_with_sensitive_disallow_found():
    robots = b"User-agent: *\nDisallow: /admin\nDisallow: /api/internal\n"
    exposed = {"/robots.txt": robots}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert any("/robots.txt" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_robots_txt_without_sensitive_disallow_not_found():
    """robots.txt with only non-sensitive Disallow entries is not reported."""
    robots = b"User-agent: *\nDisallow: /sitemap.xml\nAllow: /\n"
    exposed = {"/robots.txt": robots}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert not any("/robots.txt" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_robots_txt_with_wp_admin_disallow_found():
    robots = b"User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-login.php\n"
    exposed = {"/robots.txt": robots}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert any("/robots.txt" in f.affected_parameter for f in findings)


# ---------------------------------------------------------------------------
# Exposed file checks — negative cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_404_file_not_reported():
    """Files returning 404 must not produce findings."""
    async with _make_client(_FileTransport({})) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert not any(f.vuln_type == "misconfig_file" for f in findings)


@pytest.mark.asyncio
async def test_empty_body_not_reported():
    """A 200 response with an empty body is skipped."""
    exposed = {"/.env": b"", "/backup.sql": b"   \n   "}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert not any(f.vuln_type == "misconfig_file" for f in findings)


@pytest.mark.asyncio
async def test_multiple_files_produce_multiple_findings():
    """When several sensitive files are exposed, each gets its own finding."""
    exposed = {
        "/.env":        b"DB_HOST=localhost\nDB_PASS=secret",
        "/.git/HEAD":   b"ref: refs/heads/main\n",
        "/backup.sql":  b"-- SQL dump\nCREATE TABLE users",
    }
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    file_findings = [f for f in findings if f.vuln_type == "misconfig_file"]
    params = {f.affected_parameter for f in file_findings}
    assert "/.env" in params
    assert "/.git/HEAD" in params
    assert "/backup.sql" in params


@pytest.mark.asyncio
async def test_file_finding_fields():
    exposed = {"/.env": b"SECRET_KEY=abc123\nDATABASE_URL=postgres://user:pass@host/db"}
    async with _make_client(_FileTransport(exposed)) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    f = next(x for x in findings if "/.env" in x.affected_parameter)
    assert f.vuln_type == "misconfig_file"
    assert f.confidence == "confirmed"
    assert "/.env" in f.affected_url
    assert "example.com" in f.affected_url


@pytest.mark.asyncio
async def test_network_error_file_probe_skipped():
    async with _make_client(_NetworkErrorTransport()) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)
    assert not any(f.vuln_type == "misconfig_file" for f in findings)


@pytest.mark.asyncio
async def test_empty_target_urls_no_file_findings():
    async with _make_client(_FileTransport({"/.env": b"KEY=val"})) as client:
        findings = await MisconfigModule().run(set(), [], [], client)
    assert not any(f.vuln_type == "misconfig_file" for f in findings)


# ---------------------------------------------------------------------------
# Combined: both header and file findings in one run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_header_and_file_findings_returned_together():
    """run() correctly returns findings from both sub-checks."""

    class _CombinedTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/.env":
                return httpx.Response(200, content=b"DB_PASS=secret\n", request=request)
            # Return response with NO security headers for page requests
            return httpx.Response(200, content=b"<html>page</html>", request=request)

    async with _make_client(_CombinedTransport()) as client:
        findings = await MisconfigModule().run({f"{_BASE_URL}/"}, [], [], client)

    vuln_types = {f.vuln_type for f in findings}
    assert "misconfig_header" in vuln_types
    assert "misconfig_file" in vuln_types


# ---------------------------------------------------------------------------
# _missing_headers unit tests
# ---------------------------------------------------------------------------


def _fake_resp(headers: dict[str, str]) -> httpx.Response:
    req = httpx.Request("GET", "http://example.com/")
    return httpx.Response(200, headers=headers, content=b"body", request=req)


def test_missing_headers_detects_absent_header():
    resp = _fake_resp({})
    missing = _missing_headers(resp)
    assert "Strict-Transport-Security" in missing
    assert "Content-Security-Policy" in missing
    assert len(missing) == len(_SECURITY_HEADERS)


def test_missing_headers_all_present():
    resp = _fake_resp(_ALL_SECURITY_HEADERS)
    assert _missing_headers(resp) == []


def test_missing_headers_case_insensitive():
    # httpx normalises header names to lowercase in the response
    resp = _fake_resp({"strict-transport-security": "max-age=31536000"})
    missing = _missing_headers(resp)
    assert "Strict-Transport-Security" not in missing


def test_missing_headers_partial():
    present = {"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY"}
    resp = _fake_resp(present)
    missing = _missing_headers(resp)
    assert "Content-Security-Policy" not in missing
    assert "X-Frame-Options" not in missing
    assert "Strict-Transport-Security" in missing


# ---------------------------------------------------------------------------
# _validate_file_content unit tests
# ---------------------------------------------------------------------------


def test_validate_env_valid():
    assert _validate_file_content("/.env", "DB_HOST=localhost\nDB_PASS=secret", "env")


def test_validate_env_lowercase_key_invalid():
    assert not _validate_file_content("/.env", "host=localhost\npassword=secret", "env")


def test_validate_env_empty_invalid():
    assert not _validate_file_content("/.env", "", "env")


def test_validate_env_html_soft_404_invalid():
    assert not _validate_file_content("/.env", "<html><body>Not Found</body></html>", "env")


def test_validate_git_head_valid():
    assert _validate_file_content("/.git/HEAD", "ref: refs/heads/main\n", "git_head")


def test_validate_git_head_detached_invalid():
    assert not _validate_file_content("/.git/HEAD", "abc123deadbeef456\n", "git_head")


def test_validate_git_head_empty_invalid():
    assert not _validate_file_content("/.git/HEAD", "", "git_head")


def test_validate_git_config_with_core_valid():
    assert _validate_file_content("/.git/config", "[core]\n\trepositoryformatversion = 0", "git_config")


def test_validate_git_config_with_remote_valid():
    assert _validate_file_content("/.git/config", "[remote \"origin\"]\n\turl = git@github.com", "git_config")


def test_validate_git_config_without_markers_invalid():
    assert not _validate_file_content("/.git/config", "some random text", "git_config")


def test_validate_robots_sensitive_admin():
    robots = "User-agent: *\nDisallow: /admin\n"
    assert _validate_file_content("/robots.txt", robots, "robots")


def test_validate_robots_sensitive_api():
    robots = "User-agent: *\nDisallow: /api/private\n"
    assert _validate_file_content("/robots.txt", robots, "robots")


def test_validate_robots_non_sensitive():
    robots = "User-agent: *\nDisallow: /sitemap.xml\nAllow: /\n"
    assert not _validate_file_content("/robots.txt", robots, "robots")


def test_validate_any_non_empty():
    assert _validate_file_content("/backup.sql", "-- SQL content", "any")


def test_validate_any_whitespace_only_invalid():
    assert not _validate_file_content("/backup.sql", "   \n\t  ", "any")


# ---------------------------------------------------------------------------
# _site_root unit tests
# ---------------------------------------------------------------------------


def test_site_root_http():
    assert _site_root({"http://example.com/page"}) == "http://example.com"


def test_site_root_https_with_path():
    assert _site_root({"https://example.com/users/42"}) == "https://example.com"


def test_site_root_empty_set():
    assert _site_root(set()) is None


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------


def test_module_name():
    assert MisconfigModule().name == "Security Misconfiguration"


def test_module_vuln_types():
    types = MisconfigModule().vuln_types
    assert "misconfig_header" in types
    assert "misconfig_file" in types
