"""Tests for the sensitive data exposure detection module."""
from __future__ import annotations

import re

import httpx
import pytest

from app.scanner.modules.exposure import (
    ExposureModule,
    _PATTERNS,
    _display_match,
    _redact,
)
from app.utils.http_client import RateLimitedClient

# ---------------------------------------------------------------------------
# Sample values — chosen to satisfy each regex exactly
# ---------------------------------------------------------------------------

AWS_KEY      = "AKIAIOSFODNN7EXAMPLE"          # AKIA + 16 uppercase/digit chars
STRIPE_KEY   = "sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXX"  # sk_live_ + 24 alphanum
GENERIC_KEY  = "key-" + "a" * 32               # key- + 32 alphanum
PRIVATE_KEY  = "-----BEGIN RSA PRIVATE KEY-----"
CONN_STR     = "postgresql://user:s3cr3t@db.internal:5432/prod"
JWT_TOKEN    = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36P"
INTERNAL_A   = "10.0.0.1"
INTERNAL_B   = "172.20.0.1"
INTERNAL_C   = "192.168.1.1"
PREFILL_HTML = b'<form><input type="password" name="p" value="secret123"><button>Go</button></form>'


# ---------------------------------------------------------------------------
# Mock transport
# ---------------------------------------------------------------------------

class _StaticTransport(httpx.AsyncBaseTransport):
    """Returns a fixed body for every request."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self._body, request=request)


class _UrlDispatchTransport(httpx.AsyncBaseTransport):
    """Returns different bodies for different URL paths."""

    def __init__(self, path_to_body: dict[str, bytes]) -> None:
        self._map = path_to_body

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = self._map.get(path, b"<html>clean</html>")
        return httpx.Response(200, content=body, request=request)


class _NetworkErrorTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")


def _make_client(transport: httpx.AsyncBaseTransport) -> RateLimitedClient:
    return RateLimitedClient(rate_limit=100, timeout=5.0, _transport=transport)


def _one_url(path: str = "/page") -> set[str]:
    return {f"http://example.com{path}"}


# ---------------------------------------------------------------------------
# Detection: one pattern per test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aws_key_detected():
    body = f"<html>Config: aws_key={AWS_KEY} something</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert len(findings) == 1
    assert findings[0].vuln_type == "data_exposure"
    assert "AWS" in findings[0].affected_parameter
    assert findings[0].confidence == "confirmed"


@pytest.mark.asyncio
async def test_stripe_key_detected():
    body = f"<html>STRIPE_SECRET={STRIPE_KEY}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert any("Stripe" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_generic_api_key_detected():
    body = f"<html>api_key={GENERIC_KEY}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert any("API Key" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_private_key_detected():
    body = f"<pre>{PRIVATE_KEY}\nMIIEpAIBAAKCAQEA...</pre>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert any("Private Key" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_prefilled_password_detected():
    async with _make_client(_StaticTransport(PREFILL_HTML)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert any("Password" in f.affected_parameter for f in findings)
    pw_finding = next(f for f in findings if "Password" in f.affected_parameter)
    assert pw_finding.confidence == "confirmed"


@pytest.mark.asyncio
async def test_connection_string_detected():
    body = f"<html>DB_URL={CONN_STR}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert any("Connection String" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_jwt_token_detected():
    body = f"<html>token={JWT_TOKEN}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert any("JWT" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_internal_ip_class_a_detected():
    body = f"<html>backend={INTERNAL_A}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    ip_findings = [f for f in findings if "10.x" in f.affected_parameter]
    assert len(ip_findings) == 1
    assert ip_findings[0].confidence == "tentative"


@pytest.mark.asyncio
async def test_internal_ip_class_b_detected():
    body = f"<html>server={INTERNAL_B}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert any("172" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_internal_ip_class_c_detected():
    body = f"<html>host={INTERNAL_C}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert any("192.168" in f.affected_parameter for f in findings)


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clean_page_no_findings():
    body = b"<html><body><p>Welcome to the site. Nothing sensitive here.</p></body></html>"
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_partial_aws_key_not_detected():
    """AKIA + only 15 chars (one short) must not match."""
    body = b"<html>AKIAIOSFODNN7EXAMPL is not a valid key</html>"
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert not any("AWS" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_password_input_without_value_not_detected():
    """<input type="password"> without a value attribute is not reported."""
    body = b'<form><input type="password" name="p" placeholder="Enter password"></form>'
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert not any("Password" in f.affected_parameter for f in findings)


@pytest.mark.asyncio
async def test_public_ip_not_detected():
    """Public IP addresses must NOT trigger an internal IP finding."""
    body = b"<html>server at 8.8.8.8 and 93.184.216.34</html>"
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    ip_findings = [f for f in findings if "IP" in f.affected_parameter]
    assert ip_findings == []


@pytest.mark.asyncio
async def test_connection_string_too_short_not_detected():
    """postgresql:// with fewer than 3 chars after must not match."""
    body = b"<html>See mongodb:// and redis://ab for docs</html>"
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    # 'redis://ab' has only 2 chars after :// → no match
    # 'mongodb://' has 0 chars → no match
    conn = [f for f in findings if "Connection" in f.affected_parameter]
    assert conn == []


# ---------------------------------------------------------------------------
# Multiple patterns / multiple URLs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multiple_patterns_same_page():
    """Two patterns present on one page → two findings."""
    body = f"<html>aws={AWS_KEY} token={JWT_TOKEN}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    params = {f.affected_parameter for f in findings}
    assert any("AWS" in p for p in params)
    assert any("JWT" in p for p in params)


@pytest.mark.asyncio
async def test_multiple_urls_each_checked():
    transport = _UrlDispatchTransport({
        "/page1": f"<html>key={AWS_KEY}</html>".encode(),
        "/page2": f"<html>token={JWT_TOKEN}</html>".encode(),
    })
    urls = {"http://example.com/page1", "http://example.com/page2"}
    async with _make_client(transport) as client:
        findings = await ExposureModule().run(urls, [], [], client)
    affected = {f.affected_url for f in findings}
    assert "http://example.com/page1" in affected
    assert "http://example.com/page2" in affected


@pytest.mark.asyncio
async def test_same_pattern_reported_once_per_url():
    """Two AWS keys on one page → only one finding for that URL."""
    body = f"<html>{AWS_KEY} and AKIAJSIE27AJFAOISSIH</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    aws = [f for f in findings if "AWS" in f.affected_parameter]
    assert len(aws) == 1


@pytest.mark.asyncio
async def test_same_url_different_patterns_reported_separately():
    """Different pattern types on one URL each produce their own finding."""
    body = (
        f"<html>key={AWS_KEY} db={CONN_STR}</html>"
    ).encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    types = {f.affected_parameter for f in findings}
    assert any("AWS" in t for t in types)
    assert any("Connection" in t for t in types)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aws_key_redacted_in_evidence():
    body = f"config aws={AWS_KEY} end".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    f = next(x for x in findings if "AWS" in x.affected_parameter)
    assert AWS_KEY not in f.evidence_response
    assert "AKIA****" in f.evidence_response


@pytest.mark.asyncio
async def test_stripe_key_redacted_in_evidence():
    body = f"payment secret={STRIPE_KEY}".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    f = next(x for x in findings if "Stripe" in x.affected_parameter)
    assert STRIPE_KEY not in f.evidence_response
    assert "sk_l****" in f.evidence_response


@pytest.mark.asyncio
async def test_connection_string_redacted_in_evidence():
    body = f"url={CONN_STR} end".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    f = next(x for x in findings if "Connection" in x.affected_parameter)
    assert "s3cr3t" not in f.evidence_response   # password part is gone
    assert "post****" in f.evidence_response


@pytest.mark.asyncio
async def test_prefilled_password_value_redacted_in_evidence():
    async with _make_client(_StaticTransport(PREFILL_HTML)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    f = next(x for x in findings if "Password" in x.affected_parameter)
    assert "secret123" not in f.evidence_response
    assert "secr****" in f.evidence_response
    # The tag structure should still be visible in the evidence
    assert "input" in f.evidence_response


@pytest.mark.asyncio
async def test_internal_ip_not_redacted_in_evidence():
    """IP addresses are the evidence themselves — they must NOT be redacted."""
    body = f"<html>backend at {INTERNAL_A}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    ip_f = next(f for f in findings if "10.x" in f.affected_parameter)
    assert INTERNAL_A in ip_f.evidence_response


@pytest.mark.asyncio
async def test_private_key_not_redacted_in_evidence():
    """PEM headers are not sensitive alone — they must appear unredacted."""
    body = f"<pre>{PRIVATE_KEY}</pre>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    pk_f = next(f for f in findings if "Private Key" in f.affected_parameter)
    assert "-----BEGIN RSA PRIVATE KEY-----" in pk_f.evidence_response


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_error_skipped_gracefully():
    async with _make_client(_NetworkErrorTransport()) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_empty_target_urls_returns_empty():
    async with _make_client(_StaticTransport(b"")) as client:
        findings = await ExposureModule().run(set(), [], [], client)
    assert findings == []


@pytest.mark.asyncio
async def test_all_findings_have_data_exposure_vuln_type():
    body = f"<html>{AWS_KEY} {JWT_TOKEN} {INTERNAL_A}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run(_one_url(), [], [], client)
    assert findings
    assert all(f.vuln_type == "data_exposure" for f in findings)


@pytest.mark.asyncio
async def test_finding_affected_url_matches_source_url():
    url = "http://example.com/secret-page"
    body = f"<html>{AWS_KEY}</html>".encode()
    async with _make_client(_StaticTransport(body)) as client:
        findings = await ExposureModule().run({url}, [], [], client)
    assert findings[0].affected_url == url


# ---------------------------------------------------------------------------
# _redact unit tests
# ---------------------------------------------------------------------------

def test_redact_long_string():
    assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA****"

def test_redact_short_string_returns_stars():
    assert _redact("abc") == "****"

def test_redact_exactly_four_chars():
    assert _redact("AKIA") == "****"  # len==4, so first 4 + **** → "AKIA****"... wait

def test_redact_five_chars():
    assert _redact("AKIAX") == "AKIA****"

def test_redact_empty_string():
    assert _redact("") == "****"


# ---------------------------------------------------------------------------
# _display_match unit tests
# ---------------------------------------------------------------------------

def _fake_match(pattern_str: str, text: str) -> re.Match:
    return re.search(pattern_str, text)


def test_display_match_no_redact():
    m = _fake_match(r"10\.\d+\.\d+\.\d+", "server at 10.0.0.1 end")
    assert _display_match(m, redact=False) == "10.0.0.1"


def test_display_match_redact_no_group():
    m = _fake_match(r"AKIA[0-9A-Z]{16}", f"key={AWS_KEY}")
    result = _display_match(m, redact=True)
    assert result == "AKIA****"
    assert AWS_KEY not in result


def test_display_match_redact_with_group():
    """For patterns with a capturing group (e.g. prefilled password),
    only the captured group is redacted, not the whole tag."""
    pattern = r'<input[^>]*value=["\']([^"\']+)["\']'
    text = '<input type="password" value="mysecret">'
    m = re.search(pattern, text, re.IGNORECASE)
    result = _display_match(m, redact=True)
    assert "mysecret" not in result
    assert "myse****" in result
    assert "input" in result     # tag structure preserved


# ---------------------------------------------------------------------------
# Pattern regex unit tests
# ---------------------------------------------------------------------------

def _pat(name: str) -> _Pattern:
    return next(p for p in _PATTERNS if p.name == name)


def test_aws_key_regex_matches_valid():
    assert _pat("aws_access_key").regex.search(AWS_KEY)

def test_aws_key_regex_rejects_short():
    assert not _pat("aws_access_key").regex.search("AKIAIOSFODNN7EXAMPL")  # 15 chars

def test_stripe_key_regex_matches_valid():
    assert _pat("stripe_secret_key").regex.search(STRIPE_KEY)

def test_stripe_key_rejects_test_key():
    assert not _pat("stripe_secret_key").regex.search("sk_test_abc123")

def test_generic_key_regex_matches_valid():
    assert _pat("generic_api_key").regex.search(GENERIC_KEY)

def test_jwt_regex_matches_valid():
    assert _pat("jwt_token").regex.search(JWT_TOKEN)

def test_jwt_regex_rejects_partial():
    assert not _pat("jwt_token").regex.search("eyJhbGciOiJIUzI1NiJ9")  # only header, no payload

def test_private_key_regex_rsa():
    assert _pat("private_key_pem").regex.search("-----BEGIN RSA PRIVATE KEY-----")

def test_private_key_regex_ec():
    assert _pat("private_key_pem").regex.search("-----BEGIN EC PRIVATE KEY-----")

def test_private_key_regex_openssh():
    assert _pat("private_key_pem").regex.search("-----BEGIN OPENSSH PRIVATE KEY-----")

def test_internal_ip_class_a_matches():
    assert _pat("internal_ip_class_a").regex.search("host=10.0.0.1 end")

def test_internal_ip_class_a_rejects_public():
    assert not _pat("internal_ip_class_a").regex.search("ip=11.0.0.1")

def test_internal_ip_class_b_matches():
    assert _pat("internal_ip_class_b").regex.search("172.16.0.1")
    assert _pat("internal_ip_class_b").regex.search("172.31.255.254")

def test_internal_ip_class_b_rejects_172_15():
    assert not _pat("internal_ip_class_b").regex.search("172.15.0.1")

def test_internal_ip_class_b_rejects_172_32():
    assert not _pat("internal_ip_class_b").regex.search("172.32.0.1")

def test_internal_ip_class_c_matches():
    assert _pat("internal_ip_class_c").regex.search("192.168.1.1")

def test_internal_ip_class_c_rejects_192_169():
    assert not _pat("internal_ip_class_c").regex.search("192.169.1.1")

def test_connection_string_postgresql():
    assert _pat("connection_string").regex.search(CONN_STR)

def test_connection_string_mongodb():
    assert _pat("connection_string").regex.search("mongodb://admin:pass@mongo.internal/db")

def test_connection_string_redis():
    assert _pat("connection_string").regex.search("redis://:password@cache.internal:6379")


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

def test_module_name():
    assert ExposureModule().name == "Sensitive Data Exposure"

def test_module_vuln_types():
    assert ExposureModule().vuln_types == ["data_exposure"]
