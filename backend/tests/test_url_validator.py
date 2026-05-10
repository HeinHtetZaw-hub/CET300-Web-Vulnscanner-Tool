import socket
from unittest.mock import patch

import pytest

from app.utils.url_validator import PrivateIPError, is_private_ip, validate_url

# ---------------------------------------------------------------------------
# Helpers — fake socket.getaddrinfo responses
# ---------------------------------------------------------------------------

def _addr(ip: str):
    """Build a minimal getaddrinfo return value for a single IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]


def _patch(ip: str):
    """Context manager: make every getaddrinfo call return *ip*."""
    return patch("app.utils.url_validator.socket.getaddrinfo", return_value=_addr(ip))


# ---------------------------------------------------------------------------
# validate_url — scheme checks
# ---------------------------------------------------------------------------

def test_valid_http_url_passes():
    with _patch("93.184.216.34"):
        result = validate_url("http://example.com/path?q=1")
    assert result == "http://example.com/path?q=1"


def test_valid_https_url_passes():
    with _patch("93.184.216.34"):
        result = validate_url("https://example.com")
    assert result == "https://example.com"


def test_ftp_scheme_raises():
    with pytest.raises(ValueError, match="scheme must be 'http' or 'https'"):
        validate_url("ftp://example.com")


def test_file_scheme_raises():
    with pytest.raises(ValueError, match="scheme must be 'http' or 'https'"):
        validate_url("file:///etc/passwd")


def test_no_scheme_raises():
    with pytest.raises(ValueError):
        validate_url("example.com")


def test_javascript_scheme_raises():
    with pytest.raises(ValueError):
        validate_url("javascript:alert(1)")


# ---------------------------------------------------------------------------
# validate_url — hostname checks
# ---------------------------------------------------------------------------

def test_missing_hostname_raises():
    with pytest.raises(ValueError, match="valid hostname"):
        validate_url("http://")


def test_dns_failure_raises():
    with patch(
        "app.utils.url_validator.socket.getaddrinfo",
        side_effect=socket.gaierror("Name or service not known"),
    ):
        with pytest.raises(ValueError, match="Cannot resolve hostname"):
            validate_url("http://this-domain-does-not-exist-xyz.invalid")


# ---------------------------------------------------------------------------
# validate_url — private IP blocking
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "127.0.0.1",       # loopback
    "127.0.0.2",       # loopback range
    "::1",             # IPv6 loopback
])
def test_loopback_addresses_blocked(ip):
    with _patch(ip):
        with pytest.raises(PrivateIPError, match="private, loopback, or reserved"):
            validate_url("http://target.internal")


@pytest.mark.parametrize("ip", [
    "10.0.0.1",        # RFC 1918 class A
    "10.255.255.255",  # RFC 1918 class A top
    "172.16.0.1",      # RFC 1918 class B bottom
    "172.31.255.255",  # RFC 1918 class B top
    "192.168.0.1",     # RFC 1918 class C
    "192.168.255.255", # RFC 1918 class C top
])
def test_rfc1918_addresses_blocked(ip):
    with _patch(ip):
        with pytest.raises(PrivateIPError):
            validate_url("http://internal.corp")


@pytest.mark.parametrize("ip", [
    "169.254.0.1",     # link-local
    "169.254.169.254", # AWS metadata endpoint
])
def test_link_local_addresses_blocked(ip):
    with _patch(ip):
        with pytest.raises(PrivateIPError):
            validate_url("http://metadata.internal")


@pytest.mark.parametrize("ip", [
    "100.64.0.1",      # CGNAT (RFC 6598)
    "100.127.255.255", # CGNAT top
])
def test_cgnat_addresses_blocked(ip):
    with _patch(ip):
        with pytest.raises(PrivateIPError):
            validate_url("http://carrier-nat.example")


def test_localhost_hostname_blocked():
    # No mock needed — localhost always resolves to 127.x locally
    with pytest.raises(PrivateIPError):
        validate_url("http://localhost")


# ---------------------------------------------------------------------------
# validate_url — public IPs pass
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "93.184.216.34",   # example.com
    "8.8.8.8",         # Google DNS
    "1.1.1.1",         # Cloudflare DNS
    "104.21.0.1",      # Cloudflare CDN range
])
def test_public_ips_pass(ip):
    with _patch(ip):
        result = validate_url("https://example.com")
    assert result == "https://example.com"


# ---------------------------------------------------------------------------
# validate_url — allow_private override
# ---------------------------------------------------------------------------

def test_allow_private_bypasses_block():
    with _patch("192.168.1.1"):
        result = validate_url("http://internal.lab", allow_private=True)
    assert result == "http://internal.lab"


def test_allow_private_bypasses_loopback():
    with _patch("127.0.0.1"):
        result = validate_url("http://localhost", allow_private=True)
    assert result == "http://localhost"


# ---------------------------------------------------------------------------
# is_private_ip — direct IP strings (no mock needed)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "::1",
])
def test_is_private_ip_true(host):
    assert is_private_ip(host) is True


@pytest.mark.parametrize("host", [
    "93.184.216.34",
    "8.8.8.8",
    "1.1.1.1",
])
def test_is_private_ip_false_for_public(host):
    with _patch(host):
        assert is_private_ip(host) is False


def test_is_private_ip_false_for_unresolvable():
    with patch(
        "app.utils.url_validator.socket.getaddrinfo",
        side_effect=socket.gaierror("nxdomain"),
    ):
        assert is_private_ip("nxdomain.invalid") is False


# ---------------------------------------------------------------------------
# PrivateIPError is a subclass of ValueError
# ---------------------------------------------------------------------------

def test_private_ip_error_is_value_error():
    with _patch("10.0.0.1"):
        with pytest.raises(ValueError):
            validate_url("http://internal")
