import ipaddress
import socket
from urllib.parse import urlparse


class PrivateIPError(ValueError):
    """Raised when a target URL resolves to a private, loopback, or link-local address."""


# Extra ranges not fully covered by ipaddress.is_private on all Python versions
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved (RFC 1112)
]


def validate_url(url: str, allow_private: bool = False) -> str:
    """Return the URL unchanged if valid, otherwise raise ValueError or PrivateIPError.

    Checks performed:
    - Scheme must be http or https
    - Hostname must be present
    - Hostname must resolve via DNS
    - Resolved IP must not be private/loopback/link-local (unless allow_private=True)
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"URL scheme must be 'http' or 'https', got {parsed.scheme!r}. "
            "Only web targets are supported."
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid hostname.")

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname {hostname!r}: {exc}") from exc

    if not addr_infos:
        raise ValueError(f"No addresses returned for hostname {hostname!r}.")

    if not allow_private:
        for info in addr_infos:
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if _is_blocked(ip):
                raise PrivateIPError(
                    f"Scanning {hostname!r} is not permitted: it resolves to {ip_str}, "
                    "which is a private, loopback, or reserved address. "
                    "VulnScanner only scans publicly routable targets. "
                    "This restriction exists to prevent accidental scanning of internal networks, "
                    "in compliance with responsible disclosure practices."
                )

    return url


def is_private_ip(host: str) -> bool:
    """Return True if *host* (hostname or IP string) resolves to a private/reserved address."""
    try:
        addr_infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False

    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked(ip):
            return True

    return False


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the address must be blocked from scanning."""
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_multicast
    ):
        return True
    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False
