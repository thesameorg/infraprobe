import ipaddress
import socket
from urllib.parse import urlparse

_BLOCKED_NETWORKS = [
    # IPv4 private / reserved
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 private / reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64
    ipaddress.ip_network("100::/64"),  # discard
    ipaddress.ip_network("fc00::/7"),  # unique local
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("fd00:ec2::/32"),  # AWS EC2 IPv6 metadata
]


class BlockedTargetError(Exception):
    pass


class InvalidTargetError(Exception):
    pass


def parse_target(raw: str) -> tuple[str, int | None]:
    """Extract host and optional port from target string.

    Delegates to urllib.parse.urlparse for all parsing — handles schemes,
    IPv6 brackets, ports, and encoded characters correctly.
    """
    raw = raw.strip()
    if "://" not in raw:
        # Bare IPv6 addresses (contain ":" but no brackets) need wrapping
        # so urlparse can parse them correctly.
        if ":" in raw and not raw.startswith("["):
            try:
                ipaddress.ip_address(raw)
                raw = f"https://[{raw}]"
            except ValueError:
                # Might be host:port — let urlparse handle it.
                raw = f"https://{raw}"
        else:
            raw = f"https://{raw}"
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        raise InvalidTargetError(f"Cannot extract host from target: {raw}")
    return host, parsed.port


def _is_blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an already-parsed IP address falls in any blocked network."""
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _parse_ip_strict(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse a host string into an IP address.

    Uses ipaddress.ip_address which normalises decimal, octal, and hex
    representations (e.g. 0x7f000001, 2130706433, 0177.0.0.1) into their
    canonical form before matching against blocked networks.
    """
    return ipaddress.ip_address(host)


def validate_target(raw: str) -> str:
    """Validate and normalize a scan target. Raises on blocked/invalid targets."""
    host, port = parse_target(raw)

    # Check if host is an IP (handles decimal, hex, octal via ipaddress)
    try:
        addr = _parse_ip_strict(host)
        if _is_blocked_ip(addr):
            raise BlockedTargetError(f"Target {host} is in a blocked range")
    except ValueError:
        # Not an IP — it's a domain.  Resolve and check all resulting IPs.
        try:
            infos = socket.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise InvalidTargetError(f"Cannot resolve {host}: {exc}") from exc
        for info in infos:
            ip_str = str(info[4][0])
            try:
                addr = _parse_ip_strict(ip_str)
            except ValueError:
                continue
            if _is_blocked_ip(addr):
                raise BlockedTargetError(f"Target {host} resolves to blocked IP {ip_str}") from None

    return f"{host}:{port}" if port else host
