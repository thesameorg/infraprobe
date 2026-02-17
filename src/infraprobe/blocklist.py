import ipaddress

from infraprobe.target import ScanContext, Target, build_context, parse_target

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


class CapacityExceededError(Exception):
    """Raised when server capacity (e.g. nmap slots) is exhausted."""


# Re-export so existing ``from infraprobe.blocklist import ...`` works.
__all__ = [
    "BlockedTargetError",
    "CapacityExceededError",
    "InvalidTargetError",
    "ScanContext",
    "Target",
    "build_context",
    "parse_target",
    "validate_domain",
    "validate_ip",
    "validate_target",
]


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


def validate_target(raw: str) -> ScanContext:
    """Validate and normalize a scan target. Returns ScanContext with pre-resolved IPs.

    Raises BlockedTargetError for private/reserved IPs, InvalidTargetError for
    unresolvable domains or unparseable targets.
    """
    ctx = build_context(raw)

    for ip_str in ctx.resolved_ips:
        try:
            addr = _parse_ip_strict(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(addr):
            if ctx.is_ip:
                raise BlockedTargetError(f"Target {ctx.host} is in a blocked range")
            raise BlockedTargetError(f"Target {ctx.host} resolves to blocked IP {ip_str}")

    return ctx


def validate_domain(raw: str) -> ScanContext:
    """Validate that target is a domain (not an IP). Returns ScanContext."""
    ctx = validate_target(raw)
    if ctx.is_ip:
        raise InvalidTargetError(f"Expected a domain, got IP address: {ctx.host}")
    return ctx


def validate_ip(raw: str) -> ScanContext:
    """Validate that target is an IP address (not a domain). Returns ScanContext."""
    ctx = validate_target(raw)
    if not ctx.is_ip:
        raise InvalidTargetError(f"Expected an IP address, got domain: {ctx.host}")
    return ctx
