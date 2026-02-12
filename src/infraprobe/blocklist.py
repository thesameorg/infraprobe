import ipaddress
import socket
from urllib.parse import urlparse

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class BlockedTargetError(Exception):
    pass


class InvalidTargetError(Exception):
    pass


def parse_target(raw: str) -> tuple[str, int | None]:
    """Extract host and optional port from target string."""
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname or raw, parsed.port
    if raw.startswith("["):
        # IPv6 with port: [::1]:8080
        bracket_end = raw.find("]")
        if bracket_end == -1:
            raise InvalidTargetError(f"Malformed IPv6 target: {raw}")
        host = raw[1:bracket_end]
        rest = raw[bracket_end + 1 :]
        port = int(rest[1:]) if rest.startswith(":") else None
        return host, port
    if raw.count(":") == 1:
        host, port_str = raw.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return raw, None
    return raw, None


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _BLOCKED_NETWORKS)


def validate_target(raw: str) -> str:
    """Validate and normalize a scan target. Raises on blocked/invalid targets."""
    host, port = parse_target(raw)
    if not host:
        raise InvalidTargetError("Empty target")

    # Check if host is already an IP
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        if _is_blocked_ip(host):
            raise BlockedTargetError(f"Target {host} is in a blocked range")
    else:
        # It's a domain — resolve and check all IPs
        try:
            infos = socket.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise InvalidTargetError(f"Cannot resolve {host}: {exc}") from exc
        for info in infos:
            ip = str(info[4][0])
            if _is_blocked_ip(ip):
                raise BlockedTargetError(f"Target {host} resolves to blocked IP {ip}")

    return f"{host}:{port}" if port else host
