"""Unified target parsing for domains and IP addresses.

Every scanner and validator should use ``parse_target`` instead of
hand-rolling host/port extraction logic.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import NamedTuple
from urllib.parse import urlparse


class Target(NamedTuple):
    host: str
    port: int | None

    @property
    def is_ip(self) -> bool:
        """Check if the host is an IP address."""
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Pre-resolved scan context passed through the scan pipeline."""

    host: str
    port: int | None
    is_ip: bool
    resolved_ips: tuple[str, ...]

    def __str__(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host


def parse_target(raw: str) -> Target:
    """Extract host and optional port from a target string.

    Accepts bare domains, IPs (v4/v6), host:port pairs, bracketed IPv6,
    and full URLs.  Delegates heavy lifting to ``urllib.parse.urlparse``.

    Examples::

        >>> parse_target("example.com")
        Target(host='example.com', port=None)
        >>> parse_target("example.com:8080")
        Target(host='example.com', port=8080)
        >>> parse_target("93.184.216.34:443")
        Target(host='93.184.216.34', port=443)
        >>> parse_target("[::1]:8080")
        Target(host='::1', port=8080)
        >>> parse_target("::1")
        Target(host='::1', port=None)
        >>> parse_target("https://example.com:8443/path?q=1")
        Target(host='example.com', port=8443)
    """
    from infraprobe.blocklist import InvalidTargetError

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
    return Target(host, parsed.port)


async def build_context(raw: str) -> ScanContext:
    """Parse a target string and resolve IPs, returning a ScanContext.

    Does NOT check the blocklist — use ``validate_target`` for that.
    Uses non-blocking DNS resolution via the event loop.
    """
    from infraprobe.blocklist import InvalidTargetError

    target = parse_target(raw)

    if target.is_ip:
        return ScanContext(host=target.host, port=target.port, is_ip=True, resolved_ips=(target.host,))

    # Domain — resolve IPs (non-blocking)
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(target.host, target.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise InvalidTargetError(f"Cannot resolve {target.host}: {exc}") from exc

    seen: set[str] = set()
    resolved: list[str] = []
    for info in infos:
        ip_str = str(info[4][0])
        if ip_str not in seen:
            seen.add(ip_str)
            resolved.append(ip_str)

    return ScanContext(host=target.host, port=target.port, is_ip=False, resolved_ips=tuple(resolved))
