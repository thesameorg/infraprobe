"""Shared HTTP client utilities for scanners.

All scanners that need to fetch web content should use these helpers
instead of duplicating HTTPS-first / HTTP-fallback logic.
"""

from __future__ import annotations

import httpx

from infraprobe.target import parse_target


def scanner_client(timeout: float, *, follow_redirects: bool = True) -> httpx.AsyncClient:
    """Create a standard async HTTP client for scanners.

    - HTTPS-first with a short connect timeout (3 s or less)
    - TLS verification disabled (we inspect certs separately)
    - Follows redirects by default
    """
    connect_timeout = min(3.0, timeout)
    timeouts = httpx.Timeout(timeout, connect=connect_timeout)
    return httpx.AsyncClient(verify=False, timeout=timeouts, follow_redirects=follow_redirects)


async def fetch_with_fallback(target: str, client: httpx.AsyncClient) -> tuple[str, httpx.Response]:
    """Fetch *target*, trying HTTPS first and falling back to HTTP.

    Returns ``(base_url, response)`` where *base_url* is the scheme + host
    that succeeded (no trailing slash).
    """
    host = parse_target(target).host

    # Already has a scheme — use as-is.
    if "://" in target:
        resp = await client.get(target)
        return target.rstrip("/"), resp

    # Try HTTPS first.
    try:
        resp = await client.get(f"https://{target}")
        return f"https://{target}", resp
    except httpx.HTTPError:
        pass

    # Fall back to HTTP.
    resp = await client.get(f"http://{host}")
    return f"http://{host}", resp
