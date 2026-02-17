"""Shared HTTP client utilities for scanners.

All scanners that need to fetch web content should use these helpers
instead of duplicating HTTPS-first / HTTP-fallback logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from infraprobe.target import parse_target

if TYPE_CHECKING:
    from infraprobe.models import AuthConfig


def _strip_auth_on_cross_origin_redirect(response: httpx.Response) -> None:
    """Strip credentials when a redirect crosses to a different host."""
    if response.next_request is None:
        return
    original_host = response.request.url.host
    next_host = response.next_request.url.host
    if original_host == next_host:
        return
    response.next_request.headers.pop("authorization", None)
    response.next_request.headers.pop("cookie", None)


def scanner_client(
    timeout: float,
    *,
    follow_redirects: bool = True,
    auth: AuthConfig | None = None,
) -> httpx.AsyncClient:
    """Create a standard async HTTP client for scanners.

    - HTTPS-first with a short connect timeout (3 s or less)
    - TLS verification disabled (we inspect certs separately)
    - Follows redirects by default
    - Optionally applies auth credentials to requests
    """
    connect_timeout = min(3.0, timeout)
    timeouts = httpx.Timeout(timeout, connect=connect_timeout)

    kwargs: dict[str, Any] = {}
    event_hooks: dict[str, list] = {}

    if auth is not None:
        from infraprobe.models import BasicAuth, BearerAuth, CookieAuth, HeaderAuth

        match auth:
            case HeaderAuth():
                kwargs["headers"] = auth.headers
            case BasicAuth():
                kwargs["auth"] = httpx.BasicAuth(auth.username, auth.password)
            case BearerAuth():
                kwargs["headers"] = {"Authorization": f"Bearer {auth.token}"}
            case CookieAuth():
                kwargs["cookies"] = auth.cookies

        event_hooks["response"] = [_strip_auth_on_cross_origin_redirect]

    if event_hooks:
        kwargs["event_hooks"] = event_hooks

    return httpx.AsyncClient(
        verify=False, timeout=timeouts, follow_redirects=follow_redirects, **kwargs
    )


async def fetch_with_fallback(target: str, client: httpx.AsyncClient) -> tuple[str, httpx.Response]:
    """Fetch *target*, trying HTTPS first and falling back to HTTP.

    Returns ``(base_url, response)`` where *base_url* is the scheme + host
    that succeeded (no trailing slash).

    Re-validates the target against the blocklist before connecting to
    mitigate DNS rebinding attacks (shrinks the TOCTOU window between
    initial validation and the actual connection).
    """
    from infraprobe.blocklist import validate_target

    # Re-resolve and validate IPs right before connecting (DNS rebinding defense)
    validate_target(target)

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
