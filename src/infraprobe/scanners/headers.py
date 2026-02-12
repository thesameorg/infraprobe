import httpx

from infraprobe.models import CheckResult, CheckType, Finding, Severity

# Security headers we expect to be present, with severity if missing
_EXPECTED_HEADERS: list[tuple[str, str, Severity, str]] = [
    (
        "strict-transport-security",
        "HSTS not set",
        Severity.HIGH,
        "Without HSTS, users can be downgraded to HTTP via man-in-the-middle attacks.",
    ),
    (
        "content-security-policy",
        "CSP not set",
        Severity.MEDIUM,
        "Content-Security-Policy helps prevent XSS and data injection attacks.",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options not set",
        Severity.MEDIUM,
        "Without nosniff, browsers may MIME-sniff responses, enabling XSS via content type confusion.",
    ),
    (
        "x-frame-options",
        "X-Frame-Options not set",
        Severity.MEDIUM,
        "Without framing protection the site is vulnerable to clickjacking.",
    ),
    (
        "permissions-policy",
        "Permissions-Policy not set",
        Severity.LOW,
        "Permissions-Policy restricts browser features (camera, microphone, geolocation).",
    ),
    (
        "referrer-policy",
        "Referrer-Policy not set",
        Severity.LOW,
        "Without Referrer-Policy, the full URL may leak to third-party sites.",
    ),
]

# Headers that leak server information
_LEAKY_HEADERS: list[tuple[str, str]] = [
    ("server", "Server header exposes software version"),
    ("x-powered-by", "X-Powered-By header exposes technology stack"),
    ("x-aspnet-version", "X-AspNet-Version header exposes ASP.NET version"),
    ("x-aspnetmvc-version", "X-AspNetMvc-Version header exposes ASP.NET MVC version"),
]


async def _fetch(target: str, timeout: float) -> httpx.Response:
    """Try HTTPS first (short connect timeout), fall back to HTTP."""
    host = target.split(":")[0] if ":" in target and not target.startswith("[") else target

    if "://" in target:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            return await client.get(target)

    # Try HTTPS with a short connect timeout — don't wait 10s if port 443 isn't open
    try:
        connect_timeout = min(3.0, timeout)
        timeouts = httpx.Timeout(timeout, connect=connect_timeout)
        async with httpx.AsyncClient(verify=False, timeout=timeouts, follow_redirects=True) as client:
            return await client.get(f"https://{target}")
    except httpx.HTTPError:
        pass

    # Fall back to HTTP
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        return await client.get(f"http://{host}")


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    try:
        resp = await _fetch(target, timeout)
    except httpx.HTTPError as exc:
        return CheckResult(check=CheckType.HEADERS, error=f"Cannot connect to {target}: {exc}")

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[Finding] = []

    # Check for missing security headers
    for header_name, title, severity, description in _EXPECTED_HEADERS:
        if header_name not in headers_lower:
            findings.append(Finding(severity=severity, title=title, description=description))
        else:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"{header_name} is set",
                    description=f"Value: {headers_lower[header_name]}",
                    details={"value": headers_lower[header_name]},
                )
            )

    # Check for info-leaking headers
    for header_name, description in _LEAKY_HEADERS:
        if header_name in headers_lower:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title=f"{header_name} header leaks information",
                    description=f"{description}. Value: {headers_lower[header_name]}",
                    details={"header": header_name, "value": headers_lower[header_name]},
                )
            )

    # Check HTTPS
    if resp.url and str(resp.url).startswith("http://"):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Site served over HTTP (not HTTPS)",
                description="The target does not use HTTPS, all traffic is unencrypted.",
            )
        )

    raw = {
        "url": str(resp.url),
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
    }

    return CheckResult(check=CheckType.HEADERS, findings=findings, raw=raw)
