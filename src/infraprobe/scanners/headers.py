"""HTTP security headers scanner with deep directive analysis.

Checks for missing headers, misconfigured values (CSP directives, HSTS max-age,
cookie attributes), and information-leaking headers. Inspired by drHEADer rules
and OWASP Secure Headers Project recommendations.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import httpx

from infraprobe.models import CheckResult, CheckType, Finding, Severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIN_HSTS_MAX_AGE = 31_536_000  # 1 year (OWASP recommendation)

_SAFE_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)

_VALID_XCTO = "nosniff"

_VALID_XFO = frozenset({"deny", "sameorigin"})

# CSP directives that weaken the policy
_CSP_DANGEROUS_VALUES = re.compile(
    r"""
    'unsafe-inline'  |
    'unsafe-eval'    |
    data:            |
    \*               # wildcard source
    """,
    re.VERBOSE | re.IGNORECASE,
)

# CSP directives to inspect
_CSP_DIRECTIVES_TO_CHECK = (
    "default-src",
    "script-src",
    "style-src",
    "object-src",
    "base-uri",
)

# Headers whose mere presence leaks server information
_LEAKY_HEADERS: list[tuple[str, str]] = [
    ("server", "Server header exposes software version"),
    ("x-powered-by", "X-Powered-By header exposes technology stack"),
    ("x-aspnet-version", "X-AspNet-Version header exposes ASP.NET version"),
    ("x-aspnetmvc-version", "X-AspNetMvc-Version header exposes ASP.NET MVC version"),
    ("x-generator", "X-Generator header exposes site generator"),
]


# ---------------------------------------------------------------------------
# Deep-analysis helpers
# ---------------------------------------------------------------------------


def _parse_csp(value: str) -> dict[str, str]:
    """Parse CSP header into {directive: sources} map."""
    directives: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        directive = tokens[0].lower()
        sources = tokens[1] if len(tokens) > 1 else ""
        directives[directive] = sources
    return directives


def _check_hsts(value: str, findings: list[Finding]) -> None:
    """Analyse Strict-Transport-Security value."""
    value_lower = value.lower()

    # Extract max-age
    match = re.search(r"max-age\s*=\s*(\d+)", value_lower)
    if not match:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="HSTS missing max-age directive",
                description="Strict-Transport-Security header is present but has no valid max-age.",
                details={"value": value},
            )
        )
        return

    max_age = int(match.group(1))
    if max_age < _MIN_HSTS_MAX_AGE:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="HSTS max-age too short",
                description=(
                    f"max-age is {max_age}s ({max_age // 86400}d). Recommended minimum is {_MIN_HSTS_MAX_AGE}s (365d)."
                ),
                details={"max_age": max_age, "recommended": _MIN_HSTS_MAX_AGE},
            )
        )

    if "includesubdomains" not in value_lower:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="HSTS missing includeSubDomains",
                description="Without includeSubDomains, subdomains can still be accessed over HTTP.",
                details={"value": value},
            )
        )


def _check_csp(value: str, findings: list[Finding]) -> None:
    """Analyse Content-Security-Policy directives."""
    directives = _parse_csp(value)

    if not directives:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="CSP header is empty",
                description="Content-Security-Policy is present but contains no directives.",
            )
        )
        return

    # Check for dangerous values in key directives
    for directive in _CSP_DIRECTIVES_TO_CHECK:
        sources = directives.get(directive)
        if sources is None:
            continue
        dangerous = _CSP_DANGEROUS_VALUES.findall(sources)
        if dangerous:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"CSP {directive} contains unsafe source",
                    description=f"'{directive}' contains {', '.join(dangerous)} which weakens the policy.",
                    details={"directive": directive, "sources": sources, "unsafe": dangerous},
                )
            )

    # Missing default-src (fallback for all fetch directives)
    if "default-src" not in directives:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="CSP missing default-src",
                description="Without default-src, any unspecified fetch directive falls back to allowing everything.",
            )
        )

    # Check for report-only (not enforcing)
    # Note: report-only comes as a separate header, but some sites put it in CSP
    # We check the actual header name in the caller


def _check_xcto(value: str, findings: list[Finding]) -> None:
    """Analyse X-Content-Type-Options value."""
    if value.strip().lower() != _VALID_XCTO:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="X-Content-Type-Options has invalid value",
                description=f"Expected 'nosniff', got '{value.strip()}'.",
                details={"value": value.strip(), "expected": _VALID_XCTO},
            )
        )


def _check_xfo(value: str, findings: list[Finding]) -> None:
    """Analyse X-Frame-Options value."""
    val = value.strip().lower()
    # allow-from is deprecated and ignored by modern browsers
    if val.startswith("allow-from"):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="X-Frame-Options uses deprecated ALLOW-FROM",
                description="ALLOW-FROM is not supported by modern browsers. Use CSP frame-ancestors instead.",
                details={"value": value.strip()},
            )
        )
    elif val not in _VALID_XFO:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="X-Frame-Options has invalid value",
                description=f"Expected 'DENY' or 'SAMEORIGIN', got '{value.strip()}'.",
                details={"value": value.strip()},
            )
        )


def _check_referrer_policy(value: str, findings: list[Finding]) -> None:
    """Analyse Referrer-Policy value."""
    # Referrer-Policy can be comma-separated (fallback list); use the last supported value
    policies = [p.strip().lower() for p in value.split(",")]
    effective = policies[-1] if policies else ""

    if effective == "unsafe-url":
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Referrer-Policy set to unsafe-url",
                description="'unsafe-url' sends the full URL as referrer, leaking paths and query parameters.",
                details={"value": value},
            )
        )
    elif effective == "no-referrer-when-downgrade":
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="Referrer-Policy uses weak no-referrer-when-downgrade",
                description="Leaks the full URL for same-protocol requests. Prefer strict-origin-when-cross-origin.",
                details={"value": value},
            )
        )
    elif effective and effective not in _SAFE_REFERRER_POLICIES:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title=f"Referrer-Policy has uncommon value '{effective}'",
                description="Verify this policy meets your privacy requirements.",
                details={"value": value, "effective_policy": effective},
            )
        )


def _check_cookies(resp: httpx.Response, findings: list[Finding]) -> None:
    """Check Set-Cookie headers for security attributes."""
    cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]

    is_https = str(resp.url).startswith("https://")

    for cookie_str in cookies:
        # Extract cookie name
        name = cookie_str.split("=", 1)[0].strip()
        lower = cookie_str.lower()

        if is_https and "secure" not in lower:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"Cookie '{name}' missing Secure flag",
                    description="Without the Secure flag, the cookie can be sent over unencrypted HTTP.",
                    details={"cookie": name},
                )
            )

        if "httponly" not in lower:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    description="Without HttpOnly, the cookie is accessible via JavaScript (XSS risk).",
                    details={"cookie": name},
                )
            )

        if "samesite" not in lower:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title=f"Cookie '{name}' missing SameSite attribute",
                    description="Without SameSite, the cookie may be sent in cross-site requests (CSRF risk).",
                    details={"cookie": name},
                )
            )


# ---------------------------------------------------------------------------
# Fetch helper (reused from original)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Headers to check: (header_name, severity_if_missing, title, description)
# ---------------------------------------------------------------------------

_EXPECTED_HEADERS: list[tuple[str, Severity, str, str]] = [
    (
        "strict-transport-security",
        Severity.HIGH,
        "HSTS not set",
        "Without HSTS, users can be downgraded to HTTP via man-in-the-middle attacks.",
    ),
    (
        "content-security-policy",
        Severity.MEDIUM,
        "CSP not set",
        "Content-Security-Policy helps prevent XSS and data injection attacks.",
    ),
    (
        "x-content-type-options",
        Severity.MEDIUM,
        "X-Content-Type-Options not set",
        "Without nosniff, browsers may MIME-sniff responses, enabling XSS via content type confusion.",
    ),
    (
        "x-frame-options",
        Severity.MEDIUM,
        "X-Frame-Options not set",
        "Without framing protection the site is vulnerable to clickjacking.",
    ),
    (
        "permissions-policy",
        Severity.LOW,
        "Permissions-Policy not set",
        "Permissions-Policy restricts browser features (camera, microphone, geolocation).",
    ),
    (
        "referrer-policy",
        Severity.LOW,
        "Referrer-Policy not set",
        "Without Referrer-Policy, the full URL may leak to third-party sites.",
    ),
]

# Deep-analysis dispatch: header → analysis function
_DEEP_CHECKS: dict[str, Callable[..., Any]] = {
    "strict-transport-security": _check_hsts,
    "content-security-policy": _check_csp,
    "x-content-type-options": _check_xcto,
    "x-frame-options": _check_xfo,
    "referrer-policy": _check_referrer_policy,
}


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    try:
        resp = await _fetch(target, timeout)
    except httpx.HTTPError as exc:
        return CheckResult(check=CheckType.HEADERS, error=f"Cannot connect to {target}: {exc}")

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[Finding] = []

    # --- Missing-header checks + deep value analysis when present ---
    present_security_headers: dict[str, str] = {}
    for header_name, severity, title, description in _EXPECTED_HEADERS:
        if header_name not in headers_lower:
            findings.append(Finding(severity=severity, title=title, description=description))
        else:
            value = headers_lower[header_name]
            present_security_headers[header_name] = value
            # Run deep analysis if available
            deep_fn = _DEEP_CHECKS.get(header_name)
            if deep_fn:
                deep_fn(value, findings)

    # --- Positive findings for well-configured headers ---
    if "strict-transport-security" in present_security_headers:
        match = re.search(r"max-age\s*=\s*(\d+)", present_security_headers["strict-transport-security"].lower())
        if match and int(match.group(1)) >= _MIN_HSTS_MAX_AGE:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="HSTS is properly configured",
                    description="HSTS is set with a strong max-age.",
                )
            )
    if "content-security-policy" in present_security_headers:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="Content-Security-Policy is set",
                description="CSP header is present and enforced.",
            )
        )
    if (
        "x-content-type-options" in present_security_headers
        and present_security_headers["x-content-type-options"].strip().lower() == _VALID_XCTO
    ):
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="X-Content-Type-Options is set",
                description="nosniff is enabled, preventing MIME-type sniffing.",
            )
        )
    if "permissions-policy" in present_security_headers:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="Permissions-Policy is set",
                description="Browser feature restrictions are configured.",
            )
        )

    # --- CSP report-only without enforcement ---
    if "content-security-policy-report-only" in headers_lower and "content-security-policy" not in headers_lower:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="CSP is report-only, not enforced",
                description="Content-Security-Policy-Report-Only is set but the enforcing CSP header is absent.",
            )
        )

    # --- Information-leaking headers ---
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

    # --- HTTPS check ---
    if resp.url and str(resp.url).startswith("http://"):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Site served over HTTP (not HTTPS)",
                description="The target does not use HTTPS, all traffic is unencrypted.",
            )
        )
    elif resp.url and str(resp.url).startswith("https://"):
        findings.append(
            Finding(severity=Severity.INFO, title="HTTPS is enabled", description="Site is served over HTTPS.")
        )

    # --- Cookie security ---
    _check_cookies(resp, findings)

    raw = {
        "url": str(resp.url),
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "present_security_headers": present_security_headers,
    }

    return CheckResult(check=CheckType.HEADERS, findings=findings, raw=raw)
