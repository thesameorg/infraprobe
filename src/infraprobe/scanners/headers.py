"""HTTP security headers scanner — declarative rule engine.

Rules define required/forbidden headers, severity levels, and deep validators.
Inspired by drHEADer's rule-based approach but implemented without external deps.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from infraprobe.models import CheckResult, CheckType, Finding, Severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIN_HSTS_MAX_AGE = 31_536_000  # 1 year (OWASP recommendation)

_SAFE_REFERRER_POLICIES = frozenset({"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"})

_CSP_DANGEROUS = re.compile(r"'unsafe-inline'|'unsafe-eval'|data:|\*", re.IGNORECASE)
_CSP_DIRECTIVES = ("default-src", "script-src", "style-src", "object-src", "base-uri")


# ---------------------------------------------------------------------------
# Value validators — called only when the header IS present
# ---------------------------------------------------------------------------


def _validate_hsts(value: str, findings: list[Finding]) -> None:
    lower = value.lower()
    match = re.search(r"max-age\s*=\s*(\d+)", lower)
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

    if "includesubdomains" not in lower:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="HSTS missing includeSubDomains",
                description="Without includeSubDomains, subdomains can still be accessed over HTTP.",
                details={"value": value},
            )
        )


def _validate_csp(value: str, findings: list[Finding]) -> None:
    directives: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        directives[tokens[0].lower()] = tokens[1] if len(tokens) > 1 else ""

    if not directives:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="CSP header is empty",
                description="Content-Security-Policy is present but contains no directives.",
            )
        )
        return

    for d in _CSP_DIRECTIVES:
        sources = directives.get(d)
        if sources is None:
            continue
        dangerous = _CSP_DANGEROUS.findall(sources)
        if dangerous:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"CSP {d} contains unsafe source",
                    description=f"'{d}' contains {', '.join(dangerous)} which weakens the policy.",
                    details={"directive": d, "sources": sources, "unsafe": dangerous},
                )
            )

    if "default-src" not in directives:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="CSP missing default-src",
                description="Without default-src, any unspecified fetch directive falls back to allowing everything.",
            )
        )


def _validate_xcto(value: str, findings: list[Finding]) -> None:
    if value.strip().lower() != "nosniff":
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="X-Content-Type-Options has invalid value",
                description=f"Expected 'nosniff', got '{value.strip()}'.",
                details={"value": value.strip(), "expected": "nosniff"},
            )
        )


def _validate_xfo(value: str, findings: list[Finding]) -> None:
    val = value.strip().lower()
    if val.startswith("allow-from"):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="X-Frame-Options uses deprecated ALLOW-FROM",
                description="ALLOW-FROM is not supported by modern browsers. Use CSP frame-ancestors instead.",
                details={"value": value.strip()},
            )
        )
    elif val not in ("deny", "sameorigin"):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="X-Frame-Options has invalid value",
                description=f"Expected 'DENY' or 'SAMEORIGIN', got '{value.strip()}'.",
                details={"value": value.strip()},
            )
        )


def _validate_referrer(value: str, findings: list[Finding]) -> None:
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


def _validate_cache_control(value: str, findings: list[Finding]) -> None:
    lower = value.lower()
    if "no-store" not in lower and "private" not in lower:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="Cache-Control allows public caching",
                description="Without 'no-store' or 'private', responses may be cached by intermediaries.",
                details={"value": value},
            )
        )


# ---------------------------------------------------------------------------
# Positive-finding condition helpers
# ---------------------------------------------------------------------------


def _hsts_ok(value: str) -> bool:
    m = re.search(r"max-age\s*=\s*(\d+)", value.lower())
    return m is not None and int(m.group(1)) >= _MIN_HSTS_MAX_AGE


def _xcto_ok(value: str) -> bool:
    return value.strip().lower() == "nosniff"


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _RequiredRule:
    """Header that MUST be present. Optional value validation and positive finding."""

    header: str
    severity: Severity
    title_missing: str
    desc_missing: str
    validate: Callable[[str, list[Finding]], None] | None = None
    positive_title: str = ""
    positive_desc: str = ""
    positive_check: Callable[[str], bool] | None = None  # None → always emit positive


_REQUIRED_RULES: tuple[_RequiredRule, ...] = (
    _RequiredRule(
        header="strict-transport-security",
        severity=Severity.HIGH,
        title_missing="HSTS not set",
        desc_missing="Without HSTS, users can be downgraded to HTTP via man-in-the-middle attacks.",
        validate=_validate_hsts,
        positive_title="HSTS is properly configured",
        positive_desc="HSTS is set with a strong max-age.",
        positive_check=_hsts_ok,
    ),
    _RequiredRule(
        header="content-security-policy",
        severity=Severity.MEDIUM,
        title_missing="CSP not set",
        desc_missing="Content-Security-Policy helps prevent XSS and data injection attacks.",
        validate=_validate_csp,
        positive_title="Content-Security-Policy is set",
        positive_desc="CSP header is present and enforced.",
    ),
    _RequiredRule(
        header="x-content-type-options",
        severity=Severity.MEDIUM,
        title_missing="X-Content-Type-Options not set",
        desc_missing="Without nosniff, browsers may MIME-sniff responses, enabling XSS via content type confusion.",
        validate=_validate_xcto,
        positive_title="X-Content-Type-Options is set",
        positive_desc="nosniff is enabled, preventing MIME-type sniffing.",
        positive_check=_xcto_ok,
    ),
    _RequiredRule(
        header="x-frame-options",
        severity=Severity.MEDIUM,
        title_missing="X-Frame-Options not set",
        desc_missing="Without framing protection the site is vulnerable to clickjacking.",
        validate=_validate_xfo,
    ),
    _RequiredRule(
        header="permissions-policy",
        severity=Severity.LOW,
        title_missing="Permissions-Policy not set",
        desc_missing="Permissions-Policy restricts browser features (camera, microphone, geolocation).",
        positive_title="Permissions-Policy is set",
        positive_desc="Browser feature restrictions are configured.",
    ),
    _RequiredRule(
        header="referrer-policy",
        severity=Severity.LOW,
        title_missing="Referrer-Policy not set",
        desc_missing="Without Referrer-Policy, the full URL may leak to third-party sites.",
        validate=_validate_referrer,
    ),
    _RequiredRule(
        header="cache-control",
        severity=Severity.LOW,
        title_missing="Cache-Control not set",
        desc_missing="Without Cache-Control, sensitive responses may be stored by intermediate caches.",
        validate=_validate_cache_control,
    ),
)

# Info-leak headers: presence indicates a problem
_LEAK_HEADERS: tuple[tuple[str, str], ...] = (
    ("server", "Server header exposes software version"),
    ("x-powered-by", "X-Powered-By header exposes technology stack"),
    ("x-aspnet-version", "X-AspNet-Version header exposes ASP.NET version"),
    ("x-aspnetmvc-version", "X-AspNetMvc-Version header exposes ASP.NET MVC version"),
    ("x-generator", "X-Generator header exposes site generator"),
    ("x-client-ip", "X-Client-IP header leaks internal IP address"),
    ("x-forwarded-for", "X-Forwarded-For header leaks client/proxy IP addresses"),
)


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


def _eval_required(headers: dict[str, str], findings: list[Finding]) -> None:
    """Evaluate required-header rules: missing → finding, present → validate + positive."""
    for rule in _REQUIRED_RULES:
        value = headers.get(rule.header)
        if value is None:
            findings.append(Finding(severity=rule.severity, title=rule.title_missing, description=rule.desc_missing))
            continue
        if rule.validate:
            rule.validate(value, findings)
        if rule.positive_title and (rule.positive_check is None or rule.positive_check(value)):
            findings.append(Finding(severity=Severity.INFO, title=rule.positive_title, description=rule.positive_desc))


def _eval_leaks(headers: dict[str, str], findings: list[Finding]) -> None:
    """Detect info-leaking headers."""
    for header, desc in _LEAK_HEADERS:
        value = headers.get(header)
        if value is not None:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title=f"{header} header leaks information",
                    description=f"{desc}. Value: {value}",
                    details={"header": header, "value": value},
                )
            )


def _eval_xxss(headers: dict[str, str], findings: list[Finding]) -> None:
    """X-XSS-Protection is deprecated; non-zero values can cause info leaks."""
    value = headers.get("x-xss-protection")
    if value is not None and value.strip() != "0":
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="X-XSS-Protection is deprecated",
                description=(
                    f"Value '{value.strip()}' is set. Modern browsers ignore this header; use CSP instead. "
                    "'1; mode=block' can cause information leaks in old browsers."
                ),
                details={"value": value.strip()},
            )
        )


# ---------------------------------------------------------------------------
# Fetch helper
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
# Cookie security
# ---------------------------------------------------------------------------


def _check_cookies(resp: httpx.Response, findings: list[Finding]) -> None:
    """Check Set-Cookie headers for security attributes."""
    cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
    is_https = str(resp.url).startswith("https://")

    for cookie_str in cookies:
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
# Main scan
# ---------------------------------------------------------------------------


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    try:
        resp = await _fetch(target, timeout)
    except httpx.HTTPError as exc:
        return CheckResult(check=CheckType.HEADERS, error=f"Cannot connect to {target}: {exc}")

    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[Finding] = []

    # Declarative rule checks
    _eval_required(headers, findings)
    _eval_leaks(headers, findings)
    _eval_xxss(headers, findings)

    # CSP report-only without enforcement
    if "content-security-policy-report-only" in headers and "content-security-policy" not in headers:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="CSP is report-only, not enforced",
                description="Content-Security-Policy-Report-Only is set but the enforcing CSP header is absent.",
            )
        )

    # HTTPS check
    url = str(resp.url)
    if url.startswith("http://"):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Site served over HTTP (not HTTPS)",
                description="The target does not use HTTPS, all traffic is unencrypted.",
            )
        )
    elif url.startswith("https://"):
        findings.append(
            Finding(severity=Severity.INFO, title="HTTPS is enabled", description="Site is served over HTTPS.")
        )

    # Cookie security
    _check_cookies(resp, findings)

    raw = {
        "url": url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
    }

    return CheckResult(check=CheckType.HEADERS, findings=findings, raw=raw)
