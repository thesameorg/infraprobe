"""Web security scanner — CORS, exposed paths, robots.txt, mixed content, security.txt."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from infraprobe.http import fetch_with_fallback, scanner_client
from infraprobe.models import CheckResult, CheckType, Finding, Severity

logger = logging.getLogger("infraprobe.scanners.web")

# ---------------------------------------------------------------------------
# Sensitive path probes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PathProbe:
    """A sensitive path to probe. content_check validates the body to reduce false positives."""

    path: str
    severity: Severity
    title: str
    description: str
    content_check: Callable[[str], bool] | None = None


_PROBES: tuple[_PathProbe, ...] = (
    _PathProbe(
        path="/.env",
        severity=Severity.CRITICAL,
        title="Environment file (.env) is publicly accessible",
        description=".env files often contain API keys, database credentials, and other secrets.",
        content_check=lambda body: (
            "=" in body
            and any(kw in body.upper() for kw in ("KEY", "SECRET", "PASSWORD", "DB_", "DATABASE", "TOKEN", "API"))
        ),
    ),
    _PathProbe(
        path="/.git/HEAD",
        severity=Severity.HIGH,
        title="Git repository is publicly accessible",
        description="Exposed .git directory allows attackers to download source code and commit history.",
        content_check=lambda body: (
            body.strip().startswith("ref:")
            or (len(body.strip()) == 40 and all(c in "0123456789abcdef" for c in body.strip()))
        ),
    ),
    _PathProbe(
        path="/.git/config",
        severity=Severity.HIGH,
        title="Git config is publicly accessible",
        description="Exposed .git/config may reveal remote repository URLs and configuration.",
        content_check=lambda body: "[core]" in body or "[remote" in body,
    ),
    _PathProbe(
        path="/.htpasswd",
        severity=Severity.CRITICAL,
        title=".htpasswd file is publicly accessible",
        description=".htpasswd contains password hashes that can be cracked offline.",
        content_check=lambda body: ":" in body and ("$" in body or "{SHA}" in body),
    ),
    _PathProbe(
        path="/wp-config.php.bak",
        severity=Severity.CRITICAL,
        title="WordPress config backup is publicly accessible",
        description="wp-config.php.bak may contain database credentials and authentication keys.",
        content_check=lambda body: "DB_PASSWORD" in body or "DB_NAME" in body or "<?php" in body,
    ),
    _PathProbe(
        path="/phpinfo.php",
        severity=Severity.HIGH,
        title="phpinfo() page is publicly accessible",
        description="phpinfo() exposes PHP version, server config, environment variables, and installed modules.",
        content_check=lambda body: "phpinfo()" in body or "PHP Version" in body or "PHP License" in body,
    ),
    _PathProbe(
        path="/server-status",
        severity=Severity.MEDIUM,
        title="Apache server-status is publicly accessible",
        description="server-status exposes active connections, request details, and server load.",
        content_check=lambda body: "Apache Server Status" in body or "Server Version:" in body,
    ),
    _PathProbe(
        path="/server-info",
        severity=Severity.MEDIUM,
        title="Apache server-info is publicly accessible",
        description="server-info exposes module configuration and server internals.",
        content_check=lambda body: "Apache Server Information" in body,
    ),
    _PathProbe(
        path="/.svn/entries",
        severity=Severity.HIGH,
        title="SVN repository is publicly accessible",
        description="Exposed .svn directory allows attackers to download source code.",
        content_check=lambda body: body.strip().split("\n")[0].strip().isdigit() if body.strip() else False,
    ),
    _PathProbe(
        path="/elmah.axd",
        severity=Severity.HIGH,
        title="ELMAH error log is publicly accessible",
        description="ELMAH exposes detailed error logs, stack traces, and potentially sensitive data.",
        content_check=lambda body: "Error Log for" in body or "ELMAH" in body,
    ),
    _PathProbe(
        path="/actuator",
        severity=Severity.HIGH,
        title="Spring Boot Actuator is publicly accessible",
        description="Actuator endpoints expose application internals, environment variables, and health data.",
        content_check=lambda body: '"_links"' in body or '"health"' in body,
    ),
    _PathProbe(
        path="/debug/pprof/",
        severity=Severity.HIGH,
        title="Go pprof debug endpoint is publicly accessible",
        description="pprof exposes profiling data, goroutine dumps, and memory statistics.",
        content_check=lambda body: "goroutine" in body or "heap" in body,
    ),
)

# Sensitive keywords in robots.txt Disallow entries
_ROBOTS_SENSITIVE = frozenset(
    {
        "/admin",
        "/administrator",
        "/backup",
        "/config",
        "/database",
        "/db",
        "/debug",
        "/internal",
        "/private",
        "/secret",
        "/staging",
        "/test",
        "/tmp",
        "/wp-admin",
        "/cgi-bin",
        "/phpmyadmin",
    }
)

# Regex to find http:// resources in HTML attributes
_MIXED_CONTENT_RE = re.compile(
    r"""(?:src|href|action)\s*=\s*["'](http://[^"']+)["']""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# CORS check
# ---------------------------------------------------------------------------

_EVIL_ORIGIN = "https://evil.example.com"


async def _check_cors(base_url: str, client: httpx.AsyncClient, findings: list[Finding], raw: dict[str, Any]) -> None:
    """Check for CORS misconfiguration by sending a request with a spoofed Origin."""
    try:
        resp = await client.get(base_url, headers={"Origin": _EVIL_ORIGIN})
    except httpx.HTTPError:
        return

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()

    raw["cors"] = {
        "access_control_allow_origin": acao or None,
        "access_control_allow_credentials": acac or None,
    }

    if acao == _EVIL_ORIGIN:
        sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
        cred_note = " with credentials allowed" if acac == "true" else ""
        findings.append(
            Finding(
                severity=sev,
                title=f"CORS reflects arbitrary Origin{cred_note}",
                description=(
                    f"The server echoes back the attacker-controlled Origin header{cred_note}, "
                    "enabling cross-site data theft."
                ),
                details={"origin_sent": _EVIL_ORIGIN, "acao": acao, "acac": acac or None},
            )
        )
    elif acao == "*":
        if acac == "true":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="CORS allows all origins with credentials",
                    description=(
                        "Access-Control-Allow-Origin is '*' with credentials allowed. "
                        "Browsers block this combination, but it indicates a misconfiguration."
                    ),
                    details={"acao": acao, "acac": acac},
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="CORS allows all origins",
                    description=(
                        "Access-Control-Allow-Origin is '*'. "
                        "This is only a concern if the endpoint serves sensitive data."
                    ),
                    details={"acao": acao},
                )
            )
    elif acao == "null":
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="CORS allows null Origin",
                description="Access-Control-Allow-Origin is 'null', which can be exploited via sandboxed iframes.",
                details={"acao": acao},
            )
        )
    elif not acao:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="No CORS headers present",
                description="The server does not return CORS headers, following the same-origin policy.",
            )
        )


# ---------------------------------------------------------------------------
# Exposed path probes
# ---------------------------------------------------------------------------


async def _probe_path(base_url: str, probe: _PathProbe, client: httpx.AsyncClient) -> Finding | None:
    """Probe a single path. Return a Finding if the path is exposed, None otherwise."""
    url = base_url.rstrip("/") + probe.path
    try:
        resp = await client.get(url, follow_redirects=False)
    except httpx.HTTPError:
        return None

    if resp.status_code != 200:
        return None

    # Content check to filter out custom 404 pages that return 200
    if probe.content_check is not None:
        try:
            body = resp.text[:8192]
        except Exception:
            return None
        if not probe.content_check(body):
            return None

    return Finding(
        severity=probe.severity,
        title=probe.title,
        description=probe.description,
        details={"path": probe.path, "url": url, "status_code": resp.status_code},
    )


async def _check_paths(base_url: str, client: httpx.AsyncClient, findings: list[Finding], raw: dict[str, Any]) -> None:
    """Probe all sensitive paths in parallel."""
    tasks = [_probe_path(base_url, probe, client) for probe in _PROBES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    exposed: list[str] = []
    for result in results:
        if isinstance(result, Exception):
            logger.error("path probe failed", extra={"error": str(result)}, exc_info=result)
        elif isinstance(result, Finding):
            findings.append(result)
            exposed.append(result.details.get("path", ""))

    raw["exposed_paths"] = exposed

    if not exposed:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="No common sensitive paths exposed",
                description=f"Probed {len(_PROBES)} common sensitive paths — none were publicly accessible.",
                details={"paths_checked": [p.path for p in _PROBES]},
            )
        )


# ---------------------------------------------------------------------------
# robots.txt analysis
# ---------------------------------------------------------------------------


async def _check_robots(base_url: str, client: httpx.AsyncClient, findings: list[Finding], raw: dict[str, Any]) -> None:
    """Fetch and analyze robots.txt for sensitive path disclosures."""
    url = base_url.rstrip("/") + "/robots.txt"
    try:
        resp = await client.get(url, follow_redirects=False)
    except httpx.HTTPError:
        return

    if resp.status_code != 200:
        return

    body = resp.text
    disallowed: list[str] = []
    sensitive: list[str] = []

    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
                path_lower = path.lower().rstrip("/")
                if any(s in path_lower for s in _ROBOTS_SENSITIVE):
                    sensitive.append(path)

    raw["robots_txt"] = {
        "found": True,
        "disallowed_count": len(disallowed),
        "sensitive_paths": sensitive,
    }

    if sensitive:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="robots.txt reveals sensitive paths",
                description=f"robots.txt disallows potentially sensitive paths: {', '.join(sensitive)}",
                details={"sensitive_paths": sensitive},
            )
        )


# ---------------------------------------------------------------------------
# Mixed content
# ---------------------------------------------------------------------------


def _check_mixed_content(resp: httpx.Response, findings: list[Finding], raw: dict[str, Any]) -> None:
    """Check for HTTP resources loaded on an HTTPS page."""
    if not str(resp.url).startswith("https://"):
        return  # mixed content only applies to HTTPS pages

    try:
        body = resp.text
    except Exception:
        return

    urls = _MIXED_CONTENT_RE.findall(body)
    raw["mixed_content"] = urls[:20]

    if urls:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Mixed content: HTTP resources on HTTPS page",
                description=f"Found {len(urls)} HTTP resource(s) on HTTPS page, weakening transport security.",
                details={"urls": urls[:10], "total": len(urls)},
            )
        )


# ---------------------------------------------------------------------------
# security.txt (RFC 9116)
# ---------------------------------------------------------------------------


async def _check_security_txt(
    base_url: str, client: httpx.AsyncClient, findings: list[Finding], raw: dict[str, Any]
) -> None:
    """Check for a security.txt file at /.well-known/security.txt."""
    url = base_url.rstrip("/") + "/.well-known/security.txt"
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError:
        raw["security_txt"] = False
        return

    if resp.status_code == 200 and ("Contact:" in resp.text or "contact:" in resp.text):
        raw["security_txt"] = True
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="security.txt is present",
                description="security.txt helps researchers report vulnerabilities responsibly (RFC 9116).",
            )
        )
    else:
        raw["security_txt"] = False
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="No security.txt found",
                description="Add /.well-known/security.txt to help researchers report vulnerabilities (RFC 9116).",
            )
        )


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


async def scan(target: str, timeout: float = 10.0, auth=None) -> CheckResult:
    """Web security scan: CORS, exposed paths, mixed content, robots.txt, security.txt."""
    findings: list[Finding] = []
    raw: dict[str, Any] = {}

    try:
        async with scanner_client(timeout, auth=auth) as client:
            # Determine base URL (HTTPS first, HTTP fallback)
            base_url, main_resp = await fetch_with_fallback(target, client)
            raw["url"] = str(main_resp.url)
            raw["status_code"] = main_resp.status_code

            # Sync check on the response we already have
            _check_mixed_content(main_resp, findings, raw)

            # Parallel async checks
            check_results = await asyncio.gather(
                _check_cors(base_url, client, findings, raw),
                _check_paths(base_url, client, findings, raw),
                _check_robots(base_url, client, findings, raw),
                _check_security_txt(base_url, client, findings, raw),
                return_exceptions=True,
            )
            for result in check_results:
                if isinstance(result, Exception):
                    logger.error("web sub-check failed", extra={"error": str(result)}, exc_info=result)
    except httpx.HTTPError as exc:
        return CheckResult(check=CheckType.WEB, error=f"Cannot connect to {target}: {exc}")

    return CheckResult(check=CheckType.WEB, findings=findings, raw=raw)
