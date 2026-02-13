"""HTTP security headers scanner — powered by drheaderplus.

Uses the drHEADer rule engine for header analysis, with supplementary checks
for HTTPS, CSP report-only, and positive findings.
"""

from __future__ import annotations

import httpx
from drheader import Drheader

from infraprobe.models import CheckResult, CheckType, Finding, Severity

# drheaderplus severity → our Severity enum
_SEVERITY_MAP: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _map_severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get(raw.lower(), Severity.MEDIUM)


def _build_details(item: object) -> dict:
    """Extract useful fields from a drheaderplus Finding into details."""
    keys = ("value", "expected", "delimiter", "anomalies", "avoid")
    return {k: v for k in keys if (v := getattr(item, k, None)) is not None}


# ---------------------------------------------------------------------------
# Fetch helper (kept from original — async, HTTPS-first with fallback)
# ---------------------------------------------------------------------------


async def _fetch(target: str, timeout: float) -> httpx.Response:
    """Try HTTPS first (short connect timeout), fall back to HTTP."""
    host = target.split(":")[0] if ":" in target and not target.startswith("[") else target

    if "://" in target:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            return await client.get(target)

    try:
        connect_timeout = min(3.0, timeout)
        timeouts = httpx.Timeout(timeout, connect=connect_timeout)
        async with httpx.AsyncClient(verify=False, timeout=timeouts, follow_redirects=True) as client:
            return await client.get(f"https://{target}")
    except httpx.HTTPError:
        pass

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        return await client.get(f"http://{host}")


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    try:
        resp = await _fetch(target, timeout)
    except httpx.HTTPError as exc:
        return CheckResult(check=CheckType.HEADERS, error=f"Cannot connect to {target}: {exc}")

    # Build headers dict for drheaderplus.
    # set-cookie must be a list for cookie validation to work.
    headers_for_drheader: dict[str, str | list[str]] = {}
    for k, v in resp.headers.multi_items():
        k_lower = k.lower()
        if k_lower == "set-cookie":
            headers_for_drheader.setdefault("set-cookie", []).append(v)  # type: ignore[union-attr]
        else:
            headers_for_drheader[k_lower] = v

    # Run drheaderplus analysis
    scanner = Drheader(headers=headers_for_drheader)
    report = scanner.analyze()

    findings: list[Finding] = []
    for item in report:
        findings.append(
            Finding(
                severity=_map_severity(item.severity),
                title=f"{item.rule}: {item.message}",
                description=f"{item.rule} — {item.message}",
                details=_build_details(item),
            )
        )

    # --- Supplementary checks not covered by drheaderplus ---

    url = str(resp.url)
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # HTTPS check
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

    # CSP report-only without enforcement
    if "content-security-policy-report-only" in headers_lower and "content-security-policy" not in headers_lower:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="CSP is report-only, not enforced",
                description="Content-Security-Policy-Report-Only is set but the enforcing CSP header is absent.",
            )
        )

    raw = {
        "url": url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
    }

    return CheckResult(check=CheckType.HEADERS, findings=findings, raw=raw)
