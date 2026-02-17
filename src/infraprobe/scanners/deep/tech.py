"""Deep technology detection scanner powered by wappalyzer-next.

Uses the official Wappalyzer fingerprint database (1,500+ technologies).
Runs in 'fast' mode (single HTTP request, no browser dependency).
We handle HTTP fetching ourselves (with proper timeouts) and feed the
response to wappalyzer's analyze_from_response() directly.
"""

from __future__ import annotations

import asyncio

import httpx

from infraprobe.http import fetch_with_fallback, scanner_client
from infraprobe.models import CheckResult, CheckType, Finding, Severity


class _ResponseAdapter:
    """Minimal adapter so httpx.Response satisfies wappalyzer's analyze_from_response."""

    def __init__(self, resp: httpx.Response) -> None:
        self.text = resp.text
        self.url = str(resp.url)
        self.headers = dict(resp.headers)
        self._cookies = {k: v for k, v in resp.cookies.items()}
        self.raw = None  # certIssuer parser accesses .raw but handles exceptions

    class _CookieDict(dict):
        def get_dict(self) -> dict:
            return dict(self)

    @property
    def cookies(self) -> _CookieDict:
        return self._CookieDict(self._cookies)


# CMS names that warrant a security finding
_CMS_FINDINGS = frozenset({"WordPress", "Joomla", "Drupal", "Magento", "PrestaShop"})


def _analyze_response(adapted: _ResponseAdapter) -> dict:
    """Run wappalyzer analysis on a pre-fetched response (called via asyncio.to_thread)."""
    # Stub wappalyzer.browser before import — the browser subpackage (Selenium-based)
    # is stripped from the Docker image to save ~60MB, but wappalyzer's __init__.py
    # unconditionally imports from it.  We only use wappalyzer.core (HTTP-only analysis).
    import sys
    import types

    if "wappalyzer.browser" not in sys.modules:
        _stub = types.ModuleType("wappalyzer.browser")
        _stub.analyzer = types.ModuleType("wappalyzer.browser.analyzer")  # type: ignore[attr-defined]
        _stub.analyzer.DriverPool = None  # type: ignore[attr-defined]
        _stub.analyzer.cookie_to_cookies = None  # type: ignore[attr-defined]
        _stub.analyzer.process_url = None  # type: ignore[attr-defined]
        _stub.analyzer.merge_technologies = None  # type: ignore[attr-defined]
        sys.modules["wappalyzer.browser"] = _stub
        sys.modules["wappalyzer.browser.analyzer"] = _stub.analyzer  # type: ignore[attr-defined]

    from wappalyzer.core.analyzer import analyze_from_response
    from wappalyzer.core.utils import create_result

    techs = analyze_from_response(adapted, scan_type="fast")
    return create_result(techs)


async def scan(target: str, timeout: float = 10.0, auth=None) -> CheckResult:
    try:
        async with scanner_client(timeout, auth=auth) as client:
            url, resp = await fetch_with_fallback(target, client)
    except httpx.HTTPError as exc:
        return CheckResult(check=CheckType.TECH_DEEP, error=f"Cannot analyze {target}: {exc}")

    adapted = _ResponseAdapter(resp)
    techs = await asyncio.to_thread(_analyze_response, adapted)

    findings: list[Finding] = []
    detected: list[dict] = []

    for name, info in techs.items():
        categories = info.get("categories", [])
        version = info.get("version", "")
        confidence = info.get("confidence", 0)
        groups = info.get("groups", [])

        detected.append(
            {
                "name": name,
                "version": version,
                "confidence": confidence,
                "categories": categories,
                "groups": groups,
            }
        )

        # CMS detections
        if name in _CMS_FINDINGS:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"{name} detected",
                    description=f"{name} CMS detected. Ensure core and extensions are up to date.",
                    details={"technology": name, "version": version},
                )
            )

        # Version exposure
        if version and any(cat in ("Programming languages", "Web servers") for cat in categories):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title=f"{name} version exposed",
                    description=f"{name} version '{version}' detected. Version exposure aids attackers.",
                    details={"technology": name, "version": version},
                )
            )

    # --- Positive findings for security-relevant tech ---
    categories_seen: set[str] = set()
    for tech in detected:
        for cat in tech.get("categories", []):
            categories_seen.add(cat.lower() if isinstance(cat, str) else "")

    cdn_names = [t["name"] for t in detected if any("cdn" in str(c).lower() for c in t.get("categories", []))]
    if cdn_names:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"CDN detected ({', '.join(cdn_names)})",
                description="A CDN provides DDoS protection and improved performance.",
            )
        )

    waf_names = [
        t["name"]
        for t in detected
        if any("firewall" in str(c).lower() or "waf" in str(c).lower() for c in t.get("categories", []))
    ]
    if waf_names:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"WAF detected ({', '.join(waf_names)})",
                description="A Web Application Firewall helps protect against common attacks.",
            )
        )

    raw = {
        "url": url,
        "detected": detected,
        "technologies_count": len(detected),
    }

    return CheckResult(check=CheckType.TECH_DEEP, findings=findings, raw=raw)
