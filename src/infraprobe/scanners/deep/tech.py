"""Deep technology detection scanner powered by wappalyzer-next.

Uses the official Wappalyzer fingerprint database (1,500+ technologies).
Runs in 'fast' mode (single HTTP request, no browser dependency).
"""

from __future__ import annotations

import asyncio

from infraprobe.models import CheckResult, CheckType, Finding, Severity

# CMS names that warrant a security finding
_CMS_FINDINGS = frozenset({"WordPress", "Joomla", "Drupal", "Magento", "PrestaShop"})


def _run_wappalyzer(url: str) -> dict:
    """Run wappalyzer analysis synchronously (called via asyncio.to_thread)."""
    from wappalyzer import analyze

    return analyze(url=url, scan_type="fast")


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    host = target.split(":")[0] if ":" in target and not target.startswith("[") else target

    url = target if "://" in target else f"https://{host}"

    try:
        result = await asyncio.to_thread(_run_wappalyzer, url)
    except Exception:
        # HTTPS failed, try HTTP
        if not target.startswith("http"):
            try:
                url = f"http://{host}"
                result = await asyncio.to_thread(_run_wappalyzer, url)
            except Exception as exc:
                return CheckResult(check=CheckType.TECH_DEEP, error=f"Cannot analyze {target}: {exc}")
        else:
            return CheckResult(check=CheckType.TECH_DEEP, error=f"Cannot analyze {target}")

    # Wappalyzer returns {url: {tech_name: {version, confidence, categories, groups}}}
    techs: dict = {}
    for _url_key, tech_map in result.items():
        techs = tech_map
        break

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

    raw = {
        "url": url,
        "detected": detected,
        "technologies_count": len(detected),
    }

    return CheckResult(check=CheckType.TECH_DEEP, findings=findings, raw=raw)
