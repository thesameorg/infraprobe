"""CVE scanner — nmap version detection + NVD API lookup for known vulnerabilities."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
import nmap

from infraprobe.blocklist import BlockedTargetError, InvalidTargetError, validate_target
from infraprobe.config import settings
from infraprobe.models import CheckResult, CheckType, Finding, Severity
from infraprobe.target import parse_target

logger = logging.getLogger("infraprobe.scanners.cve")

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cvss_to_severity(score: float) -> Severity:
    """Map a CVSS base score to InfraProbe severity."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFO


def _cpe22_to_cpe23(cpe22: str) -> str:
    """Convert a CPE 2.2 URI (nmap output) to CPE 2.3 formatted string.

    Example: ``cpe:/a:openbsd:openssh:7.6p1`` → ``cpe:2.3:a:openbsd:openssh:7.6p1:*:*:*:*:*:*:*``
    """
    if not cpe22.startswith("cpe:/"):
        return cpe22
    parts = cpe22[5:].split(":")
    # CPE 2.3 has exactly 11 components after the "cpe:2.3:" prefix
    while len(parts) < 11:
        parts.append("*")
    return "cpe:2.3:" + ":".join(parts[:11])


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float, str]:
    """Extract the best available CVSS base score and version string."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            return cvss_data.get("baseScore", 0.0), cvss_data.get("version", "")
    return 0.0, ""


def _extract_description(descriptions: list[dict[str, str]]) -> str:
    """Extract English description from NVD CVE descriptions array."""
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


# ---------------------------------------------------------------------------
# Nmap version detection (blocking — runs in thread pool)
# ---------------------------------------------------------------------------


def _run_nmap_version(host: str, arguments: str) -> list[dict[str, Any]]:
    """Run nmap with version detection — returns services with CPE info."""
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments=arguments)

    services: list[dict[str, Any]] = []
    for scanned_host in nm.all_hosts():
        for proto in nm[scanned_host].all_protocols():
            for port in sorted(nm[scanned_host][proto].keys()):
                info = nm[scanned_host][proto][port]
                if info.get("state") != "open":
                    continue
                product = info.get("product", "")
                version = info.get("version", "")
                cpe = info.get("cpe", "")
                # Only include if nmap identified something useful
                if product or cpe:
                    services.append(
                        {
                            "port": port,
                            "protocol": proto,
                            "service": info.get("name", ""),
                            "product": product,
                            "version": version,
                            "cpe": cpe,
                        }
                    )
    return services


# ---------------------------------------------------------------------------
# NVD API query
# ---------------------------------------------------------------------------


async def _query_nvd(
    cpe23: str | None,
    product: str,
    version: str,
    timeout: float,
    api_key: str | None,
) -> list[dict[str, Any]]:
    """Query NVD API 2.0 for CVEs matching a CPE or product+version.

    Prefers ``cpeName`` (accurate, CPE-based) and falls back to
    ``keywordSearch`` (broader, may include noise).
    """
    params: dict[str, str | int] = {
        "resultsPerPage": 25,
        "noRejected": "",
    }

    if cpe23 and cpe23.startswith("cpe:2.3:"):
        params["cpeName"] = cpe23
    elif product and version:
        # Use only the first version token to avoid over-specific queries
        # e.g. "6.6.1p1 Ubuntu 2ubuntu2.13" → "6.6.1p1"
        short_version = version.split()[0] if version else version
        params["keywordSearch"] = f"{product} {short_version}"
    else:
        return []

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=3.0)) as client:
        try:
            resp = await client.get(_NVD_API_URL, params=params, headers=headers)
            if resp.status_code in (403, 404):
                logger.warning("NVD API %d", resp.status_code, extra={"cpe": cpe23, "product": product})
                return []
            resp.raise_for_status()
            data = resp.json()
            return data.get("vulnerabilities", [])
        except Exception as exc:
            logger.warning("NVD query failed", extra={"error": str(exc), "cpe": cpe23, "product": product})
            return []


# ---------------------------------------------------------------------------
# Scanner entrypoint
# ---------------------------------------------------------------------------


async def scan(target: str, timeout: float = 30.0) -> CheckResult:
    """CVE scanner: nmap version detection on top-20 ports → NVD API lookup."""
    try:
        host = parse_target(target).host
        api_key = settings.nvd_api_key

        # Re-validate and use pre-resolved IP for nmap to prevent DNS rebinding
        try:
            ctx = validate_target(target)
            nmap_host = ctx.resolved_ips[0] if ctx.resolved_ips else host
        except (BlockedTargetError, InvalidTargetError) as exc:
            return CheckResult(check=CheckType.CVE, error=f"Target validation failed: {exc}")

        # ---- Budget split: 70 % nmap, 25 % NVD, 5 % margin ----
        nmap_budget = timeout * 0.7
        nvd_budget = timeout * 0.25

        nmap_host_timeout = max(3, int(nmap_budget - 1))
        nmap_args = f"-sT -sV -T4 -Pn --top-ports 20 --host-timeout {nmap_host_timeout}s"

        services = await asyncio.to_thread(_run_nmap_version, nmap_host, nmap_args)

        if not services:
            return CheckResult(
                check=CheckType.CVE,
                findings=[
                    Finding(
                        severity=Severity.INFO,
                        title="No versioned services detected",
                        description="No open ports with identifiable service versions were found.",
                    )
                ],
                raw={"host": host, "services_scanned": 0, "cves_found": 0},
            )

        # ---- NVD queries — one per unique service, all in parallel ----
        seen_queries: set[str] = set()
        query_tasks: list[tuple[dict[str, Any], asyncio.Task]] = []

        per_query_timeout = max(5.0, nvd_budget)

        for svc in services:
            raw_cpe = svc["cpe"]
            # OS-level CPEs (cpe:/o:...) don't describe the service — fall back to keyword search
            cpe23 = _cpe22_to_cpe23(raw_cpe) if raw_cpe and not raw_cpe.startswith("cpe:/o:") else None
            query_key = cpe23 or f"{svc['product']}:{svc['version']}"
            if query_key in seen_queries or query_key == ":":
                continue
            seen_queries.add(query_key)

            task = asyncio.create_task(_query_nvd(cpe23, svc["product"], svc["version"], per_query_timeout, api_key))
            query_tasks.append((svc, task))

        # ---- Collect results ----
        findings: list[Finding] = []
        all_cves: list[dict[str, Any]] = []
        seen_cve_ids: set[str] = set()

        for svc, task in query_tasks:
            try:
                vulns = await asyncio.wait_for(task, timeout=per_query_timeout + 1)
            except TimeoutError:
                logger.warning("NVD query timed out", extra={"product": svc["product"]})
                continue

            for vuln in vulns:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id or cve_id in seen_cve_ids:
                    continue
                seen_cve_ids.add(cve_id)

                cvss_score, cvss_version = _extract_cvss(cve_data.get("metrics", {}))
                severity = _cvss_to_severity(cvss_score)
                desc = _extract_description(cve_data.get("descriptions", []))

                svc_label = svc["product"]
                if svc["version"]:
                    svc_label += f" {svc['version']}"

                findings.append(
                    Finding(
                        severity=severity,
                        title=f"{cve_id} — {svc_label} (port {svc['port']})",
                        description=desc[:500] if desc else f"CVE found for {svc_label}",
                        details={
                            "cve_id": cve_id,
                            "cvss_score": cvss_score,
                            "cvss_version": cvss_version,
                            "port": svc["port"],
                            "service": svc["service"],
                            "product": svc["product"],
                            "version": svc["version"],
                            "cpe": svc["cpe"],
                        },
                    )
                )

                all_cves.append(
                    {
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": str(severity),
                        "product": svc["product"],
                        "version": svc["version"],
                        "port": svc["port"],
                    }
                )

        # Sort: most severe first, then alphabetically by CVE ID
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        findings.sort(key=lambda f: (sev_order.get(f.severity, 5), f.title))

        if not findings:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="No known CVEs found",
                    description=f"No known vulnerabilities found for {len(services)} detected service(s).",
                )
            )

        return CheckResult(
            check=CheckType.CVE,
            findings=findings,
            raw={
                "host": host,
                "services_scanned": len(services),
                "services": services,
                "cves_found": len(all_cves),
                "cves": all_cves,
            },
        )

    except Exception as exc:
        return CheckResult(check=CheckType.CVE, error=f"CVE scan failed: {exc}")
