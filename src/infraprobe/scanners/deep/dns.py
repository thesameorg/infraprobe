"""Deep DNS scanner powered by checkdmarc.

Full RFC-compliant SPF parsing (lookup counting, nested includes), DMARC policy
analysis (subdomain policy, alignment, reporting URIs), MX validation, and DNSSEC check.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict

import checkdmarc

from infraprobe.models import CheckResult, CheckType, Finding, Severity


def _strip_port(target: str) -> str:
    """Remove port from target if present."""
    if target.startswith("["):
        return target
    if ":" in target:
        host, _, maybe_port = target.rpartition(":")
        if maybe_port.isdigit():
            return host
    return target


def _run_checkdmarc(domain: str, timeout: float) -> OrderedDict:
    """Run checkdmarc synchronously (called via asyncio.to_thread)."""
    result = checkdmarc.check_domains(
        [domain],
        skip_tls=True,
        timeout=min(timeout / 3, 5.0),
    )
    if isinstance(result, list):
        return result[0]
    return result


def _analyze_results(data: OrderedDict, findings: list[Finding], raw: dict) -> None:
    """Convert checkdmarc results into findings."""
    raw["domain"] = data.get("domain", "")
    raw["base_domain"] = data.get("base_domain", "")
    raw["dnssec"] = data.get("dnssec", False)

    # --- DNSSEC ---
    if not data.get("dnssec"):
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="DNSSEC not enabled",
                description="Domain does not have DNSSEC, leaving DNS responses vulnerable to spoofing.",
            )
        )

    # --- NS ---
    ns_data = data.get("ns", {})
    raw["ns"] = ns_data.get("hostnames", [])
    for warning in ns_data.get("warnings", []):
        findings.append(Finding(severity=Severity.LOW, title="NS warning", description=str(warning)))

    # --- MX ---
    mx_data = data.get("mx", {})
    raw["mx"] = mx_data.get("hosts", [])
    for warning in mx_data.get("warnings", []):
        findings.append(Finding(severity=Severity.LOW, title="MX warning", description=str(warning)))

    # --- SPF ---
    spf_data = data.get("spf", {})
    if isinstance(spf_data, dict) and "error" in spf_data:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="SPF error",
                description=str(spf_data["error"]),
            )
        )
        raw["spf"] = spf_data.get("record", "")
    elif isinstance(spf_data, dict):
        raw["spf"] = spf_data.get("record", "")
        raw["spf_valid"] = spf_data.get("valid", False)
        raw["spf_dns_lookups"] = spf_data.get("dns_lookups", 0)

        if not spf_data.get("valid", True):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="SPF record is invalid",
                    description="The SPF record failed validation.",
                    details={"record": spf_data.get("record", "")},
                )
            )

        dns_lookups = spf_data.get("dns_lookups", 0)
        if dns_lookups > 10:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="SPF exceeds 10 DNS lookup limit",
                    description=f"SPF record requires {dns_lookups} DNS lookups (RFC 7208 limit is 10).",
                    details={"dns_lookups": dns_lookups},
                )
            )

        parsed = spf_data.get("parsed", {})
        all_mechanism = parsed.get("all", "")
        if all_mechanism == "pass":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="SPF allows all senders (+all)",
                    description="SPF record uses +all, allowing any server to send on behalf of this domain.",
                )
            )
        elif all_mechanism == "softfail":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="SPF uses softfail (~all)",
                    description="SPF record uses ~all (softfail). Consider upgrading to -all (hardfail).",
                )
            )

        for warning in spf_data.get("warnings", []):
            findings.append(Finding(severity=Severity.LOW, title="SPF warning", description=str(warning)))
    else:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="No SPF record",
                description="No SPF record found. Any server can claim to send email for this domain.",
            )
        )

    # --- DMARC ---
    dmarc_data = data.get("dmarc", {})
    if isinstance(dmarc_data, dict) and "error" in dmarc_data:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="DMARC error",
                description=str(dmarc_data["error"]),
            )
        )
        raw["dmarc"] = dmarc_data.get("record", "")
    elif isinstance(dmarc_data, dict) and dmarc_data.get("record"):
        raw["dmarc"] = dmarc_data.get("record", "")
        raw["dmarc_valid"] = dmarc_data.get("valid", False)

        tags = dmarc_data.get("tags", {})

        # Policy check
        policy = tags.get("p", {}).get("value", "")
        raw["dmarc_policy"] = policy
        if policy == "none":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="DMARC policy is 'none' (monitoring only)",
                    description="DMARC is set to monitoring mode. Consider upgrading to 'quarantine' or 'reject'.",
                )
            )

        # Subdomain policy
        sp = tags.get("sp", {}).get("value", "")
        raw["dmarc_subdomain_policy"] = sp
        if sp == "none" and policy != "none":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="DMARC subdomain policy is 'none'",
                    description="Subdomains have no DMARC enforcement even though the main domain does.",
                )
            )

        # Percentage
        pct = tags.get("pct", {}).get("value", 100)
        if isinstance(pct, int) and pct < 100:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title=f"DMARC applied to only {pct}% of messages",
                    description=f"DMARC pct={pct}. Consider increasing to 100 for full coverage.",
                    details={"pct": pct},
                )
            )

        # Reporting
        rua = tags.get("rua", {}).get("value", [])
        raw["dmarc_rua"] = [r.get("address", "") for r in rua] if isinstance(rua, list) else []

        for warning in dmarc_data.get("warnings", []):
            findings.append(Finding(severity=Severity.LOW, title="DMARC warning", description=str(warning)))
    else:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="No DMARC record",
                description="No DMARC record found. Email authentication is not enforced.",
            )
        )


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    domain = _strip_port(target)

    try:
        data = await asyncio.to_thread(_run_checkdmarc, domain, timeout)
    except Exception as exc:
        return CheckResult(check=CheckType.DNS_DEEP, error=f"DNS deep scan failed for {domain}: {exc}")

    findings: list[Finding] = []
    raw: dict = {}

    _analyze_results(data, findings, raw)

    return CheckResult(check=CheckType.DNS_DEEP, findings=findings, raw=raw)
