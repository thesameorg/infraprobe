import asyncio

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from infraprobe.models import CheckResult, CheckType, Finding, Severity
from infraprobe.target import parse_target

# Record types to query — order doesn't matter, all run in parallel
_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]


async def _resolve(domain: str, rdtype: str, timeout: float) -> list[str]:
    """Resolve a single record type, returning list of string representations.

    Each call creates its own Resolver with an independent lifetime budget,
    so one slow query (e.g. large TXT) cannot exhaust the budget for others.
    """
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = timeout
        answer = await resolver.resolve(domain, rdtype, raise_on_no_answer=False)
        return [rdata.to_text() for rdata in answer]
    except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


def _check_spf(txt_records: list[str]) -> tuple[str | None, list[Finding]]:
    """Analyze TXT records for SPF policy. Returns (spf_record, findings)."""
    findings: list[Finding] = []
    spf_record = None

    for txt in txt_records:
        # TXT records come quoted from dnspython, strip quotes
        clean = txt.strip('"')
        if clean.lower().startswith("v=spf1"):
            spf_record = clean
            break

    if spf_record is None:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="No SPF record",
                description="No SPF (TXT v=spf1) record found. Without SPF, anyone can send email as this domain.",
            )
        )
    else:
        findings.append(
            Finding(severity=Severity.INFO, title="SPF record present", description="SPF record is configured.")
        )
        lower = spf_record.lower()
        if "+all" in lower:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="SPF allows all senders (+all)",
                    description="SPF record uses '+all', which permits any server to send email as this domain.",
                    details={"spf": spf_record},
                )
            )
        elif "~all" not in lower and "-all" not in lower and "?all" not in lower:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="SPF record has no restrictive 'all' mechanism",
                    description="SPF record does not end with -all, ~all, or ?all. Senders are not restricted.",
                    details={"spf": spf_record},
                )
            )

    return spf_record, findings


def _check_dmarc(txt_records: list[str]) -> tuple[str | None, list[Finding]]:
    """Analyze TXT records from _dmarc subdomain. Returns (dmarc_record, findings)."""
    findings: list[Finding] = []
    dmarc_record = None

    for txt in txt_records:
        clean = txt.strip('"')
        if clean.lower().startswith("v=dmarc1"):
            dmarc_record = clean
            break

    if dmarc_record is None:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="No DMARC record",
                description="No DMARC record found at _dmarc subdomain. "
                "Without DMARC, receiving servers cannot verify email authentication.",
            )
        )
    else:
        findings.append(
            Finding(severity=Severity.INFO, title="DMARC record present", description="DMARC record is configured.")
        )
        lower = dmarc_record.lower()
        if "p=none" in lower:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="DMARC policy set to none",
                    description="DMARC policy is 'none' (monitoring only). "
                    "Failed authentication does not result in rejection.",
                    details={"dmarc": dmarc_record},
                )
            )

    return dmarc_record, findings


def _check_caa(caa_records: list[str]) -> list[Finding]:
    """Check for CAA records."""
    if not caa_records:
        return [
            Finding(
                severity=Severity.LOW,
                title="No CAA records",
                description="No CAA records found. Any certificate authority can issue certificates for this domain.",
            )
        ]
    return [
        Finding(
            severity=Severity.INFO,
            title="CAA records present",
            description=f"CAA records restrict certificate issuance ({len(caa_records)} record(s)).",
        )
    ]


async def scan(target: str, timeout: float = 10.0, auth=None) -> CheckResult:
    domain = parse_target(target).host

    try:
        # Resolve all standard record types in parallel — each _resolve() call
        # creates its own Resolver with an independent lifetime budget.
        tasks = {rdtype: _resolve(domain, rdtype, timeout) for rdtype in _RECORD_TYPES}
        results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values()), strict=True))

        # Also resolve _dmarc subdomain
        dmarc_txt = await _resolve(f"_dmarc.{domain}", "TXT", timeout)

    except Exception as exc:
        return CheckResult(check=CheckType.DNS, error=f"DNS resolution failed for {domain}: {exc}")

    findings: list[Finding] = []

    # SPF analysis (from TXT records of main domain)
    spf_record, spf_findings = _check_spf(results.get("TXT", []))
    findings.extend(spf_findings)

    # DMARC analysis (from _dmarc subdomain TXT records)
    dmarc_record, dmarc_findings = _check_dmarc(dmarc_txt)
    findings.extend(dmarc_findings)

    # CAA analysis
    findings.extend(_check_caa(results.get("CAA", [])))

    # Build raw data — all resolved records
    raw: dict = {"domain": domain}
    for rdtype in _RECORD_TYPES:
        raw[rdtype.lower()] = results.get(rdtype, [])
    raw["dmarc_txt"] = dmarc_txt
    if spf_record:
        raw["spf"] = spf_record
    if dmarc_record:
        raw["dmarc"] = dmarc_record

    return CheckResult(check=CheckType.DNS, findings=findings, raw=raw)
