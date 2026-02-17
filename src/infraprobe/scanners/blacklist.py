import asyncio
import socket

import dns.asyncresolver
import dns.exception
import dns.resolver

from infraprobe.models import CheckResult, CheckType, Finding, Severity
from infraprobe.target import parse_target

# DNSBL zones with severity: (zone, severity, description)
_DNSBLS_MAJOR: list[tuple[str, Severity, str]] = [
    ("zen.spamhaus.org", Severity.HIGH, "Spamhaus ZEN (combined SBL/XBL/PBL)"),
    ("b.barracudacentral.org", Severity.HIGH, "Barracuda Reputation Block List"),
]

_DNSBLS_ALL: list[tuple[str, Severity, str]] = [
    *_DNSBLS_MAJOR,
    ("bl.spamcop.net", Severity.HIGH, "SpamCop Blocking List"),
    # Mid-tier — MEDIUM severity
    ("dnsbl.sorbs.net", Severity.MEDIUM, "SORBS combined DNSBL"),
    ("dnsbl-1.uceprotect.net", Severity.MEDIUM, "UCEPROTECT Level 1"),
    ("spam.dnsbl.sorbs.net", Severity.MEDIUM, "SORBS spam sources"),
    ("cbl.abuseat.org", Severity.MEDIUM, "Composite Blocking List (CBL)"),
    ("dnsbl.dronebl.org", Severity.MEDIUM, "DroneBL"),
    ("db.wpbl.info", Severity.MEDIUM, "WPBL"),
    ("bl.mailspike.net", Severity.MEDIUM, "Mailspike Blacklist"),
    # Niche — LOW severity
    ("psbl.surriel.com", Severity.LOW, "PSBL (Passive Spam Block List)"),
    ("ubl.unsubscore.com", Severity.LOW, "Unsubscribe Blacklist"),
    ("dyna.spamrats.com", Severity.LOW, "SpamRATS Dynamic"),
    ("noptr.spamrats.com", Severity.LOW, "SpamRATS No-PTR"),
    ("all.s5h.net", Severity.LOW, "s5h.net all"),
]

# Per-zone timeout so one dead DNSBL can't stall the whole scanner
_PER_ZONE_TIMEOUT = 3.0


def _reverse_ip(ip: str) -> str:
    """Reverse IPv4 octets for DNSBL lookup (e.g. 1.2.3.4 -> 4.3.2.1)."""
    return ".".join(reversed(ip.split(".")))


async def _resolve_target_ip(target: str) -> str:
    """Resolve target to an IPv4 address asynchronously."""
    host = parse_target(target).host

    # Try to parse as IP first
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    # Resolve hostname to IP asynchronously
    loop = asyncio.get_running_loop()
    info = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    if not info:
        raise ValueError(f"Cannot resolve {host} to IPv4")
    return str(info[0][4][0])


async def _check_dnsbl(
    resolver: dns.asyncresolver.Resolver,
    reversed_ip: str,
    zone: str,
) -> bool | None:
    """Query a single DNSBL. Returns True if listed, False if clean, None on timeout."""
    query_name = f"{reversed_ip}.{zone}"
    try:
        await asyncio.wait_for(resolver.resolve(query_name, "A"), timeout=_PER_ZONE_TIMEOUT)
        return True  # Got a response = listed
    except TimeoutError:
        return None  # Zone timed out
    except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer, dns.resolver.NoNameservers):
        return False  # Not listed
    except dns.exception.DNSException:
        return False  # Query failed — treat as not listed


async def _run_blacklist(
    check_type: CheckType,
    zones: list[tuple[str, Severity, str]],
    target: str,
    timeout: float,
) -> CheckResult:
    try:
        ip = await _resolve_target_ip(target)
    except Exception as exc:
        return CheckResult(check=check_type, error=f"Cannot resolve {target} to IPv4: {exc}")

    reversed_ip = _reverse_ip(ip)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    # Fan out all DNSBL queries in parallel
    tasks = [_check_dnsbl(resolver, reversed_ip, zone) for zone, _, _ in zones]
    try:
        results = await asyncio.gather(*tasks)
    except Exception as exc:
        return CheckResult(check=check_type, error=f"DNSBL lookup failed: {exc}")

    findings: list[Finding] = []
    listings: dict[str, str] = {}

    for (zone, severity, description), listed in zip(zones, results, strict=True):
        if listed is None:
            listings[zone] = "timeout"
        elif listed:
            listings[zone] = "listed"
            findings.append(
                Finding(
                    severity=severity,
                    title=f"Listed on {zone}",
                    description=f"IP {ip} is listed on {description}.",
                    details={"zone": zone, "ip": ip},
                )
            )
        else:
            listings[zone] = "clean"

    listed_count = sum(1 for v in listings.values() if v == "listed")
    checked_count = sum(1 for v in listings.values() if v != "timeout")

    if listed_count == 0:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"Not listed on any of {checked_count} blacklists",
                description=f"IP {ip} is clean across all checked DNSBL zones.",
            )
        )

    raw = {
        "ip": ip,
        "reversed_ip": reversed_ip,
        "listings": listings,
        "listed_count": listed_count,
        "total_checked": checked_count,
    }

    return CheckResult(check=check_type, findings=findings, raw=raw)


async def scan(target: str, timeout: float = 10.0, auth=None) -> CheckResult:
    """Light blacklist check — 2 major DNSBL sources (fast)."""
    return await _run_blacklist(CheckType.BLACKLIST, _DNSBLS_MAJOR, target, timeout)


async def scan_deep(target: str, timeout: float = 30.0, auth=None) -> CheckResult:
    """Deep blacklist check — all 15 DNSBL sources with per-zone timeout."""
    return await _run_blacklist(CheckType.BLACKLIST_DEEP, _DNSBLS_ALL, target, timeout)
