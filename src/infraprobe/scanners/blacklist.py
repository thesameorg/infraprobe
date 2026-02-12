import asyncio
import socket

import dns.asyncresolver
import dns.exception
import dns.resolver

from infraprobe.models import CheckResult, CheckType, Finding, Severity

# DNSBL zones with severity: (zone, severity, description)
_DNSBLS: list[tuple[str, Severity, str]] = [
    # Major lists — HIGH severity if listed
    ("zen.spamhaus.org", Severity.HIGH, "Spamhaus ZEN (combined SBL/XBL/PBL)"),
    ("b.barracudacentral.org", Severity.HIGH, "Barracuda Reputation Block List"),
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


def _reverse_ip(ip: str) -> str:
    """Reverse IPv4 octets for DNSBL lookup (e.g. 1.2.3.4 -> 4.3.2.1)."""
    return ".".join(reversed(ip.split(".")))


def _resolve_target_ip(target: str) -> str:
    """Resolve target to an IPv4 address synchronously (for initial resolution)."""
    # Strip port if present
    host = target
    if host.startswith("["):
        bracket_end = host.find("]")
        host = host[1:bracket_end]
    elif ":" in host:
        parts = host.rsplit(":", 1)
        try:
            int(parts[1])
            host = parts[0]
        except ValueError:
            pass

    # Try to parse as IP first
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    # Resolve hostname to IP
    info = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    if not info:
        raise ValueError(f"Cannot resolve {host} to IPv4")
    return str(info[0][4][0])


async def _check_dnsbl(
    resolver: dns.asyncresolver.Resolver,
    reversed_ip: str,
    zone: str,
) -> bool:
    """Query a single DNSBL. Returns True if IP is listed (A record exists)."""
    query_name = f"{reversed_ip}.{zone}"
    try:
        await resolver.resolve(query_name, "A")
        return True  # Got a response = listed
    except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer, dns.resolver.NoNameservers):
        return False  # Not listed
    except dns.exception.DNSException:
        return False  # Query failed — treat as not listed


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    try:
        ip = _resolve_target_ip(target)
    except Exception as exc:
        return CheckResult(check=CheckType.BLACKLIST, error=f"Cannot resolve {target} to IPv4: {exc}")

    reversed_ip = _reverse_ip(ip)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    # Fan out all DNSBL queries in parallel
    tasks = [_check_dnsbl(resolver, reversed_ip, zone) for zone, _, _ in _DNSBLS]
    try:
        results = await asyncio.gather(*tasks)
    except Exception as exc:
        return CheckResult(check=CheckType.BLACKLIST, error=f"DNSBL lookup failed: {exc}")

    findings: list[Finding] = []
    listings: dict[str, str] = {}

    for (zone, severity, description), listed in zip(_DNSBLS, results, strict=True):
        status = "listed" if listed else "clean"
        listings[zone] = status
        if listed:
            findings.append(
                Finding(
                    severity=severity,
                    title=f"Listed on {zone}",
                    description=f"IP {ip} is listed on {description}.",
                    details={"zone": zone, "ip": ip},
                )
            )

    listed_count = sum(1 for v in listings.values() if v == "listed")
    raw = {
        "ip": ip,
        "reversed_ip": reversed_ip,
        "listings": listings,
        "listed_count": listed_count,
        "total_checked": len(_DNSBLS),
    }

    return CheckResult(check=CheckType.BLACKLIST, findings=findings, raw=raw)
