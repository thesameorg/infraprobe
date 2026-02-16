"""Port scanner powered by python-nmap — light (top-20) and deep (top-1000 + version detection)."""

from __future__ import annotations

import asyncio
from typing import Any

import nmap

from infraprobe.blocklist import BlockedTargetError, InvalidTargetError, validate_target
from infraprobe.models import CheckResult, CheckType, Finding, Severity
from infraprobe.target import parse_target

# ---------------------------------------------------------------------------
# Port risk classification
# ---------------------------------------------------------------------------

_CRITICAL_PORTS: frozenset[int] = frozenset(
    {
        23,  # Telnet
        2049,  # NFS
        5984,  # CouchDB
        6379,  # Redis
        9200,  # Elasticsearch HTTP
        9300,  # Elasticsearch transport
        11211,  # Memcached
        27017,  # MongoDB
    }
)

_HIGH_PORTS: frozenset[int] = frozenset(
    {
        21,  # FTP
        139,  # NetBIOS
        445,  # SMB
        512,  # rexec
        513,  # rlogin
        514,  # rsh
        1099,  # Java RMI
        1433,  # MSSQL
        1521,  # Oracle DB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
    }
)

_MEDIUM_PORTS: frozenset[int] = frozenset(
    {
        25,  # SMTP
        110,  # POP3
        143,  # IMAP
        161,  # SNMP
        162,  # SNMP trap
        389,  # LDAP
        636,  # LDAPS
        1883,  # MQTT
    }
)

_INFO_PORTS: frozenset[int] = frozenset(
    {
        22,  # SSH
        53,  # DNS
        80,  # HTTP
        443,  # HTTPS
    }
)

# Service name heuristics for non-standard ports
_SERVICE_HINTS: dict[str, Severity] = {
    "telnet": Severity.CRITICAL,
    "redis": Severity.CRITICAL,
    "mongodb": Severity.CRITICAL,
    "mongod": Severity.CRITICAL,
    "memcached": Severity.CRITICAL,
    "memcache": Severity.CRITICAL,
    "elasticsearch": Severity.CRITICAL,
    "couchdb": Severity.CRITICAL,
    "nfs": Severity.CRITICAL,
    "ftp": Severity.HIGH,
    "smb": Severity.HIGH,
    "microsoft-ds": Severity.HIGH,
    "netbios-ssn": Severity.HIGH,
    "ms-sql-s": Severity.HIGH,
    "mysql": Severity.HIGH,
    "postgresql": Severity.HIGH,
    "oracle": Severity.HIGH,
    "vnc": Severity.HIGH,
    "ms-wbt-server": Severity.HIGH,
    "java-rmi": Severity.HIGH,
    "smtp": Severity.MEDIUM,
    "pop3": Severity.MEDIUM,
    "imap": Severity.MEDIUM,
    "snmp": Severity.MEDIUM,
    "ldap": Severity.MEDIUM,
    "ldaps": Severity.MEDIUM,
    "mqtt": Severity.MEDIUM,
    "ssh": Severity.INFO,
    "http": Severity.INFO,
    "https": Severity.INFO,
    "http-alt": Severity.INFO,
    "https-alt": Severity.INFO,
    "domain": Severity.INFO,
}


def _classify_port(port: int, service: str) -> Severity:
    """Determine severity for an open port based on port number and service name."""
    if port in _CRITICAL_PORTS:
        return Severity.CRITICAL
    if port in _HIGH_PORTS:
        return Severity.HIGH
    if port in _MEDIUM_PORTS:
        return Severity.MEDIUM
    if port in _INFO_PORTS:
        return Severity.INFO

    # Fallback: check service name hints
    svc_lower = service.lower()
    for hint, severity in _SERVICE_HINTS.items():
        if hint in svc_lower:
            return severity

    return Severity.LOW


def _port_description(port: int, service: str, product: str, version: str) -> str:
    """Build a human-readable description for an open port finding."""
    parts = [f"Port {port}/{service} is open"]
    if product:
        detail = product
        if version:
            detail += f" {version}"
        parts.append(f"running {detail}")
    return ". ".join(parts) + "."


# ---------------------------------------------------------------------------
# Nmap execution (blocking — runs in thread pool)
# ---------------------------------------------------------------------------


def _run_nmap(host: str, arguments: str) -> dict[str, Any]:
    """Run nmap scan synchronously — called via asyncio.to_thread."""
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments=arguments)

    open_ports: list[dict[str, Any]] = []
    for scanned_host in nm.all_hosts():
        for proto in nm[scanned_host].all_protocols():
            ports = sorted(nm[scanned_host][proto].keys())
            for port in ports:
                info = nm[scanned_host][proto][port]
                if info.get("state") == "open":
                    open_ports.append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": info.get("state", ""),
                            "service": info.get("name", ""),
                            "product": info.get("product", ""),
                            "version": info.get("version", ""),
                        }
                    )

    return {
        "host": host,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "command_line": nm.command_line(),
    }


# ---------------------------------------------------------------------------
# Scanner entrypoints
# ---------------------------------------------------------------------------


async def _run_scan(check_type: CheckType, target: str, timeout: float, deep: bool) -> CheckResult:
    try:
        host = parse_target(target).host

        # Re-validate and use pre-resolved IP for nmap to prevent DNS rebinding
        try:
            ctx = validate_target(target)
            nmap_host = ctx.resolved_ips[0] if ctx.resolved_ips else host
        except (BlockedTargetError, InvalidTargetError) as exc:
            return CheckResult(check=check_type, error=f"Target validation failed: {exc}")

        host_timeout = max(1, int(timeout - 1))
        args = f"-sT -T4 -Pn --host-timeout {host_timeout}s"
        if deep:
            args += " --top-ports 1000 -sV"
        else:
            args += " --top-ports 20"

        raw = await asyncio.to_thread(_run_nmap, nmap_host, args)
        raw["host"] = host  # display original hostname, not resolved IP

        findings: list[Finding] = []
        for p in raw["open_ports"]:
            port = p["port"]
            service = p["service"]
            product = p["product"]
            version = p["version"]
            severity = _classify_port(port, service)

            findings.append(
                Finding(
                    severity=severity,
                    title=f"Port {port}/{service} open",
                    description=_port_description(port, service, product, version),
                    details=p,
                )
            )

        if not findings:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="No open ports found",
                    description=f"No open ports detected among the top {'1000' if deep else '20'} common ports.",
                )
            )

        return CheckResult(check=check_type, findings=findings, raw=raw)

    except Exception as exc:
        return CheckResult(check=check_type, error=f"Port scan failed: {exc}")


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    """Light port scan — top 20 ports, TCP connect, no version detection."""
    return await _run_scan(CheckType.PORTS, target, timeout, deep=False)


async def scan_deep(target: str, timeout: float = 30.0) -> CheckResult:
    """Deep port scan — top 1000 ports, TCP connect, with version detection."""
    return await _run_scan(CheckType.PORTS_DEEP, target, timeout, deep=True)
