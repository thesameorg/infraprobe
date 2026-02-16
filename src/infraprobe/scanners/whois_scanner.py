from __future__ import annotations

from datetime import UTC, datetime

import asyncwhois

from infraprobe.models import CheckResult, CheckType, Finding, Severity
from infraprobe.target import parse_target


def _days_until(dt: datetime) -> int:
    """Return days from now until *dt*, handling naive datetimes as UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (dt - datetime.now(UTC)).days


def _domain_age_days(created: datetime) -> int:
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return (datetime.now(UTC) - created).days


def _analyze(parsed: dict) -> list[Finding]:
    findings: list[Finding] = []

    # --- Registrar ---
    registrar = parsed.get("registrar")
    if registrar:
        findings.append(
            Finding(severity=Severity.INFO, title="Registrar identified", description=f"Registrar: {registrar}")
        )

    # --- Creation date / domain age ---
    created = parsed.get("created")
    if isinstance(created, datetime):
        age = _domain_age_days(created)
        if age < 30:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="Very new domain",
                    description=(
                        f"Domain was registered {age} day(s) ago. "
                        "Newly registered domains are a common phishing indicator."
                    ),
                    details={"created": str(created), "age_days": age},
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Domain age",
                    description=f"Domain registered {age} day(s) ago.",
                    details={"created": str(created), "age_days": age},
                )
            )

    # --- Expiration ---
    expires = parsed.get("expires")
    if isinstance(expires, datetime):
        days_left = _days_until(expires)
        if days_left < 0:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Domain expired",
                    description=f"Domain expiration date has passed ({expires.date()}). Risk of domain takeover.",
                    details={"expires": str(expires), "days_left": days_left},
                )
            )
        elif days_left < 30:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Domain expires soon",
                    description=(
                        f"Domain expires in {days_left} day(s) ({expires.date()}). Risk of lapse and hijacking."
                    ),
                    details={"expires": str(expires), "days_left": days_left},
                )
            )
        elif days_left < 90:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="Domain expiring within 90 days",
                    description=f"Domain expires in {days_left} day(s) ({expires.date()}). Consider renewing.",
                    details={"expires": str(expires), "days_left": days_left},
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Domain expiration",
                    description=f"Domain expires in {days_left} day(s) ({expires.date()}).",
                    details={"expires": str(expires), "days_left": days_left},
                )
            )
    else:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="Expiration date unavailable",
                description="WHOIS response did not include a parseable expiration date.",
            )
        )

    # --- DNSSEC ---
    dnssec = parsed.get("dnssec")
    if dnssec and str(dnssec).lower() not in ("unsigned", "none", ""):
        findings.append(Finding(severity=Severity.INFO, title="DNSSEC enabled", description=f"DNSSEC status: {dnssec}"))
    elif dnssec:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="DNSSEC not enabled",
                description="Domain does not use DNSSEC. DNS responses can be spoofed.",
            )
        )

    return findings


def _build_raw(domain: str, parsed: dict) -> dict:
    raw: dict = {"domain": domain}
    for key in ("registrar", "registrar_url", "created", "updated", "expires", "dnssec", "status", "name_servers"):
        val = parsed.get(key)
        if val is not None:
            raw[key] = str(val) if isinstance(val, datetime) else val
    return raw


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    domain = parse_target(target).host

    try:
        _query_string, parsed = await asyncwhois.aio_whois(
            domain,
            find_authoritative_server=False,
            timeout=timeout,
        )
    except Exception as exc:
        return CheckResult(check=CheckType.WHOIS, error=f"WHOIS lookup failed for {domain}: {exc}")

    if not parsed or all(v is None for v in parsed.values()):
        return CheckResult(check=CheckType.WHOIS, error=f"WHOIS returned no data for {domain}")

    findings = _analyze(parsed)
    raw = _build_raw(domain, parsed)

    return CheckResult(check=CheckType.WHOIS, findings=findings, raw=raw)
