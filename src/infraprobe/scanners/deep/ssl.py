"""SSL/TLS scanner powered by SSLyze.

Full protocol enumeration, cipher suite analysis, vulnerability scanning
(Heartbleed, ROBOT, CCS injection, TLS compression), and certificate validation.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanResult,
)

from infraprobe.models import CheckResult, CheckType, Finding, Severity

# ---------------------------------------------------------------------------
# Scan configuration
# ---------------------------------------------------------------------------

# Core commands that complete in ~1s
_SCAN_COMMANDS: set[ScanCommand] = {
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.HEARTBLEED,
    ScanCommand.OPENSSL_CCS_INJECTION,
    ScanCommand.TLS_COMPRESSION,
}

_WEAK_CIPHER_FRAGMENTS = ("RC4", "DES", "3DES", "EXPORT", "NULL", "anon")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_target(target: str) -> tuple[str, int]:
    """Extract host and port from target string. Default port is 443."""
    if target.startswith("["):
        bracket_end = target.find("]")
        host = target[1:bracket_end]
        rest = target[bracket_end + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, 443

    if target.count(":") == 1:
        host, port_str = target.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            pass

    return target, 443


def _run_sslyze(host: str, port: int) -> ServerScanResult:
    """Run SSLyze scan synchronously (called via asyncio.to_thread)."""
    scanner = Scanner()
    request = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=host, port=port),
        scan_commands=_SCAN_COMMANDS,
    )
    scanner.queue_scans([request])
    for result in scanner.get_results():
        return result
    msg = f"SSLyze returned no results for {host}:{port}"
    raise RuntimeError(msg)


def _hostname_matches(host: str, names: list[str]) -> bool:
    """Check if host matches any of the given DNS names (supports wildcard)."""
    host_lower = host.lower()
    for name in names:
        name_lower = name.lower()
        if name_lower == host_lower:
            return True
        if name_lower.startswith("*."):
            suffix = name_lower[2:]
            if host_lower.endswith(suffix) and host_lower.count(".") == name_lower.count("."):
                return True
    return False


def _get_result(attempt: Any) -> Any:
    """Extract result from a ScanCommandAttempt if completed."""
    if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
        return attempt.result
    return None


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------


def _check_certificate(scan_result: Any, host: str, findings: list[Finding], raw: dict) -> None:
    """Analyze certificate info from SSLyze results."""
    attempt = scan_result.certificate_info
    result = _get_result(attempt)
    if result is None:
        return

    if not result.certificate_deployments:
        return

    deployment = result.certificate_deployments[0]
    chain = deployment.received_certificate_chain
    if not chain:
        return

    leaf: x509.Certificate = chain[0]
    now = datetime.now(UTC)

    # --- Expiry ---
    not_after = leaf.not_valid_after_utc
    if not_after < now:
        days_expired = (now - not_after).days
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                title="Certificate expired",
                description=f"Certificate expired {days_expired} day(s) ago on {not_after.isoformat()}.",
                details={"not_valid_after": not_after.isoformat(), "days_expired": days_expired},
            )
        )
    else:
        days_left = (not_after - now).days
        if days_left <= 30:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Certificate expires soon",
                    description=f"Certificate expires in {days_left} day(s) on {not_after.isoformat()}.",
                    details={"not_valid_after": not_after.isoformat(), "days_until_expiry": days_left},
                )
            )

    # --- Self-signed ---
    if leaf.issuer == leaf.subject:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Self-signed certificate",
                description="The certificate issuer matches the subject, indicating a self-signed certificate.",
            )
        )

    # --- Weak RSA key ---
    pub_key = leaf.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey) and pub_key.key_size < 2048:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Weak RSA key",
                description=f"RSA key is {pub_key.key_size} bits, minimum recommended is 2048.",
                details={"key_bits": pub_key.key_size},
            )
        )

    # --- Hostname mismatch ---
    try:
        san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_names = []
    hostname_matches = _hostname_matches(host, san_names) if san_names else False
    if not hostname_matches:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Hostname mismatch",
                description=f"Certificate does not match target hostname '{host}'.",
                details={"host": host, "san": san_names},
            )
        )

    # --- Chain validation (check all trust stores) ---
    untrusted = all(r.validation_error is not None for r in deployment.path_validation_results)
    if deployment.path_validation_results and untrusted:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Certificate chain not trusted",
                description="Certificate chain could not be validated against any trust store.",
            )
        )

    # --- SHA-1 in chain ---
    if deployment.verified_chain_has_sha1_signature:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Certificate chain uses SHA-1 signature",
                description="SHA-1 signatures are deprecated and considered insecure.",
            )
        )

    # --- Legacy Symantec ---
    if deployment.verified_chain_has_legacy_symantec_anchor:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Certificate chain has legacy Symantec anchor",
                description="Legacy Symantec certificates are distrusted by major browsers.",
            )
        )

    # --- Raw cert data ---
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pub_key.key_size
    else:
        key_type, key_bits = type(pub_key).__name__, 0

    days_until_expiry = (not_after - now).days if not_after > now else 0
    raw.update(
        {
            "issuer": leaf.issuer.rfc4514_string(),
            "subject": leaf.subject.rfc4514_string(),
            "not_valid_before": leaf.not_valid_before_utc.isoformat(),
            "not_valid_after": not_after.isoformat(),
            "days_until_expiry": days_until_expiry,
            "serial_number": str(leaf.serial_number),
            "san": san_names,
            "key_type": key_type,
            "key_bits": key_bits,
            "chain_length": len(chain),
            "hostname_matches": hostname_matches,
            "is_ev": deployment.leaf_certificate_is_ev,
        }
    )


def _check_protocols(scan_result: Any, findings: list[Finding], raw: dict) -> None:
    """Check TLS 1.2/1.3 cipher suites for weak ciphers."""
    supported_protocols: list[str] = []
    all_accepted: list[str] = []

    for attr_name, proto_name in [
        ("tls_1_2_cipher_suites", "TLS 1.2"),
        ("tls_1_3_cipher_suites", "TLS 1.3"),
    ]:
        attempt = getattr(scan_result, attr_name)
        result: Any = _get_result(attempt)
        if result is None:
            continue
        if result.accepted_cipher_suites:
            supported_protocols.append(proto_name)
            cipher_names = [c.cipher_suite.name for c in result.accepted_cipher_suites]
            all_accepted.extend(cipher_names)

            # Check for weak ciphers in accepted suites
            for cipher_accepted in result.accepted_cipher_suites:
                name = cipher_accepted.cipher_suite.name
                for fragment in _WEAK_CIPHER_FRAGMENTS:
                    if fragment in name.upper():
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                title=f"Weak cipher accepted: {name}",
                                description=f"Server accepts weak cipher '{name}' via {proto_name}.",
                                details={"cipher": name, "protocol": proto_name, "matched": fragment},
                            )
                        )
                        break

    # No TLS 1.2 or 1.3 support
    if not supported_protocols:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="No modern TLS protocol supported",
                description="Server does not support TLS 1.2 or TLS 1.3.",
            )
        )

    raw["supported_protocols"] = supported_protocols
    raw["accepted_ciphers_tls12_13"] = all_accepted


def _check_vulnerabilities(scan_result: Any, findings: list[Finding], raw: dict) -> None:
    """Check for known TLS vulnerabilities."""
    vulns: dict[str, bool | str] = {}

    # Heartbleed
    hb = _get_result(scan_result.heartbleed)
    if hb is not None:
        vulns["heartbleed"] = hb.is_vulnerable_to_heartbleed
        if hb.is_vulnerable_to_heartbleed:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title="Vulnerable to Heartbleed (CVE-2014-0160)",
                    description="Server is vulnerable to the Heartbleed bug, allowing memory disclosure.",
                )
            )

    # CCS Injection
    ccs = _get_result(scan_result.openssl_ccs_injection)
    if ccs is not None:
        vulns["ccs_injection"] = ccs.is_vulnerable_to_ccs_injection
        if ccs.is_vulnerable_to_ccs_injection:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Vulnerable to OpenSSL CCS Injection (CVE-2014-0224)",
                    description="Server is vulnerable to CCS injection, allowing man-in-the-middle attacks.",
                )
            )

    # TLS Compression (CRIME attack)
    comp = _get_result(scan_result.tls_compression)
    if comp is not None:
        vulns["tls_compression"] = comp.supports_compression
        if comp.supports_compression:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="TLS compression enabled (CRIME attack)",
                    description="TLS compression is enabled, making the server vulnerable to the CRIME attack.",
                )
            )

    raw["vulnerabilities"] = vulns


def _add_positive_findings(findings: list[Finding], raw: dict) -> None:
    """Add INFO-level findings for things that are configured correctly."""
    # Valid certificate with plenty of time
    days = raw.get("days_until_expiry", 0)
    if days > 30:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"Valid certificate ({days} days until expiry)",
                description=f"Certificate is valid and expires on {raw.get('not_valid_after', 'unknown')}.",
            )
        )

    # Strong key
    key_type = raw.get("key_type", "")
    key_bits = raw.get("key_bits", 0)
    if key_type == "RSA" and key_bits >= 2048:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"Strong RSA key ({key_bits}-bit)",
                description="RSA key meets the recommended minimum of 2048 bits.",
            )
        )
    elif key_type == "EC":
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"EC key ({key_bits}-bit)",
                description="Elliptic curve key provides strong security with smaller key size.",
            )
        )

    # TLS 1.3 support
    protocols = raw.get("supported_protocols", [])
    if "TLS 1.3" in protocols:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="TLS 1.3 supported",
                description="Server supports TLS 1.3, the latest and most secure protocol version.",
            )
        )

    # No known vulnerabilities
    vulns = raw.get("vulnerabilities", {})
    if vulns and not any(v is True for v in vulns.values() if isinstance(v, bool)):
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="No known TLS vulnerabilities",
                description="Server is not vulnerable to Heartbleed, CCS injection, or TLS compression attacks.",
            )
        )

    # Hostname matches
    if raw.get("hostname_matches"):
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="Certificate matches hostname",
                description="The certificate's SAN entries match the target hostname.",
            )
        )

    # EV certificate
    if raw.get("is_ev"):
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="Extended Validation (EV) certificate",
                description="The certificate is an EV certificate, providing the highest level of identity assurance.",
            )
        )


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    host, port = _parse_target(target)

    try:
        result = await asyncio.to_thread(_run_sslyze, host, port)
    except Exception as exc:
        error_msg = str(exc) or type(exc).__name__
        return CheckResult(check=CheckType.SSL_DEEP, error=f"SSL scan failed for {host}:{port}: {error_msg}")

    # Check connectivity
    if result.connectivity_error_trace is not None:
        return CheckResult(
            check=CheckType.SSL_DEEP,
            error=f"Cannot establish TLS connection to {host}:{port}",
        )

    if result.scan_result is None:
        return CheckResult(check=CheckType.SSL_DEEP, error=f"No scan result for {host}:{port}")

    findings: list[Finding] = []
    raw: dict = {"host": host, "port": port}
    sr = result.scan_result

    _check_certificate(sr, host, findings, raw)
    _check_protocols(sr, findings, raw)
    _check_vulnerabilities(sr, findings, raw)

    # --- Positive findings ---
    _add_positive_findings(findings, raw)

    return CheckResult(check=CheckType.SSL_DEEP, findings=findings, raw=raw)
