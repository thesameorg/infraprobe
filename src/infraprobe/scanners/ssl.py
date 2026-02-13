import asyncio
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from infraprobe.models import CheckResult, CheckType, Finding, Severity
from infraprobe.target import parse_target

# Ciphers considered weak — match by substring in the cipher name
_WEAK_CIPHER_FRAGMENTS = ("RC4", "DES", "3DES", "EXPORT", "NULL", "anon")


async def _connect_tls(host: str, port: int, timeout: float) -> tuple[bytes, str, tuple[str, str, int]]:
    """Connect with TLS and return (der_cert, protocol_version, cipher_info).

    cipher_info is the tuple from ssl.SSLSocket.cipher(): (name, version, bits).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    connect_timeout = min(3.0, timeout)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx),
        timeout=connect_timeout,
    )

    try:
        ssl_object = writer.transport.get_extra_info("ssl_object")
        der_cert = ssl_object.getpeercert(binary_form=True)
        protocol_version = ssl_object.version()
        cipher_info = ssl_object.cipher()
        return der_cert, protocol_version, cipher_info
    finally:
        writer.close()
        await writer.wait_closed()


def _check_certificate(cert: x509.Certificate, host: str) -> list[Finding]:
    """Analyze certificate for security issues."""
    findings: list[Finding] = []
    now = datetime.now(UTC)

    # Expiry
    not_after = cert.not_valid_after_utc
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

    # Self-signed (issuer == subject)
    if cert.issuer == cert.subject:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Self-signed certificate",
                description="The certificate issuer matches the subject, indicating a self-signed certificate.",
            )
        )

    # Weak RSA key
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey) and pub_key.key_size < 2048:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Weak RSA key",
                description=f"RSA key is {pub_key.key_size} bits, minimum recommended is 2048.",
                details={"key_bits": pub_key.key_size},
            )
        )

    # SAN and hostname check
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_names = []
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="No SAN extension",
                description="Certificate has no Subject Alternative Name extension. Modern browsers require SAN.",
            )
        )

    # Hostname mismatch — check SANs first, fall back to CN
    if san_names:
        if not _hostname_matches(host, san_names):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Hostname mismatch",
                    description=f"Target '{host}' does not match any SAN: {san_names}.",
                    details={"host": host, "san": san_names},
                )
            )
    else:
        # No SAN — check CN as fallback
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        cn_value = cn_attrs[0].value if cn_attrs else None
        cn = cn_value if isinstance(cn_value, str) else None
        if cn and not _hostname_matches(host, [cn]):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Hostname mismatch",
                    description=f"Target '{host}' does not match certificate CN '{cn}'.",
                    details={"host": host, "cn": cn},
                )
            )

    return findings


def _hostname_matches(host: str, names: list[str]) -> bool:
    """Check if host matches any of the given DNS names (supports wildcard)."""
    host_lower = host.lower()
    for name in names:
        name_lower = name.lower()
        if name_lower == host_lower:
            return True
        # Wildcard: *.example.com matches sub.example.com but not example.com
        if name_lower.startswith("*."):
            suffix = name_lower[2:]
            if host_lower.endswith(suffix) and host_lower.count(".") == name_lower.count("."):
                return True
    return False


def _check_cipher(cipher_info: tuple[str, str, int]) -> list[Finding]:
    """Check if the negotiated cipher is weak."""
    cipher_name = cipher_info[0]
    for fragment in _WEAK_CIPHER_FRAGMENTS:
        if fragment in cipher_name.upper():
            return [
                Finding(
                    severity=Severity.MEDIUM,
                    title="Weak cipher negotiated",
                    description=f"Negotiated cipher '{cipher_name}' is considered weak.",
                    details={"cipher": cipher_name, "matched": fragment},
                )
            ]
    return []


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    host, port = parse_target(target)
    port = port or 443

    try:
        der_cert, protocol_version, cipher_info = await _connect_tls(host, port, timeout)
    except ssl.SSLError as exc:
        return CheckResult(check=CheckType.SSL, error=f"TLS error connecting to {host}:{port}: {exc}")
    except OSError as exc:
        msg = str(exc) or type(exc).__name__
        return CheckResult(check=CheckType.SSL, error=f"Cannot connect to {host}:{port}: {msg}")
    except TimeoutError:
        return CheckResult(check=CheckType.SSL, error=f"Connection to {host}:{port} timed out")

    cert = x509.load_der_x509_certificate(der_cert)
    findings: list[Finding] = []

    findings.extend(_check_certificate(cert, host))
    findings.extend(_check_cipher(cipher_info))

    # --- Positive findings ---
    now_check = datetime.now(UTC)
    not_after_check = cert.not_valid_after_utc
    if not_after_check > now_check:
        days_left = (not_after_check - now_check).days
        if days_left > 30:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"Valid certificate ({days_left} days until expiry)",
                    description=f"Certificate is valid and expires on {not_after_check.date().isoformat()}.",
                )
            )
    if protocol_version and "TLSv1.3" in protocol_version:
        findings.append(
            Finding(severity=Severity.INFO, title="TLS 1.3 negotiated", description="The server negotiated TLS 1.3.")
        )
    pub_key_check = cert.public_key()
    if isinstance(pub_key_check, rsa.RSAPublicKey) and pub_key_check.key_size >= 2048:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"Strong RSA key ({pub_key_check.key_size}-bit)",
                description="RSA key meets the recommended minimum of 2048 bits.",
            )
        )
    elif isinstance(pub_key_check, ec.EllipticCurvePublicKey):
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"EC key ({pub_key_check.key_size}-bit)",
                description="Elliptic curve key provides strong security with smaller key size.",
            )
        )

    # Build raw data
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_bits = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type = "EC"
        key_bits = pub_key.key_size
    else:
        key_type = type(pub_key).__name__
        key_bits = 0

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_list = []

    now = datetime.now(UTC)
    not_after = cert.not_valid_after_utc
    days_until_expiry = (not_after - now).days if not_after > now else 0

    raw = {
        "host": host,
        "port": port,
        "protocol_version": protocol_version or "unknown",
        "cipher": cipher_info[0],
        "cipher_bits": cipher_info[2],
        "issuer": cert.issuer.rfc4514_string(),
        "subject": cert.subject.rfc4514_string(),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "serial_number": str(cert.serial_number),
        "san": san_list,
        "key_type": key_type,
        "key_bits": key_bits,
    }

    return CheckResult(check=CheckType.SSL, findings=findings, raw=raw)
