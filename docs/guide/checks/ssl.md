# SSL/TLS Check

Analyzes SSL/TLS certificate validity and protocol configuration.

- **Check type:** `ssl` (light), `ssl_deep` (deep)
- **Endpoint:** `POST /v1/check/ssl` or `POST /v1/check/ssl_deep`
- **Default:** Yes (all targets)
- **Port:** 443 (default)

## What Is Checked

### Light scan

- Certificate expiry status and remaining days
- Self-signed certificates
- RSA key strength (flags keys under 2048 bits)
- Hostname mismatch against certificate SAN/CN
- Weak ciphers (RC4, DES, 3DES, EXPORT, NULL, anonymous)
- TLS protocol version

### Deep scan

Uses SSLyze for a comprehensive analysis. Includes everything from the light scan plus:

- Full certificate chain validation and trust verification
- TLS 1.2 and 1.3 cipher suite enumeration
- Heartbleed vulnerability (CVE-2014-0160)
- OpenSSL CCS Injection (CVE-2014-0224)
- TLS Compression / CRIME attack
- SHA-1 signatures in certificate chain
- Legacy Symantec certificate authority detection
- Extended Validation (EV) certificate detection

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| critical | Certificate expired, Heartbleed vulnerable |
| high | Certificate expires within 30 days, weak RSA key (<2048 bits), hostname mismatch, CCS Injection vulnerable |
| medium | Self-signed certificate, weak ciphers detected, TLS Compression enabled, SHA-1 in chain |
| info | Valid certificate (with days remaining), TLS 1.3 supported, strong RSA key, EV certificate, no known vulnerabilities |

## Raw Data Fields

### Light scan

| Field | Description |
|-------|-------------|
| `host` | Target hostname |
| `port` | Target port |
| `protocol_version` | Negotiated TLS version (e.g., TLSv1.3) |
| `cipher` | Negotiated cipher suite |
| `cipher_bits` | Cipher key length |
| `issuer` | Certificate issuer |
| `subject` | Certificate subject |
| `not_valid_before` | Certificate start date |
| `not_valid_after` | Certificate expiry date |
| `days_until_expiry` | Days until certificate expires |
| `serial_number` | Certificate serial number |
| `san` | Subject Alternative Names |
| `key_type` | Key algorithm (RSA, EC, etc.) |
| `key_bits` | Key size in bits |

### Deep scan

Includes all light scan fields plus:

| Field | Description |
|-------|-------------|
| `chain_length` | Number of certificates in the chain |
| `hostname_matches` | Whether the certificate matches the hostname |
| `is_ev` | Whether the certificate is Extended Validation |
| `supported_protocols` | List of supported TLS protocol versions |
| `accepted_ciphers_tls12_13` | Accepted cipher suites for TLS 1.2 and 1.3 |
| `vulnerabilities` | Results for Heartbleed, CCS Injection, TLS Compression |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
