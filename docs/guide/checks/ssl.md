# SSL/TLS Check

Analyzes SSL/TLS certificate validity and protocol configuration.

- **Check type:** `ssl`
- **Included in:** `POST /v1/scan`
- **Targets:** All
- **Port:** 443 (default)

## What Is Checked

- Certificate expiry status and remaining days
- Self-signed certificates
- RSA key strength (flags keys under 2048 bits)
- Hostname mismatch against certificate SAN/CN
- Weak ciphers (RC4, DES, 3DES, EXPORT, NULL, anonymous)
- TLS protocol version

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| critical | Certificate expired |
| high | Certificate expires within 30 days, weak RSA key (<2048 bits), hostname mismatch |
| medium | Self-signed certificate, weak ciphers detected |
| info | Valid certificate (with days remaining), TLS 1.3 supported, strong RSA key |

## Raw Data Fields

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

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
