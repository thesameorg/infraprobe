# WHOIS Check

Retrieves domain registration information including registrar, creation date, expiration date, and DNSSEC status.

- **Check type:** `whois`
- **Endpoint:** `POST /v1/check/whois`
- **Default:** Yes (domains only)
- **Deep variant:** None
- **Not available for IP targets**

## What Is Checked

- Domain registration age
- Domain expiration date and days remaining
- DNSSEC configuration
- Registrar information

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| high | Domain expired, domain expires within 30 days |
| medium | Domain registered less than 30 days ago (potential phishing indicator), domain expires within 90 days |
| low | DNSSEC not enabled |
| info | Domain age, expiration date, DNSSEC enabled, registrar name |

A recently registered domain can be a phishing indicator, while an expiring domain may cause service disruption. DNSSEC protects against DNS spoofing attacks.

## Raw Data Fields

| Field | Description |
|-------|-------------|
| `domain` | Queried domain |
| `registrar` | Domain registrar name |
| `registrar_url` | Registrar website |
| `created` | Domain creation date |
| `updated` | Last update date |
| `expires` | Domain expiration date |
| `dnssec` | DNSSEC status |
| `status` | Domain status codes |
| `name_servers` | Authoritative nameservers |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
