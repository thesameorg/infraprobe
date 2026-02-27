# DNS Check

Queries DNS records and evaluates email authentication (SPF, DMARC) and certificate authority authorization (CAA).

- **Check type:** `dns`
- **Included in:** `POST /v1/scan`
- **Targets:** Domains only
- **Not available for IP targets**

## What Is Checked

- DNS record resolution: A, AAAA, MX, NS, TXT, CNAME, CAA
- SPF record presence and policy strength
- DMARC record presence and policy
- CAA record presence

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| high | SPF uses `+all` (allows any server to send email) |
| medium | No SPF record found, no DMARC record found, SPF missing restrictive `all` mechanism, DMARC policy `none` not enforcing |
| low | No CAA records, DMARC policy set to `none` |
| info | SPF record present, DMARC record present, CAA records configured |

## Raw Data Fields

| Field | Description |
|-------|-------------|
| `domain` | Queried domain |
| `a` | A records (IPv4) |
| `aaaa` | AAAA records (IPv6) |
| `mx` | MX records |
| `ns` | NS records |
| `txt` | TXT records |
| `cname` | CNAME records |
| `caa` | CAA records |
| `dmarc_txt` | Raw DMARC TXT record |
| `spf` | SPF record content (if found) |
| `dmarc` | DMARC record content (if found) |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
