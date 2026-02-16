# DNS Check

Queries DNS records and evaluates email authentication (SPF, DMARC) and certificate authority authorization (CAA).

- **Check type:** `dns` (light), `dns_deep` (deep)
- **Endpoint:** `POST /v1/check/dns` or `POST /v1/check_deep/dns_deep`
- **Default:** Yes (domains only)
- **Not available for IP targets**

## What Is Checked

### Light scan

- DNS record resolution: A, AAAA, MX, NS, TXT, CNAME, CAA
- SPF record presence and policy strength
- DMARC record presence and policy
- CAA record presence

### Deep scan

Uses checkdmarc for RFC-compliant validation. Includes:

- SPF record validity per RFC 7208, DNS lookup count (limit of 10)
- DMARC record validity per RFC 7489, policy analysis (none/quarantine/reject), subdomain policy, reporting URI (rua)
- DKIM selector validation (RFC 6376)
- DNSSEC presence
- MX and NS record validation with warnings

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| high | SPF uses `+all` (allows any server to send email) |
| medium | No SPF record found, no DMARC record found, SPF missing restrictive `all` mechanism, DMARC policy `none` not enforcing |
| low | No CAA records, DMARC policy set to `none` |
| info | SPF record present, DMARC record present, CAA records configured, DNSSEC enabled, valid SPF, DMARC enforced |

### Deep scan additions

| Severity | Example findings |
|----------|-----------------|
| high | SPF exceeds 10 DNS lookups |
| medium | SPF/DMARC syntax errors, invalid records |
| info | SPF valid with N lookups, DMARC reporting configured, multiple nameservers |

## Raw Data Fields

### Light scan

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

### Deep scan

| Field | Description |
|-------|-------------|
| `domain` | Queried domain |
| `base_domain` | Base/apex domain |
| `dnssec` | DNSSEC enabled (boolean) |
| `spf` | Parsed SPF record |
| `spf_valid` | SPF validity (boolean) |
| `spf_dns_lookups` | Number of DNS lookups in SPF |
| `dmarc` | Parsed DMARC record |
| `dmarc_valid` | DMARC validity (boolean) |
| `dmarc_policy` | DMARC policy (none/quarantine/reject) |
| `dmarc_subdomain_policy` | DMARC subdomain policy |
| `dmarc_rua` | DMARC aggregate report URIs |
| `ns` | Nameservers |
| `mx` | Mail exchange servers |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
