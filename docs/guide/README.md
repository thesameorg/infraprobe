# InfraProbe API Guide

InfraProbe is an infrastructure security scanning API. Send it a domain or IP address, and it runs security checks in parallel, returning structured findings with severity levels.

## Check Types

| Check | Description | Default | Deep variant |
|-------|-------------|---------|--------------|
| [headers](checks/headers.md) | HTTP security headers | Yes | No |
| [ssl](checks/ssl.md) | SSL/TLS certificate & protocol | Yes | [ssl_deep](checks/ssl.md#deep-scan) |
| [dns](checks/dns.md) | DNS records, SPF, DMARC, CAA | Yes (domains) | [dns_deep](checks/dns.md#deep-scan) |
| [tech](checks/tech.md) | Technology fingerprinting (Wappalyzer) | Yes | No |
| [blacklist](checks/blacklist.md) | DNSBL spam/abuse lists | Yes | [blacklist_deep](checks/blacklist.md#deep-scan) |
| [whois](checks/whois.md) | Domain registration & expiry | Yes (domains) | No |
| [web](checks/web.md) | CORS, exposed paths, security.txt | Opt-in | No |
| [ports](checks/ports.md) | Open port detection | Opt-in | [ports_deep](checks/ports.md#deep-scan) |
| [cve](checks/cve.md) | CVE vulnerability detection | Opt-in | No |

**Default checks for domains:** headers, ssl, dns, tech, blacklist, whois

**Default checks for IPs:** headers, ssl, tech, blacklist

DNS and whois checks require a domain name and are not available for IP targets.

## Severity Levels

Findings use five severity levels:

| Severity | Meaning |
|----------|---------|
| `critical` | Immediate security risk requiring urgent action |
| `high` | Significant vulnerability that should be addressed soon |
| `medium` | Notable security issue worth investigating |
| `low` | Minor concern or best-practice recommendation |
| `info` | Informational finding (positive or neutral) |

## Response Structure

Every scan returns findings organized by target and check type, with severity summaries:

```json
{
  "results": [
    {
      "target": "example.com",
      "results": {
        "headers": {
          "check": "headers",
          "findings": [
            {
              "severity": "medium",
              "title": "Missing Content-Security-Policy",
              "description": "...",
              "details": {}
            }
          ],
          "raw": {},
          "error": null
        }
      },
      "duration_ms": 1234,
      "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 1}
    }
  ],
  "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 1}
}
```

- **findings** — security issues and informational notes, sorted by severity
- **raw** — unprocessed scanner output for advanced use
- **error** — non-null if the scanner failed (other checks still run)

## Guides

- [Getting Started](getting-started.md) — endpoints, examples, output formats, async scans
- [Authenticated Scanning](checks/auth.md) — scan targets behind login walls with bearer tokens, basic auth, cookies, or custom headers
- [Troubleshooting](troubleshooting.md) — error codes, common issues, performance tips
