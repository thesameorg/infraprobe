# InfraProbe API Guide

InfraProbe is an infrastructure security scanning API. Send it a domain or IP address, and it runs security checks in parallel, returning structured findings with severity levels.

## Check Types

| Check | Description |
|-------|-------------|
| [headers](checks/headers.md) | HTTP security headers |
| [ssl](checks/ssl.md) | SSL/TLS certificate & protocol |
| [dns](checks/dns.md) | DNS records, SPF, DMARC, CAA |
| [web](checks/web.md) | CORS, exposed paths, security.txt |
| [whois](checks/whois.md) | Domain registration & expiry |

**Bundle scan checks for domains:** headers, ssl, dns, web, whois

**Bundle scan checks for IPs:** headers, ssl, web

DNS and whois checks require a domain name and are not included for IP targets.

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

- [Getting Started](getting-started.md) — endpoints, examples, output formats
- [Authenticated Scanning](checks/auth.md) — scan targets behind login walls with bearer tokens, basic auth, cookies, or custom headers
- [Troubleshooting](troubleshooting.md) — error codes, common issues, performance tips
