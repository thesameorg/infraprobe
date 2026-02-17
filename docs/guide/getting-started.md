# Getting Started

## Endpoints

All endpoints are under the `/v1` prefix.

### Bundle Scan (always async)

Scan one or more targets with multiple checks at once. Always returns `202 Accepted` with a job ID — poll for results.

```bash
# Scan a domain with default checks (auto-detected based on target type)
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'

# Scan with specific checks
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"], "checks": ["headers", "ssl", "dns"]}'

# Scan multiple targets
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com", "example.org"]}'
```

Response (`202 Accepted`):

```json
{
  "job_id": "a1b2c3d4e5f6...",
  "status": "pending",
  "created_at": "2025-01-15T10:30:00Z"
}
```

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `targets` | string[] | Yes | 1-10 domains or IPs |
| `checks` | string[] | No | Check types to run (auto-detected from target type if omitted) |
| `auth` | object | No | [Auth credentials](checks/auth.md) to send to scan targets |
| `webhook_url` | string | No | URL to receive results when scan completes |
| `webhook_secret` | string | No | HMAC-SHA256 key for signing webhook payloads |

**Auto-detection:** When `checks` is omitted, InfraProbe selects defaults based on target type:
- **Domains:** headers, ssl, dns, tech, blacklist, whois
- **IPs:** headers, ssl, tech, blacklist

DNS-only checks (`dns`, `dns_deep`, `whois`) are rejected for IP targets with a 422 error.

### Poll for Results

```bash
curl https://your-instance/v1/scan/a1b2c3d4e5f6...
```

Returns the full job with its current status (`pending`, `running`, `completed`, or `failed`). When completed, `result` contains the scan response with findings. The `format` and `fail_on` query parameters work on this endpoint (see below).

### Single Check

Run one check type against a single target. Fast checks (headers, ssl, dns, etc.) return results inline (`200`). Slow checks (ports, ports_deep, cve) return `202` with a job ID.

```bash
# Fast check — returns 200 with results inline
curl -X POST https://your-instance/v1/check/headers \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Deep check — also inline
curl -X POST https://your-instance/v1/check/ssl_deep \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Slow check — returns 202, poll for results
curl -X POST https://your-instance/v1/check/ports \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org"}'
```

## Reading Results

A scan response contains one `TargetResult` per target, with a severity summary:

```json
{
  "results": [
    {
      "target": "example.com",
      "results": {
        "ssl": {
          "check": "ssl",
          "findings": [
            {
              "severity": "info",
              "title": "Valid certificate",
              "description": "Certificate expires in 250 days",
              "details": {"days_until_expiry": 250}
            }
          ],
          "raw": {
            "host": "example.com",
            "port": 443,
            "protocol_version": "TLSv1.3",
            "days_until_expiry": 250
          },
          "error": null
        }
      },
      "duration_ms": 823,
      "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1, "total": 1}
    }
  ],
  "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1, "total": 1}
}
```

**Key fields:**

- `findings[].severity` — one of: `critical`, `high`, `medium`, `low`, `info`
- `findings[].title` — short summary of the finding
- `findings[].description` — detailed explanation
- `findings[].details` — structured data relevant to the finding
- `raw` — full scanner output (varies by check type, see individual check docs)
- `error` — non-null string if the scanner failed; other checks still complete normally
- `summary` — severity counts aggregated across all findings (per-target and per-scan)

## CI/CD Gating with `fail_on`

Use the `fail_on` query parameter to gate CI/CD pipelines based on finding severity:

```bash
# Fail if any high or critical findings exist
curl "https://your-instance/v1/scan/a1b2c3d4...?fail_on=high,critical"

# Fail on medium and above
curl -X POST "https://your-instance/v1/check/headers?fail_on=medium" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

When findings at or above the threshold exist, the response is `422` with `error: "threshold_exceeded"` and the full results included. Pipelines can check the HTTP status code — no JSON parsing needed for pass/fail.

## Output Formats

Use the `format` query parameter to change the response format.

### JSON (default)

```bash
curl -X POST "https://your-instance/v1/check/headers?format=json" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### SARIF 2.1.0

Produces [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) output compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-consuming tools.

```bash
# On inline check
curl -X POST "https://your-instance/v1/check/headers?format=sarif" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# On completed job
curl "https://your-instance/v1/scan/a1b2c3d4...?format=sarif"
```

Severity mapping in SARIF:

| InfraProbe severity | SARIF level | security-severity |
|--------------------|-----------|--------------------|
| critical | error | 9.5 |
| high | error | 8.0 |
| medium | warning | 5.5 |
| low | note | 3.0 |
| info | note | 1.0 |

### CSV

One row per finding. Useful for spreadsheet analysis and reporting.

```bash
curl -X POST "https://your-instance/v1/check/headers?format=csv" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

Columns: `target`, `check`, `severity`, `title`, `description`, `details`

## Webhooks

Instead of polling, provide a `webhook_url` to get results pushed to you:

```bash
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["example.com"],
    "webhook_url": "https://your-server/callback",
    "webhook_secret": "your-secret-key"
  }'
```

When the scan completes, InfraProbe sends a POST request to your webhook URL with the scan results as the body. If you provide a `webhook_secret`, the payload is signed with HMAC-SHA256 in the `X-Signature` header for verification.

## Authentication

If your InfraProbe instance is configured with a RapidAPI proxy secret, include it in the request header:

```bash
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -H "x-rapidapi-proxy-secret: your-secret" \
  -d '{"targets": ["example.com"]}'
```

Requests without a valid secret receive `403 Forbidden`.

### Local Development

To disable authentication for local development, set `INFRAPROBE_DEV_BYPASS_AUTH=true` in your `.env` file. When enabled, the RapidAPI proxy-secret middleware is skipped entirely and no auth header is required. Defaults to `false`.

---

[Back to overview](README.md) | [Troubleshooting](troubleshooting.md)
