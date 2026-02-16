# Getting Started

## Endpoints

All endpoints are under the `/v1` prefix.

### Bundle Scan

Scan one or more targets with multiple checks at once.

```bash
# Scan a domain with default checks
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

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `targets` | string[] | Yes | 1-10 domains or IPs |
| `checks` | string[] | No | Check types to run (defaults vary by target type) |
| `webhook_url` | string | No | URL to receive results when scan completes |
| `webhook_secret` | string | No | HMAC-SHA256 key for signing webhook payloads |

### Single Check

Run one check type against a single target.

```bash
# Light check
curl -X POST https://your-instance/v1/check/ssl \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Deep check
curl -X POST https://your-instance/v1/check_deep/ssl_deep \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### Domain-Specific Endpoints

These reject IP addresses and default to domain checks (headers, ssl, dns, tech, blacklist, whois).

```bash
# Bundle domain scan
curl -X POST https://your-instance/v1/scan_domain \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'

# Single domain check
curl -X POST https://your-instance/v1/check_domain/dns \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### IP-Specific Endpoints

These reject domain names and default to IP checks (headers, ssl, tech, blacklist). DNS and whois checks are not allowed.

```bash
# Bundle IP scan
curl -X POST https://your-instance/v1/scan_ip \
  -H "Content-Type: application/json" \
  -d '{"targets": ["93.184.216.34"]}'

# Single IP check
curl -X POST https://your-instance/v1/check_ip/ssl \
  -H "Content-Type: application/json" \
  -d '{"target": "93.184.216.34"}'
```

## Reading Results

A scan response contains one `TargetResult` per target:

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
      "duration_ms": 823
    }
  ]
}
```

**Key fields:**

- `findings[].severity` — one of: `critical`, `high`, `medium`, `low`, `info`
- `findings[].title` — short summary of the finding
- `findings[].description` — detailed explanation
- `findings[].details` — structured data relevant to the finding
- `raw` — full scanner output (varies by check type, see individual check docs)
- `error` — non-null string if the scanner failed; other checks still complete normally

## Output Formats

Use the `format` query parameter to change the response format.

### JSON (default)

```bash
curl -X POST "https://your-instance/v1/scan?format=json" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'
```

### SARIF 2.1.0

Produces [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) output compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-consuming tools.

```bash
curl -X POST "https://your-instance/v1/scan?format=sarif" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'
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
curl -X POST "https://your-instance/v1/scan?format=csv" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'
```

Columns: `target`, `check`, `severity`, `title`, `description`, `details`

## Async Scans

For long-running scans, use the async endpoint to avoid HTTP timeouts.

### 1. Start the scan

```bash
curl -X POST https://your-instance/v1/scan/async \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"], "checks": ["headers", "ssl", "ports"]}'
```

Returns `202 Accepted` with a job ID:

```json
{
  "job_id": "a1b2c3d4e5f6...",
  "status": "pending",
  "created_at": "2025-01-15T10:30:00Z"
}
```

### 2. Poll for status

```bash
curl https://your-instance/v1/scan/a1b2c3d4e5f6...
```

Returns the job with its current status (`pending`, `running`, `completed`, or `failed`).

### 3. Get results

Once the job status is `completed`, fetch the report:

```bash
curl "https://your-instance/v1/scan/a1b2c3d4e5f6.../report?format=json"
```

This returns the same `ScanResponse` format as a synchronous scan. The `format` query parameter works here too.

### Webhooks

Instead of polling, provide a `webhook_url` to get results pushed to you:

```bash
curl -X POST https://your-instance/v1/scan/async \
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

---

[Back to overview](README.md) | [Troubleshooting](troubleshooting.md)
