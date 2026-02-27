# Getting Started

## Endpoints

All endpoints are under the `/v1` prefix.

### Bundle Scan

Scan a target with a fixed suite of security checks. Always returns `200` with inline results.

```bash
# Scan a domain — returns 200 with results inline
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

Response (`200 OK`):

```json
{
  "results": [{"target": "example.com", "results": {...}, "duration_ms": 1234, "summary": {...}}],
  "summary": {"critical": 0, "high": 0, "medium": 3, "low": 1, "info": 2, "total": 6, "score": 87}
}
```

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Domain, IP address, or host:port to scan |
| `auth` | object | No | [Auth credentials](checks/auth.md) to send to scan target |

**Fixed check suite** (automatically selected based on target type):
- **Domains:** headers, ssl, dns, web, whois
- **IPs:** headers, ssl, web

### Poll for Results

For async individual checks (e.g. CVE), poll the job endpoint:

```bash
curl https://your-instance/v1/scan/a1b2c3d4e5f6...
```

Returns the full job with its current status (`pending`, `running`, `completed`, or `failed`). When completed, `result` contains the scan response with findings. The `format` query parameter works on this endpoint (see below).

### Single Check

Run one check type against a single target. Fast checks (headers, ssl, dns, ports, etc.) return results inline (`200`). Slow checks (ssl_deep, cve) return `202` with a job ID.

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

## Authentication

If your InfraProbe instance is configured with a RapidAPI proxy secret, include it in the request header:

```bash
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -H "x-rapidapi-proxy-secret: your-secret" \
  -d '{"target": "example.com"}'
```

Requests without a valid secret receive `403 Forbidden`.

### Local Development

To disable authentication for local development, set `INFRAPROBE_DEV_BYPASS_AUTH=true` in your `.env` file. When enabled, the RapidAPI proxy-secret middleware is skipped entirely and no auth header is required. Defaults to `false`.

### Job Storage

By default, InfraProbe uses in-memory job storage (jobs lost on restart). For persistent storage matching the production setup, use Firestore:

```bash
INFRAPROBE_JOB_STORE_BACKEND=firestore \
INFRAPROBE_FIRESTORE_PROJECT=your-gcp-project \
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json \
INFRAPROBE_DEV_BYPASS_AUTH=true \
uv run python main.py
```

The service account needs the `Cloud Datastore User` role (`roles/datastore.user`). In production (Cloud Run), authentication is handled via Application Default Credentials automatically.

---

[Back to overview](README.md) | [Troubleshooting](troubleshooting.md)
