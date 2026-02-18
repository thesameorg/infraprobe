# Troubleshooting

## Error Codes

All error responses are JSON with this structure:

```json
{
  "error": "error_code",
  "detail": "Human-readable message"
}
```

| HTTP Status | Error Code | Cause |
|-------------|-----------|-------|
| 400 | `blocked_target` | Target is a private/reserved IP address (SSRF protection) |
| 403 | `forbidden` | Missing or invalid `x-rapidapi-proxy-secret` header |
| 404 | `not_found` | Job ID does not exist |
| 422 | `invalid_target` | Target format is invalid, or a DNS-only check was requested for an IP |
| 422 | `threshold_exceeded` | `fail_on` threshold matched — findings at or above severity exist |
| 422 | `invalid_parameter` | Invalid `fail_on` severity value |
| 500 | `internal_error` | Unexpected server error |
| 503 | `shutting_down` | Server is shutting down; retry after a moment |

## Scanner Errors

Individual scanners can fail without affecting the rest of the scan. When a scanner fails, its result includes an `error` field:

```json
{
  "check": "ssl",
  "findings": [],
  "raw": {},
  "error": "Scanner ssl timed out"
}
```

Common scanner error causes:

| Error message | Cause | What to do |
|--------------|-------|------------|
| `Scanner X timed out` | Scanner exceeded its time budget | Target may be slow to respond; try again or use deep scan for longer timeout |
| `Connection refused` | Target is not accepting connections on the expected port | Verify the target is reachable and the service is running |
| `Name resolution failed` | Domain could not be resolved via DNS | Check that the domain exists and DNS is configured |
| `No open ports found` | Port scanner found no accessible ports | Target may be behind a firewall dropping all packets |

## Common Issues

### "blocked_target" for internal addresses

InfraProbe blocks scanning of private and reserved IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, etc.) to prevent SSRF attacks. This also applies to domains that resolve to private IPs. This is by design and cannot be bypassed.

### DNS-only checks fail for IP targets

The `dns`, `dns_deep`, and `whois` checks require a domain name. Using them with IP targets returns a 422 error. InfraProbe auto-detects target type — if you omit `checks`, IP targets automatically get IP-appropriate defaults (headers, ssl, tech, blacklist).

### Scan returns mostly "info" findings

Info-level findings are positive signals (e.g., "Valid certificate", "TLS 1.3 supported"). If you only see info findings, your target's security posture is good for the checks that ran. Consider running additional checks like `web`, `ports`, or `cve` for deeper coverage.

### Deep scans are slow

Deep scans use more thorough tools and have a 30-second timeout (vs 10 seconds for light scans). `ports_deep` scans 1000 ports (vs 20), and `cve` performs version detection plus NVD API lookups. This is expected behavior.

### Webhook not received

- Verify your webhook URL is publicly accessible
- Check that InfraProbe can reach your server (not blocked by firewall)
- Webhooks are retried up to 3 times with a 5-second timeout per attempt
- Poll the job status endpoint to confirm the scan completed

### CSV or SARIF output is empty

Checks that produce no findings and no errors are omitted from CSV output. SARIF output includes all rules but may have zero results if no issues were found.

### Firestore "Permission Denied" errors

The service account used to connect to Firestore needs the `Cloud Datastore User` role (`roles/datastore.user`). For local development, set `GOOGLE_APPLICATION_CREDENTIALS` to a service account key file. In production (Cloud Run), the compute service account gets this role.

```bash
# Grant Firestore access to a service account
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:SA_EMAIL" \
  --role="roles/datastore.user"
```

### Jobs disappear after restart (memory backend)

The default `memory` job store loses all jobs when the server restarts. Set `INFRAPROBE_JOB_STORE_BACKEND=firestore` for persistent storage that survives restarts and Cloud Run scale-to-zero.

## Performance Tips

- **Use specific checks** instead of running all defaults when you only need certain data
- **All bundle scans are async** — `POST /v1/scan` always returns 202, so there's no HTTP timeout concern for long scans
- **Batch targets** in a single `/v1/scan` request (up to 10) rather than making separate requests
- **Start with light scans** — deep variants provide more detail but take longer; use them when light results indicate areas of concern

## Timeouts

| Scan type | Timeout |
|-----------|---------|
| Light checks (headers, ssl, dns, tech, blacklist, whois, web, ports) | 10 seconds |
| Deep checks (ssl_deep, dns_deep, blacklist_deep, ports_deep, cve) | 30 seconds |

These are per-scanner timeouts. A bundle scan runs all selected checks in parallel, so total wall-clock time is roughly the slowest individual check.

---

[Back to overview](README.md) | [Getting Started](getting-started.md)
