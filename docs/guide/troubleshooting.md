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
| 422 | `invalid_target` | Target format is invalid, or domain cannot be resolved |
| 500 | `internal_error` | Unexpected server error |

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
| `Scanner X timed out` | Scanner exceeded its time budget | Target may be slow to respond; try again |
| `Connection refused` | Target is not accepting connections on the expected port | Verify the target is reachable and the service is running |
| `Name resolution failed` | Domain could not be resolved via DNS | Check that the domain exists and DNS is configured |

## Common Issues

### "blocked_target" for internal addresses

InfraProbe blocks scanning of private and reserved IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, etc.) to prevent SSRF attacks. This also applies to domains that resolve to private IPs. This is by design and cannot be bypassed.

### DNS and WHOIS not in IP scan results

The `dns` and `whois` checks require a domain name. The bundle scan (`POST /v1/scan`) auto-detects target type — IP targets get headers, ssl, web; domains get headers, ssl, dns, web, whois.

### Scan returns mostly "info" findings

Info-level findings are positive signals (e.g., "Valid certificate", "TLS 1.3 supported"). If you only see info findings, your target's security posture is good for the checks that ran.

### CSV or SARIF output is empty

Checks that produce no findings and no errors are omitted from CSV output. SARIF output includes all rules but may have zero results if no issues were found.

## Performance Tips

- **Bundle scan is fast** — `POST /v1/scan` runs all checks in parallel and returns 200 inline. P95 ~5s for domains, ~3s for IPs.

## Timeouts

All scanners use a 10-second per-scanner timeout. A bundle scan runs all selected checks in parallel, so total wall-clock time is roughly the slowest individual check.

---

[Back to overview](README.md) | [Getting Started](getting-started.md)
