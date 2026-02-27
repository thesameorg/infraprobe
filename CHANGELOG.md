# Changelog

## Unreleased

### Breaking Changes

- **Simplified scan endpoint**: `POST /v1/scan` is now a single sync endpoint that always returns **200** with inline results. No more `async_mode`, `checks` selection, or webhook parameters. Just send `{"target": "example.com"}` and get results.
- **Fixed check bundle**: Scan runs a fixed set of checks based on target type — **headers, ssl, dns, web, whois** for domains; **headers, ssl, web** for IPs. The `checks` field is no longer accepted on the scan endpoint.
- **Removed async scan mode**: `POST /v1/scan` no longer supports `async_mode: true` or returns 202. Individual slow checks (`/v1/check/ssl_deep`, `/v1/check/cve`) still return 202.
- **Removed webhooks on scan**: `webhook_url` and `webhook_secret` fields removed from `ScanRequest`. Webhook delivery code (`webhook.py`) is no longer used by the scan endpoint.
- **Removed fail_on**: The `?fail_on=high,critical` query parameter has been removed from all endpoints. CI/CD gating should be implemented client-side by inspecting the `summary` field.
- **Default checks changed**: `tech` and `blacklist` removed from defaults; `web` added to defaults. All 12 scanners remain accessible via individual `/v1/check/{type}` endpoints.
- **Single target API** (earlier): `POST /v1/scan` accepts `"target": "example.com"` (a single string) instead of `"targets": ["example.com"]` (a list).

### Removed

- **`webhook.py` integration**: Webhook delivery is no longer triggered from the scan endpoint. The `webhook.py` module still exists but is unused.
- **`Job.webhook_status` and `Job.webhook_delivered_at`**: These fields have been removed from the `Job` model.
- **`ScanRequest.async_mode`, `ScanRequest.webhook_url`, `ScanRequest.webhook_secret`**: These fields have been removed.

### Improvements

- **OpenAPI tags**: Individual check endpoints now have clear tags — "Checks" for active scanners (headers, ssl, dns, web, whois), "Deprecated" for legacy scanners (tech, blacklist, etc.), "Jobs" for the polling endpoint.
- **Error messages**: `build_context()` now distinguishes format errors ("Invalid domain format") from resolution failures ("Cannot resolve domain") in 422 responses.

### Bug Fixes

- **UnicodeError crash (500 → 422)**: Domains with invalid IDNA encoding (e.g. `app.quberas..acom`) now return a clear 422 error instead of crashing with a 500.
- **Web scanner SPA false positives**: `_probe_path()` now rejects HTML responses before running content checks.
- **dns_deep analysis crashes**: Wrapped `_analyze_results()` in try/except to handle checkdmarc internal errors. Returns partial results instead of failing entirely.
