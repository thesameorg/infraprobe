# Changelog

## Unreleased

### Breaking Changes

- **Single target API**: `POST /v1/scan` now accepts `"target": "example.com"` (a single string) instead of `"targets": ["example.com"]` (a list). The response shape is unchanged — `results` is still a list with one element.

### Bug Fixes

- **UnicodeError crash (500 → 422)**: Domains with invalid IDNA encoding (e.g. `app.quberas..acom`) now return a clear 422 error instead of crashing with a 500. `target.py:build_context()` catches `UnicodeError` in addition to `socket.gaierror`.
- **Web scanner SPA false positives**: `_probe_path()` now rejects HTML responses before running content checks. SPA catch-all pages that return 200 with HTML for any path no longer trigger false positives for `.env`, `.git/HEAD`, etc.
- **dns_deep analysis crashes**: Wrapped `_analyze_results()` in try/except to handle checkdmarc internal errors (`'str' object has no attribute 'args'`). Returns partial results instead of failing entirely.
- **Webhook docs**: Fixed header name from `X-Signature` to `X-InfraProbe-Signature` in getting-started guide and auth docs.

### Improvements

- **OpenAPI descriptions**: Added `description` to all `ScanRequest` and `SingleCheckRequest` fields (`target`, `checks`, `async_mode`, `webhook_url`, `webhook_secret`, `auth`) for better auto-generated API docs.
- **Error messages**: `build_context()` now distinguishes format errors ("Invalid domain format") from resolution failures ("Cannot resolve domain") in 422 responses.
