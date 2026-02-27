# Changelog

## Unreleased

### Breaking Changes

- **Single endpoint API**: Stripped down to `POST /v1/scan` as the only scan endpoint. All `/v1/check/{type}` individual check endpoints removed. All `GET /v1/scan/{job_id}` polling removed.
- **Removed scanners**: `ssl_deep`, `dns_deep`, `tech`, `blacklist`, `blacklist_deep`, `ports`, `cve` scanners deleted. Only 5 scanners remain: headers, ssl, dns, web, whois.
- **Removed async job system**: No more 202 responses, job polling, or background tasks. All scans are synchronous 200.
- **Removed storage layer**: `MemoryJobStore`, `FirestoreJobStore`, and the entire `storage/` package deleted. No `INFRAPROBE_JOB_STORE_BACKEND` setting.
- **Removed nmap dependency**: No more nmap installation required. Port scanning and CVE detection removed.
- **Removed config settings**: `deep_scanner_timeout`, `nvd_api_key`, `nmap_max_concurrent`, `job_ttl_seconds`, `job_cleanup_interval`, `webhook_timeout`, `webhook_max_retries`, `job_store_backend`, `firestore_project`, `firestore_database`.
- **Removed dependencies**: `sslyze`, `checkdmarc`, `wappalyzer`, `python-nmap`, `google-cloud-firestore` (optional).
- **Simplified deployment**: Cloud Run memory reduced to 512Mi. No Firestore emulator in CI. No nmap in Docker image.

### Removed

- `src/infraprobe/storage/` — entire directory
- `src/infraprobe/webhook.py`
- `src/infraprobe/scanners/blacklist.py`, `tech.py`, `ports.py`, `cve.py`
- `src/infraprobe/scanners/deep/` — entire directory
- 9 test files for removed functionality
- `CapacityExceededError` (429 backpressure for nmap)
- `ScanRequest`, `JobStatus`, `JobCreate`, `Job` models
- `nmap_semaphore()` function

### Earlier Changes

- **Simplified scan endpoint**: `POST /v1/scan` is a single sync endpoint that always returns **200** with inline results.
- **Fixed check bundle**: Scan runs a fixed set of checks based on target type — **headers, ssl, dns, web, whois** for domains; **headers, ssl, web** for IPs.
- **Single target API**: `POST /v1/scan` accepts `"target": "example.com"` (a single string).

### Bug Fixes

- **UnicodeError crash (500 → 422)**: Domains with invalid IDNA encoding (e.g. `app.quberas..acom`) now return a clear 422 error instead of crashing with a 500.
- **Web scanner SPA false positives**: `_probe_path()` now rejects HTML responses before running content checks.
