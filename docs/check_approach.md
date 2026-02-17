# Scanner Development Guide

Rules and contracts for implementing scanners. All scanner code must follow this document.
Referenced from `CLAUDE.md`. For user-facing check descriptions, see `docs/guide/checks/`.

---

## Scanner Contract

Every scanner is a single async function:

```python
async def scan(target: str, timeout: float, auth=None) -> CheckResult
```

The `auth` parameter is an `AuthConfig | None` (see `models.py`). HTTP-based scanners (headers, tech, tech_deep, web) pass it to `scanner_client(timeout, auth=auth)`. Non-HTTP scanners accept the parameter but ignore it.

The `target` string is the normalized host (or host:port). A `ScanContext` (from `infraprobe.target`) is available in the orchestrator with pre-resolved IPs and `is_ip` flag, but scanners receive the target as a plain string.

### Rules

1. **`timeout` is a budget, not a guarantee.** Pass it to I/O calls (httpx, dns, ssl) as a hint. The orchestrator enforces the hard deadline — scanners do NOT call `asyncio.wait_for` on themselves.

2. **Never hang.** Every I/O call must receive an explicit timeout derived from the `timeout` parameter. No bare `await` on network calls. No unbounded loops.

3. **Never raise.** Catch all exceptions internally and return `CheckResult(check=..., error="message")`. The orchestrator has a safety net, but scanners should not rely on it.

4. **Findings = problems + positive confirmations.** Report issues that need attention (CRITICAL through LOW), and add `Severity.INFO` findings for things configured correctly (e.g. "TLS 1.3 supported", "DNSSEC enabled", "DMARC policy is reject"). This lets users see what's right, not just what's wrong. Use the `raw` dict for neutral/diagnostic data (response headers, cert details, DNS records).

5. **Stateless.** No module-level state, no connection pools, no caches. Receive target + timeout, return result. For HTTP-based scanners, use the shared client from `http.py` (`scanner_client` + `fetch_with_fallback`) instead of creating ad-hoc httpx clients. Use `scanner_client(timeout, follow_redirects=False)` when the scanner needs to analyze the target's own response (e.g. headers scanner), or leave the default (`True`) when the scanner needs final-page content (e.g. tech detection).

6. **Deterministic check type.** Always return `CheckResult(check=CheckType.YOUR_TYPE, ...)`. The check field must match the scanner's registered type.

7. **Nmap concurrency limit.** Scanners that spawn nmap subprocesses (via `asyncio.to_thread`) must acquire the shared semaphore first: `async with nmap_semaphore(): await asyncio.to_thread(...)`. Import from `infraprobe.config`. This prevents OOM when multiple nmap-based scans run concurrently.

---

## Timeout Layering

```
Request timeout (uvicorn/Cloud Run: 300s)
  └─ Orchestrator hard deadline: asyncio.wait_for(scanner, budget + SCHEDULING_BUFFER)
       └─ Scanner I/O timeout: httpx.Timeout(budget), dns timeout=budget, etc.
```

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| `settings.scanner_timeout` | `10.0s` | `config.py` | Per-scanner budget for light checks |
| `settings.deep_scanner_timeout` | `30.0s` | `config.py` | Per-scanner budget for deep checks (`ssl_deep`, `dns_deep`, `tech_deep`) |
| `_SCHEDULING_BUFFER` | `0.5s` | `api/scan.py` | Buffer for asyncio task-switch latency only |

**Rules:**
- `_run_scanner()` in `api/scan.py` is the only place that calls `asyncio.wait_for`.
- Scanners must respect their timeout budget internally — the buffer only covers scheduling latency, not scanner overruns.
- Scanners pass the budget (or values derived from it) to their I/O libraries.
- `TimeoutError` from `wait_for` is caught and converted to `CheckResult(error=...)`.
- For HTTP scanners: use `scanner_client(timeout)` from `http.py` which sets `connect=min(3.0, budget)` so connection failures fail fast.

---

## Error Handling

Scanners must handle their own errors. The orchestrator provides a safety net but scanners should not depend on it.

| Error type | Scanner responsibility | Orchestrator safety net |
|------------|----------------------|------------------------|
| Network error | Catch, return `CheckResult(error=...)` | Catches `Exception` |
| Timeout | Pass budget to I/O calls | `wait_for` kills after budget + 0.5s buffer |
| Unexpected exception | Catch broadly, return error result | Catches `Exception` |
| Target unreachable | Return error result | N/A (scanner handles) |

**Key rules:**
- One scanner failing never blocks other scanners (`asyncio.gather` runs them independently).
- No retry at any level. If a check fails, it fails. The client can retry the whole scan.
- All errors land in `CheckResult.error`. Clients check `error` — if null, `findings` is valid.

---

## Adding a New Scanner

1. Create `src/infraprobe/scanners/{name}.py`
2. Implement `async def scan(target: str, timeout: float, auth=None) -> CheckResult` following this contract
3. For HTTP-based scanners, use `scanner_client(timeout, auth=auth)` and `fetch_with_fallback(target, client)` from `infraprobe.http` — do not duplicate the HTTPS-first/HTTP-fallback pattern. Non-HTTP scanners should accept `auth` but ignore it.
4. Add enum value to `CheckType` in `models.py` if needed
5. Register in `app.py`: `register_scanner(CheckType.{NAME}, {name}.scan)`
6. Add integration test in `tests/test_scan.py` against a real target

What you don't need to change:
- `api/scan.py` — handles any registered scanner automatically. Individual endpoints (`/v1/check/{type}` for light, `/v1/check_deep/{type}` for deep) are generated from `CheckType` at import time, so new enum values get their own route automatically.

---

## Debugging

**Scanner hangs:** Orchestrator kills it after budget + 0.5s buffer. Result: `CheckResult(error="Scanner X timed out after Ys")`. Root cause: an I/O call without explicit timeout.

**Scanner returns error:** Check `CheckResult.error` string. Root cause: usually a parsing error on unexpected response format.

**Request takes too long:** Check `duration_ms` in `TargetResult`. All scanners run in parallel, so total time ≈ slowest scanner. Validate with `INFRAPROBE_SCANNER_TIMEOUT=2`.

**DNS scanner:** Each DNS query creates its own `Resolver` instance with an independent `lifetime` budget, so one slow query (e.g. large TXT response) cannot exhaust the timeout for others. All queries still run in parallel via `asyncio.gather`.

**`ModuleNotFoundError` for a third-party submodule in Docker:** The Dockerfile strips heavy/unused dependencies (e.g. `selenium`, `wappalyzer/browser`) to shrink the image. If a library's `__init__.py` unconditionally imports the stripped submodule, any import of that library — even a different submodule — will fail. Fix: stub the stripped module in `sys.modules` before importing. See `scanners/deep/tech.py` for the `wappalyzer.browser` stub pattern.

---

## What Scanners Should Not Do (YAGNI)

Add these only when there is a concrete requirement:

- Retry logic — adds latency, masks failures
- Connection pooling — scanners are stateless, short-lived
- Caching — add when same targets are scanned repeatedly
- Scanner dependency chains — all scanners are independent
- Per-scanner timeout config — one timeout fits all for now
- Circuit breakers — meaningful with persistent services, not one-shot scans
