# InfraProbe Scanner Architecture

Canonical reference for scanner design, timeout handling, error propagation, and concurrency.
All code changes must follow these rules. Referenced from `CLAUDE.md`.

---

## 1. Core Principles

**DRY** — Timeout enforcement happens in exactly one place (the orchestrator). Scanners never implement their own timeout logic.

**YAGNI** — Scanners do one thing: take a target, return findings. No caching, no retry, no scoring inside scanners.

**SOLID:**
- **S** — Orchestrator orchestrates. Scanners scan. Scoring scores. No mixing.
- **O** — New scanner = new file + register in `app.py`. No changes to orchestrator.
- **L** — Every scanner has the same signature and same behavioral contract.
- **I** — Scanners depend only on `CheckResult`/`Finding` models, not on each other.
- **D** — Orchestrator depends on the scanner signature type, not on concrete scanner modules.

---

## 2. Scanner Contract

Every scanner is a single async function:

```python
async def scan(target: str, timeout: float) -> CheckResult
```

### Rules

1. **`timeout` is a budget, not a guarantee.** The scanner should pass it to I/O calls (httpx, dns, ssl) as a hint. The orchestrator enforces the hard deadline — the scanner does NOT need to wrap its own code in `asyncio.wait_for`.

2. **Never hang.** Every I/O call must receive an explicit timeout derived from the `timeout` parameter. No bare `await` on network calls. No unbounded loops.

3. **Never raise.** Catch all exceptions internally and return `CheckResult(check=..., error="message")`. The orchestrator has a safety net, but scanners should not rely on it.

4. **Findings = problems only.** Don't create INFO findings for "header X is present". Only report what needs attention. Use `raw` dict for neutral/diagnostic data (response headers, cert details, DNS records).

5. **Stateless.** No module-level state, no connection pools, no caches. Receive target + timeout, return result. If shared HTTP clients are needed in the future, they'll be injected via the function signature, not managed by the scanner.

6. **Deterministic check type.** Always return `CheckResult(check=CheckType.YOUR_TYPE, ...)`. The check field must match the scanner's registered type.

---

## 3. Timeout Architecture

```
                    ┌─────────────────────────────┐
                    │  Request-level timeout       │
                    │  (uvicorn/Cloud Run: 300s)   │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │  Orchestrator hard deadline   │
                    │  asyncio.wait_for(           │
                    │    scanner(target, budget),   │
                    │    timeout=budget + GRACE     │
                    │  )                            │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │  Scanner I/O timeout         │
                    │  httpx.Timeout(budget)       │
                    │  dns resolver timeout=budget │
                    │  ssl socket timeout=budget   │
                    └─────────────────────────────┘
```

### Constants

| Name | Value | Where | Purpose |
|------|-------|-------|---------|
| `settings.scanner_timeout` | `10.0s` | config.py | Per-scanner budget passed to `scan(target, timeout)` |
| `ORCHESTRATOR_GRACE` | `2.0s` | api/scan.py | Buffer for task scheduling overhead. Hard kill = budget + grace |

### Rules

1. **Single enforcement point.** `_run_scanner()` in `api/scan.py` is the ONLY place that calls `asyncio.wait_for`. Scanners never call `wait_for` on themselves.

2. **Budget propagation.** The orchestrator passes `settings.scanner_timeout` as the `timeout` argument. Scanners pass this value (or values derived from it) to their I/O libraries.

3. **Grace period.** The orchestrator wraps with `wait_for(timeout=budget + GRACE)`. This accounts for asyncio scheduling jitter. If the scanner respects its budget, the grace period is never reached.

4. **Timeout = error, not crash.** `TimeoutError` from `wait_for` is caught and converted to `CheckResult(error="Scanner X timed out after Ys")`. The scan continues with other checks.

5. **Connect timeout < total timeout.** For HTTP scanners: use `connect=min(3.0, budget)` so connection failures fail fast, leaving time for fallback strategies (HTTPS→HTTP).

---

## 4. Error Handling

### Error categories

| Category | Example | Orchestrator behavior | User sees |
|----------|---------|----------------------|-----------|
| **Scanner not registered** | `CheckType.SSL` with no scanner | Return `CheckResult(error=...)` | `"error": "Scanner ssl not registered"` |
| **Timeout** | Network unreachable, slow target | `wait_for` cancels, return error result | `"error": "Scanner headers timed out after 10.0s"` |
| **Scanner exception** | Bug in scanner code, unexpected error | Catch `Exception`, return error result | `"error": "Scanner headers failed: ..."` |
| **Target blocked** | SSRF attempt, private IP | HTTPException before scanning starts | HTTP 400 |
| **Target invalid** | Unresolvable domain | HTTPException before scanning starts | HTTP 422 |

### Rules

1. **Scanners that error don't block other scanners.** Each scanner runs independently via `asyncio.gather`. One failure doesn't affect others.

2. **All scanner errors land in `CheckResult.error`.** The response always has the same shape. Clients check `error` field — if null, `findings` is valid.

3. **No retry at any level.** Scanners don't retry. The orchestrator doesn't retry. If a check fails, it fails. The client can retry the whole scan. Retry logic adds complexity, hides latency, and masks bugs.

4. **Fail the whole request only for input validation errors** (blocked target, invalid target). Never fail the whole request because a single scanner errored.

---

## 5. Concurrency Model

```
POST /scan {targets: [A, B], checks: [headers, ssl]}

asyncio.gather(
    _scan_target(A, [headers, ssl]),   ← parallel
    _scan_target(B, [headers, ssl]),   ← parallel
)

_scan_target(A, [headers, ssl]):
    asyncio.gather(
        _run_scanner(headers, A, 10s),  ← parallel
        _run_scanner(ssl, A, 10s),      ← parallel
    )
```

### Rules

1. **Two-level parallelism.** Targets run in parallel. Checks per target run in parallel. This is the only concurrency model.

2. **No semaphore/pool needed yet (YAGNI).** With max 10 targets × 4 checks = 40 concurrent tasks, all lightweight I/O-bound. Add concurrency limits only when there's evidence of resource exhaustion.

3. **Each `_run_scanner` call is fully independent.** No shared state between concurrent scanner invocations. No locks needed.

4. **Total request time ≈ max(scanner_timeout) + overhead**, not sum. This is the key benefit of parallel execution.

---

## 6. Adding a New Scanner

Checklist:

1. **Create** `src/infraprobe/scanners/{name}.py`
2. **Implement** `async def scan(target: str, timeout: float) -> CheckResult` following the contract in section 2
3. **Register** in `app.py`: `register_scanner(CheckType.{NAME}, {name}.scan)`
4. **Test** with a real target in `tests/test_scan.py`

What you DON'T need to change:
- `api/scan.py` (orchestrator) — handles any registered scanner automatically
- `scoring.py` — works on findings from any scanner
- `models.py` — unless you need a new `CheckType` enum value

---

## 7. Debugging Guide

### Scanner hangs (doesn't return within timeout)

1. The orchestrator's `wait_for` will kill it after `budget + GRACE` seconds
2. The result will be `CheckResult(error="Scanner X timed out after Ys")`
3. **Root cause:** an I/O call without explicit timeout. Fix: pass `timeout` to every network call

### Scanner returns unexpected error

1. Check `CheckResult.error` string — it includes the exception message
2. The orchestrator catches `Exception` broadly, so even unexpected errors are surfaced
3. **Root cause:** usually a parsing error on unexpected response format. Fix: handle edge cases in the scanner

### Request takes too long

1. Check `duration_ms` in `TargetResult` — shows total time for that target
2. All scanners run in parallel, so total ≈ slowest scanner
3. If one scanner dominates, its `timeout` budget may be too generous for the use case

### Validating timeout behavior

Run with `INFRAPROBE_SCANNER_TIMEOUT=2` to use a short timeout and verify scanners respect it. All scanners should either complete or error within ~4s (budget + grace).

---

## 8. What This Architecture Deliberately Excludes (YAGNI)

These are not needed now. Add them only when there is a concrete requirement:

- **Retry logic** — adds latency, complexity, masks failures
- **Circuit breakers** — meaningful with persistent connections/services, not one-shot scans
- **Scanner dependency chains** — (e.g., "run tech after headers") — all scanners are independent
- **Connection pooling** — scanners are stateless, short-lived. Pool when profiling shows connection setup is a bottleneck
- **Per-scanner timeout config** — one timeout fits all for now. Split when scanners have provably different latency profiles
- **Async job queue** — scans are synchronous request-response. Add queue when scans exceed request timeout (e.g., port scans)
- **Structured logging / tracing** — add when there are production debugging needs, not preemptively
- **Rate limiting** — add when there are paying users or abuse
- **Caching** — add when the same targets are scanned repeatedly in short windows
