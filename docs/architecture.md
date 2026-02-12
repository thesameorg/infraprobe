# Architecture

Technical architecture for InfraProbe. Covers system design, component structure, data flow, and deployment.

---

## System Overview

InfraProbe is a stateless HTTP API that runs security checks against infrastructure targets. A single `POST /scan` request accepts one or more targets and check types, executes all checks concurrently, scores the results, and returns a structured JSON response. There is no persistent storage, no background processing, and no inter-request state.

```
Client
  │
  │  POST /scan {targets, checks}
  ▼
┌──────────────────────────────────────────────────┐
│  FastAPI (ASGI)                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  api/scan.py — Orchestrator                │  │
│  │  ┌──────────┐  ┌──────────┐               │  │
│  │  │ Target A │  │ Target B │  ...           │  │
│  │  │ ┌──────┐ │  │ ┌──────┐ │               │  │
│  │  │ │ hdrs │ │  │ │ hdrs │ │  asyncio      │  │
│  │  │ │ ssl  │ │  │ │ ssl  │ │  .gather()    │  │
│  │  │ │ dns  │ │  │ │ dns  │ │               │  │
│  │  │ │ tech │ │  │ │ tech │ │               │  │
│  │  │ └──────┘ │  │ └──────┘ │               │  │
│  │  └──────────┘  └──────────┘               │  │
│  └────────────────────────────────────────────┘  │
│         │                                        │
│         ▼                                        │
│  ┌─────────────┐  ┌──────────────┐               │
│  │ scoring.py  │  │ blocklist.py │               │
│  └─────────────┘  └──────────────┘               │
└──────────────────────────────────────────────────┘
  │
  │  200 OK {results: [{target, score, findings, ...}]}
  ▼
Client
```

---

## Package Layout

```
src/infraprobe/
├── __init__.py
├── app.py              # FastAPI instance, scanner registration, /health
├── config.py           # pydantic-settings (INFRAPROBE_ env prefix)
├── models.py           # Pydantic models + enums (Severity, CheckType)
├── scoring.py          # Findings → numeric score → letter grade
├── blocklist.py        # SSRF protection: block private/reserved IPs
├── api/
│   └── scan.py         # POST /scan, orchestrator, scanner registry
└── scanners/
    ├── headers.py      # HTTP security headers check
    └── ssl.py          # SSL/TLS certificate and cipher check
```

Build: `hatchling` backend, installable as `infraprobe` wheel. Entry point for dev: `main.py` (runs uvicorn with reload).

---

## Components

### App (`app.py`)

Creates the FastAPI instance. Registers scanners into the module-level registry in `api/scan.py` via `register_scanner(CheckType, scan_fn)`. Mounts the scan router. Exposes `GET /health`.

No middleware, no CORS, no auth. These are deferred until needed.

### Orchestrator (`api/scan.py`)

Owns the full lifecycle of a scan request:

1. Validate and parse `ScanRequest` (Pydantic)
2. Resolve and validate each target through `blocklist.validate_target()` — rejects private IPs (SSRF protection) and unresolvable domains
3. Fan out: `asyncio.gather` over targets, then `asyncio.gather` over checks per target
4. Each check runs through `_run_scanner()`, which wraps the scanner call in `asyncio.wait_for(fn, timeout=budget + GRACE)` — the single timeout enforcement point
5. Collect all `CheckResult`s, aggregate findings, pass to `scoring.calculate_score()`
6. Return `ScanResponse`

The orchestrator is scanner-agnostic. It dispatches by `CheckType` to whatever function was registered. Adding a scanner requires no changes here.

### Scanner Registry

Module-level dict in `api/scan.py`: `_SCANNERS: dict[CheckType, ScanFn]`. Populated at import time by `app.py`. The orchestrator looks up scanners by `CheckType` — unregistered types return a `CheckResult` with an error string.

Scanner function signature: `async def scan(target: str, timeout: float) -> CheckResult`. See `docs/check_approach.md` for the full contract.

### Blocklist (`blocklist.py`)

SSRF protection layer. Called before any scanner runs.

- Parses the target (bare domain, domain:port, IP, URL)
- If IP: checks against blocked networks (loopback, private RFC 1918, link-local, cloud metadata 169.254.x.x, IPv6 equivalents)
- If domain: resolves via DNS, checks every resolved IP against the same blocklist
- Raises `BlockedTargetError` (→ HTTP 400) or `InvalidTargetError` (→ HTTP 422)

### Scoring (`scoring.py`)

Pure function: `calculate_score(findings: list[Finding]) -> tuple[str, SeveritySummary]`.

Starts at 100 points, deducts per finding severity: CRITICAL -40, HIGH -20, MEDIUM -10, LOW -3, INFO 0. Clamped to [0, 100]. Maps to letter grade: A+ (100), A (90+), B+ (85+), B (80+), C (70+), D (60+), F (<60).

### Config (`config.py`)

`pydantic-settings` with `INFRAPROBE_` env prefix. Singleton `settings` instance.

| Setting | Default | Env var |
|---------|---------|---------|
| `env` | `"development"` | `INFRAPROBE_ENV` |
| `log_level` | `"info"` | `INFRAPROBE_LOG_LEVEL` |
| `port` | `8080` | `INFRAPROBE_PORT` |
| `scanner_timeout` | `10.0` | `INFRAPROBE_SCANNER_TIMEOUT` |

---

## Data Model

```
ScanRequest                    ScanResponse
├── targets: list[str] (1-10)  └── results: list[TargetResult]
└── checks: list[CheckType]
                               TargetResult
                               ├── target: str
CheckResult                    ├── score: str (A+ .. F)
├── check: CheckType           ├── summary: SeveritySummary
├── findings: list[Finding]    ├── results: dict[str, CheckResult]
├── raw: dict[str, Any]        └── duration_ms: int
└── error: str | None
                               SeveritySummary
Finding                        ├── critical: int
├── severity: Severity         ├── high: int
├── title: str                 ├── medium: int
├── description: str           ├── low: int
└── details: dict[str, Any]    └── info: int
```

Enums: `Severity` (critical, high, medium, low, info), `CheckType` (ssl, headers, dns, tech).

`CheckResult.error` is the discriminator: if null, `findings` and `raw` are valid. If set, the scanner failed and `findings` is empty.

---

## Concurrency

Two-level fan-out, both using `asyncio.gather`:

```
POST /scan {targets: [A, B], checks: [headers, ssl]}

gather(
    _scan_target(A, [headers, ssl]),    # parallel
    _scan_target(B, [headers, ssl]),    # parallel
)

_scan_target(A, ...):
    gather(
        _run_scanner(headers, A, 10s),  # parallel
        _run_scanner(ssl, A, 10s),      # parallel
    )
```

Max concurrency: 10 targets x 4 check types = 40 tasks. All I/O-bound (HTTP, DNS, TLS handshakes). No semaphore or pool — not needed at this scale.

Total latency per request ≈ `max(scanner_timeout)` + scheduling overhead, not the sum.

---

## Timeout Model

Single enforcement point: `_run_scanner()` wraps each scanner call in `asyncio.wait_for(fn(target, budget), timeout=budget + GRACE)`.

- `budget` = `settings.scanner_timeout` (default 10s)
- `GRACE` = 2s (accounts for asyncio scheduling jitter)
- Scanners pass `budget` to their I/O libraries as a soft hint
- If a scanner exceeds budget + grace, `wait_for` cancels it and the orchestrator returns `CheckResult(error="timed out")`

Scanners never call `wait_for` on themselves. See `docs/check_approach.md` for the full timeout contract.

---

## Error Model

| Source | Scope | HTTP | Mechanism |
|--------|-------|------|-----------|
| Invalid/blocked target | Whole request | 400/422 | `HTTPException` before scanners run |
| Scanner not registered | Single check | 200 | `CheckResult(error=...)` |
| Scanner timeout | Single check | 200 | `wait_for` cancels, `CheckResult(error=...)` |
| Scanner exception | Single check | 200 | Catch `Exception`, `CheckResult(error=...)` |

Only input validation fails the entire request. Scanner failures are isolated — one failing check never affects another. No retry at any level.

---

## Deployment

### Runtime

- **Container:** Python 3.12 (uv base image), multi-stage Dockerfile
- **Server:** uvicorn (uvloop + httptools)
- **Platform:** Google Cloud Run (managed, scales to zero)

### CI/CD Pipeline

```
Push to main
  └─ CI (GitHub Actions)
       ├── ruff check + ruff format --check
       ├── ty check
       └── pytest
            └─ on success ─→ Deploy
                              ├── docker build + push to Artifact Registry
                              └── gcloud run deploy (SHA-tagged image)
```

Deploy workflow triggers on CI success (not in parallel). Uses immutable SHA-tagged images for Cloud Run deployments. Artifact Registry in the same GCP region as Cloud Run.

### Docker

```dockerfile
FROM ghcr.io/astral-sh/uv:0.6-python3.12-bookworm-slim
# Two-stage uv sync for layer caching:
# 1. Install deps from lockfile (cached unless pyproject.toml/uv.lock change)
# 2. Copy source and install project
CMD ["uv", "run", "uvicorn", "infraprobe.app:app", "--host", "0.0.0.0", "--port", "8080"]
```

Production: no `--reload`, no dev dependencies (`--no-dev`), frozen lockfile (`--frozen`).

Local dev: `docker-compose.yaml` mounts source as volume, enables `--reload`, maps host port 8000 to container port 8080.

---

## Current State

**Deployed:** Live on Google Cloud Run (`infraprobe-tzhg2ptrea-uc.a.run.app`). Cloud Run handles auth via identity tokens. CI/CD pipeline pushes on every `main` merge.

**Implemented:** `headers` scanner (HTTP security headers + info-leak detection, HTTPS-first with HTTP fallback), `ssl` scanner (TLS certificate validation, cipher strength, expiry, hostname matching).

**Planned (enum defined, not implemented):** `dns`, `tech`.

**Deferred (YAGNI):** retry logic, circuit breakers, connection pooling, caching, rate limiting, app-level auth, structured logging, async job queue. Add when there's a concrete need. See `docs/check_approach.md` for the full list.
