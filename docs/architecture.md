# Architecture

Technical architecture for InfraProbe. Covers system design, component structure, data flow, and deployment.

---

## System Overview

InfraProbe is a stateless HTTP API that runs security checks against infrastructure targets. Two endpoint styles exist under `/v1`:

- **`POST /v1/scan`** — bundle endpoint. Accepts one or more targets and check types, executes all checks concurrently, and returns a `ScanResponse`.
- **`POST /v1/check/{type}`** — light scanner endpoints (e.g. `/v1/check/headers`). Accepts a single target, runs one scanner, returns a `TargetResult`.
- **`POST /v1/check_deep/{type}`** — deep scanner endpoints (e.g. `/v1/check_deep/ssl`). Same contract as light checks. Each is a separate route in OpenAPI for per-endpoint RapidAPI monetization.

There is no persistent storage, no background processing, and no inter-request state. No unversioned routes — all access goes through `/v1`.

```
Client
  │
  │  POST /v1/scan {targets, checks}     — or —
  │  POST /v1/check/headers {target}  or  /v1/check_deep/ssl {target}
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
│  ┌──────────────┐                                │
│  │ blocklist.py │                                │
│  └──────────────┘                                │
└──────────────────────────────────────────────────┘
  │
  │  200 OK {results: [{target, results, findings, ...}]}
  ▼
Client
```

---

## Package Layout

```
src/infraprobe/
├── __init__.py
├── app.py              # FastAPI instance, scanner registration, exception handlers, /health
├── config.py           # pydantic-settings (INFRAPROBE_ env prefix)
├── models.py           # Pydantic models + enums (Severity, CheckType)
├── blocklist.py        # SSRF protection: block private/reserved IPs (urllib.parse-based)
├── http.py             # Shared HTTP client (scanner_client, fetch_with_fallback)
├── api/
│   └── scan.py         # POST /v1/scan + /v1/check/ + /v1/check_deep/, orchestrator, scanner registry
└── scanners/
    ├── headers_drheader.py  # HTTP security headers check (drheaderplus)
    ├── ssl.py          # SSL/TLS certificate and cipher check
    ├── dns.py          # DNS security records check
    ├── tech.py         # Technology detection (lightweight)
    ├── blacklist.py    # Domain blacklist check
    ├── web.py          # Web security (CORS, exposed paths, mixed content, robots.txt, security.txt)
    └── deep/
        ├── ssl.py      # Deep SSL/TLS scan (SSLyze)
        ├── dns.py      # Deep DNS scan (checkdmarc)
        └── tech.py     # Deep tech detection (Wappalyzer)

scripts/
└── verify_deploy.py    # Deployment verification — hits every endpoint, reports pass/fail
```

Build: `hatchling` backend, installable as `infraprobe` wheel. Entry point for dev: `main.py` (runs uvicorn with reload).

---

## Components

### App (`app.py`)

Creates the FastAPI instance. Registers scanners into the module-level registry in `api/scan.py` via `register_scanner(CheckType, scan_fn)`. Mounts the scan router under `/v1`. Exposes `GET /health`.

Global exception handlers convert `BlockedTargetError` → HTTP 400 and `InvalidTargetError` → HTTP 422, so endpoint code doesn't need per-route try/except for target validation.

Optional RapidAPI proxy-secret middleware is enabled when `INFRAPROBE_RAPIDAPI_PROXY_SECRET` is set.

### Orchestrator (`api/scan.py`)

Owns the full lifecycle of a scan request. Serves two endpoint styles:

**Bundle (`POST /scan`):**
1. Validate and parse `ScanRequest` (Pydantic)
2. Resolve and validate each target through `blocklist.validate_target()` — rejects private IPs (SSRF protection) and unresolvable domains. Validation errors propagate as exceptions and are caught by global exception handlers in `app.py`.
3. Fan out: `asyncio.gather` over targets, then `asyncio.gather` over checks per target
4. Each check runs through `_run_scanner()`, which wraps the scanner call in `asyncio.wait_for(fn, timeout=budget + SCHEDULING_BUFFER)` — the single timeout enforcement point
5. Collect all `CheckResult`s, return `ScanResponse`

**Individual (`POST /check/{type}` and `POST /check_deep/{type}`):**
1. Validate and parse `SingleCheckRequest` (single target)
2. Same target validation and scanner dispatch as bundle, but runs one check type
3. Returns `TargetResult` directly (not wrapped in `ScanResponse`)
4. Routes are generated at import time by looping over `CheckType` enum — light checks get `/check/{name}`, deep checks get `/check_deep/{name}` (with `_deep` suffix stripped from the URL slug)

The orchestrator is scanner-agnostic. It dispatches by `CheckType` to whatever function was registered. Adding a scanner requires no changes here.

### Scanner Registry

Module-level dict in `api/scan.py`: `_SCANNERS: dict[CheckType, ScanFn]`. Populated at import time by `app.py`. The orchestrator looks up scanners by `CheckType` — unregistered types return a `CheckResult` with an error string.

Scanner function signature: `async def scan(target: str, timeout: float) -> CheckResult`. See `docs/check_approach.md` for the full contract.

### Shared HTTP Client (`http.py`)

Provides `scanner_client(timeout)` and `fetch_with_fallback(target, client)` used by all HTTP-based scanners (`headers_drheader`, `tech`, `web`). Centralises the HTTPS-first with HTTP-fallback pattern, TLS verification disabled (scanners inspect certs separately), and short connect timeouts (3 s cap).

### Blocklist (`blocklist.py`)

SSRF protection layer. Called before any scanner runs.

- Parses the target via `urllib.parse.urlparse` (handles schemes, IPv6 brackets, ports, encoded characters). Bare IPv6 addresses are detected and wrapped in brackets before parsing.
- If IP: checks against blocked networks. Covers IPv4 private (RFC 1918), loopback, link-local, cloud metadata (169.254.x.x), carrier-grade NAT (100.64.0.0/10), TEST-NETs, multicast, plus IPv6 equivalents including IPv4-mapped (::ffff:0:0/96), unique-local (fc00::/7), and AWS EC2 IPv6 metadata (fd00:ec2::/32).
- If domain: resolves via DNS, checks every resolved IP against the same blocklist
- Raises `BlockedTargetError` (→ HTTP 400) or `InvalidTargetError` (→ HTTP 422), caught by global exception handlers in `app.py`

### Config (`config.py`)

`pydantic-settings` with `INFRAPROBE_` env prefix. Singleton `settings` instance.

| Setting | Default | Env var |
|---------|---------|---------|
| `env` | `"development"` | `INFRAPROBE_ENV` |
| `log_level` | `"info"` | `INFRAPROBE_LOG_LEVEL` |
| `port` | `8080` | `INFRAPROBE_PORT` |
| `scanner_timeout` | `10.0` | `INFRAPROBE_SCANNER_TIMEOUT` |
| `deep_scanner_timeout` | `30.0` | `INFRAPROBE_DEEP_SCANNER_TIMEOUT` |

---

## Data Model

```
ScanRequest                    SingleCheckRequest
├── targets: list[str] (1-10)  └── target: str
└── checks: list[CheckType]

ScanResponse                   TargetResult
└── results: list[TargetResult] ├── target: str
                               ├── results: dict[str, CheckResult]
CheckResult                    └── duration_ms: int
├── check: CheckType
├── findings: list[Finding]
├── raw: dict[str, Any]
└── error: str | None

Finding
├── severity: Severity
├── title: str
├── description: str
└── details: dict[str, Any]
```

Enums: `Severity` (critical, high, medium, low, info), `CheckType` (ssl, ssl_deep, headers, dns, dns_deep, tech, tech_deep, blacklist, web).

`POST /v1/scan` uses `ScanRequest` → `ScanResponse`. `POST /v1/check/{type}` and `POST /v1/check_deep/{type}` use `SingleCheckRequest` → `TargetResult`.

`CheckResult.error` is the discriminator: if null, `findings` and `raw` are valid. If set, the scanner failed and `findings` is empty.

---

## Concurrency

Two-level fan-out, both using `asyncio.gather`:

```
POST /v1/scan {targets: [A, B], checks: [headers, ssl]}

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

Max concurrency for bundle: 10 targets x 8 check types = 80 tasks. Individual check endpoints run 1 task. All I/O-bound (HTTP, DNS, TLS handshakes). No semaphore or pool — not needed at this scale.

Total latency per request ≈ `max(scanner_timeout)` + scheduling overhead, not the sum.

---

## Timeout Model

Single enforcement point: `_run_scanner()` wraps each scanner call in `asyncio.wait_for(fn(target, budget), timeout=budget + SCHEDULING_BUFFER)`.

- `budget` = `settings.scanner_timeout` (default 10s) for light checks, `settings.deep_scanner_timeout` (default 30s) for deep checks
- `SCHEDULING_BUFFER` = 0.5s (covers asyncio task-switch latency only — scanners must respect their own timeout budget internally)
- Scanners pass `budget` to their I/O libraries as a soft hint
- If a scanner exceeds budget + buffer, `wait_for` cancels it and the orchestrator returns `CheckResult(error="timed out")`

Scanners never call `wait_for` on themselves. See `docs/check_approach.md` for the full timeout contract.

---

## Error Model

| Source | Scope | HTTP | Mechanism |
|--------|-------|------|-----------|
| Invalid/blocked target | Whole request | 400/422 | Global exception handlers in `app.py` catch `BlockedTargetError`/`InvalidTargetError` |
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

**Deployed:** Live on Google Cloud Run. URL stored in `.envs/deployed.url`, RapidAPI proxy secret in `.envs/rapidapi_proxy_secret.txt`. CI/CD pipeline pushes on every `main` merge.

**Deployment verification:** `scripts/verify_deploy.py` tests all endpoints against a live instance — health, every light and deep scanner, bundle/domain/IP scans, async job flow (submit → poll → report), output formats (JSON, SARIF, CSV), error handling (SSRF block, validation), and auth enforcement. Reads URL and secret from `.envs/` by default; also supports `uv run python scripts/verify_deploy.py http://localhost:8080` for local dev.

**Implemented scanners:** `headers`, `ssl`, `ssl_deep`, `dns`, `dns_deep`, `tech`, `tech_deep`, `blacklist`, `blacklist_deep`, `web`, `whois`, `ports`, `ports_deep`, `cve` — all registered and accessible via both bundle and individual endpoints. `web`, `ports`, `ports_deep`, and `cve` are opt-in (not in default checks).

**Deferred (YAGNI):** retry logic, circuit breakers, connection pooling, caching, rate limiting, structured logging. Add when there's a concrete need. See `docs/check_approach.md` for the full list.
