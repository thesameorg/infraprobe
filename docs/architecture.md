# Architecture

Technical architecture for InfraProbe. Covers system design, component structure, data flow, and deployment.

---

## System Overview

InfraProbe is an HTTP API that runs security checks against infrastructure targets. Single endpoint under `/v1`:

- **`POST /v1/scan`** — bundle endpoint. Accepts a single `target`, runs a fixed set of checks based on target type (domains: headers/ssl/dns/web/whois; IPs: headers/ssl/web). Always returns **200** with inline results. Supports `format` field in request body: `json` (default), `sarif`, `csv`.

No unversioned routes — all access goes through `/v1`.

```
Client
  │
  │  POST /v1/scan {target}
  ▼
┌──────────────────────────────────────────────────┐
│  FastAPI (ASGI)                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  api/scan.py — Orchestrator                │  │
│  │  ┌────────────────────────────┐            │  │
│  │  │ Target                     │            │  │
│  │  │ ┌───────┐ ┌─────┐ ┌─────┐ │  asyncio   │  │
│  │  │ │ hdrs  │ │ ssl │ │ dns │ │  .gather() │  │
│  │  │ │ web   │ │whois│ │     │ │            │  │
│  │  │ └───────┘ └─────┘ └─────┘ │            │  │
│  │  └────────────────────────────┘            │  │
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
├── app.py              # FastAPI instance, scanner registration, exception handlers, /health, /health/ready, /metrics
├── config.py           # pydantic-settings (INFRAPROBE_ env prefix), scan_semaphore
├── models.py           # Pydantic models + enums (Severity, CheckType, ErrorResponse)
├── metrics.py          # Prometheus metrics (request count/duration, scanner duration, active scans)
├── blocklist.py        # SSRF protection: block private/reserved IPs (urllib.parse-based)
├── target.py           # parse_target(), build_context() — URL/host/IPv6 normalization + DNS resolution
├── http.py             # Shared HTTP client (scanner_client, fetch_with_fallback)
├── logging.py          # Structured JSON logging configuration
├── api/
│   └── scan.py         # POST /v1/scan, orchestrator, scanner registry
├── formatters/
│   ├── sarif.py        # SARIF 2.1.0 output formatter
│   └── csv.py          # CSV output formatter
└── scanners/
    ├── headers_drheader.py  # HTTP security headers check (drheaderplus)
    ├── ssl.py          # SSL/TLS certificate and cipher check
    ├── dns.py          # DNS security records check
    ├── web.py          # Web security (CORS, exposed paths, mixed content, robots.txt, security.txt)
    └── whois_scanner.py # WHOIS domain registration and expiry

scripts/
└── verify_deploy.py    # Deployment verification — hits scan endpoint, reports pass/fail
```

Build: `hatchling` backend, installable as `infraprobe` wheel. Entry point for dev: `main.py` (runs uvicorn with reload).

---

## Components

### App (`app.py`)

Creates the FastAPI instance. Registers scanners into the module-level registry in `api/scan.py` via `register_scanner(CheckType, scan_fn)`. Mounts the scan router under `/v1`. Exposes `GET /health` (liveness), `GET /health/ready` (readiness), and `GET /metrics` (Prometheus). Infrastructure paths (`/health`, `/health/ready`, `/metrics`) are excluded from logging and auth middleware.

Global exception handlers return consistent `{"error": "<code>", "detail": "<message>"}` shapes: `BlockedTargetError` → 400 `blocked_target`, `InvalidTargetError` → 422 `invalid_target`, unhandled `Exception` → 500 `internal_error`.

Optional RapidAPI proxy-secret middleware is enabled when `INFRAPROBE_RAPIDAPI_PROXY_SECRET` is set, unless `INFRAPROBE_DEV_BYPASS_AUTH=true` which disables authentication entirely (for local development).

### Orchestrator (`api/scan.py`)

Owns the full lifecycle of a scan request:

1. Validate and parse `SingleCheckRequest` (Pydantic) — just `target` + optional `auth`
2. Resolve checks from target type: `DOMAIN_CHECKS` (headers, ssl, dns, web, whois) or `IP_CHECKS` (headers, ssl, web)
3. Validate target through `blocklist.validate_target()` — rejects private IPs (SSRF protection) and unresolvable domains
4. Fan out: `asyncio.gather` over all checks for the target
5. Each check runs through `_run_scanner()`, which wraps the scanner call in `asyncio.wait_for(fn, timeout=budget + SCHEDULING_BUFFER)` — the single timeout enforcement point
6. Return `ScanResponse` inline (200)

The orchestrator is scanner-agnostic: it dispatches by `CheckType` to whatever function was registered. Adding a scanner requires no changes here.

### Scanner Registry

Module-level dict in `api/scan.py`: `_SCANNERS: dict[CheckType, ScanFn]`. Populated at import time by `app.py`. The orchestrator looks up scanners by `CheckType` — unregistered types return a `CheckResult` with an error string.

Scanner function signature: `async def scan(target: str, timeout: float) -> CheckResult`. See `docs/check_approach.md` for the full contract.

### Shared HTTP Client (`http.py`)

Provides `scanner_client(timeout)` and `fetch_with_fallback(target, client)` used by all HTTP-based scanners (`headers_drheader`, `web`). Centralises the HTTPS-first with HTTP-fallback pattern, TLS verification disabled (scanners inspect certs separately), and short connect timeouts (3 s cap). `scanner_client` accepts `follow_redirects` (default `True`); the headers scanner uses `follow_redirects=False` to analyze the target's own response headers rather than a redirect destination's.

### Blocklist (`blocklist.py`)

SSRF protection layer. Called before any scanner runs.

- Parses the target via `urllib.parse.urlparse` (handles schemes, IPv6 brackets, ports, encoded characters). Bare IPv6 addresses are detected and wrapped in brackets before parsing.
- If IP: checks against blocked networks. Covers IPv4 private (RFC 1918), loopback, link-local, cloud metadata (169.254.x.x), carrier-grade NAT (100.64.0.0/10), TEST-NETs, multicast, plus IPv6 equivalents including IPv4-mapped (::ffff:0:0/96), unique-local (fc00::/7), and AWS EC2 IPv6 metadata (fd00:ec2::/32).
- If domain: resolves via DNS, checks every resolved IP against the same blocklist
- Raises `BlockedTargetError` (→ HTTP 400) or `InvalidTargetError` (→ HTTP 422), caught by global exception handlers in `app.py`

### Config (`config.py`)

`pydantic-settings` with `INFRAPROBE_` env prefix. Singleton `settings` instance. All numeric settings have `Field` constraints (`gt=0`, `ge=1`, etc.) to reject invalid values at startup. `log_level` is validated against Python's logging levels.

| Setting | Default | Env var | Constraint |
|---------|---------|---------|------------|
| `env` | `"development"` | `INFRAPROBE_ENV` | — |
| `log_level` | `"info"` | `INFRAPROBE_LOG_LEVEL` | valid Python log level |
| `port` | `8080` | `INFRAPROBE_PORT` | `ge=1, le=65535` |
| `scanner_timeout` | `10.0` | `INFRAPROBE_SCANNER_TIMEOUT` | `gt=0` |
| `dev_bypass_auth` | `false` | `INFRAPROBE_DEV_BYPASS_AUTH` | — |
| `max_concurrent_scans` | `5` | `INFRAPROBE_MAX_CONCURRENT_SCANS` | `ge=1, le=50` |

---

## Data Model

```
SingleCheckRequest (API input)
└── target: TargetStr (max 2048 chars)
    auth: AuthConfig | None (excluded from dumps)

ScanResponse                   TargetResult
├── results: list[TargetResult] ├── target: str
└── summary: SeveritySummary   ├── results: dict[str, CheckResult]
                               ├── duration_ms: int
CheckResult                    └── summary: SeveritySummary
├── check: CheckType
├── findings: list[Finding]     SeveritySummary
├── raw: dict[str, Any]         ├── critical/high/medium/low/info: int
└── error: str | None           └── total: int

Finding
├── severity: Severity
├── title: str
├── description: str
└── details: dict[str, Any]
```

Enums: `Severity` (critical, high, medium, low, info), `CheckType` (ssl, headers, dns, web, whois).

`POST /v1/scan` uses `SingleCheckRequest` → `ScanResponse` (always 200).

`CheckResult.error` is the discriminator: if null, `findings` and `raw` are valid. If set, the scanner failed and `findings` is empty.

---

## Concurrency

Single-level fan-out using `asyncio.gather`:

```
POST /v1/scan {target: "example.com"}

_scan_target(example.com, [headers, ssl, dns, web, whois]):
    gather(
        _run_scanner(headers, example.com, 10s),  # parallel
        _run_scanner(ssl, example.com, 10s),      # parallel
        _run_scanner(dns, example.com, 10s),      # parallel
        _run_scanner(web, example.com, 10s),      # parallel
        _run_scanner(whois, example.com, 10s),    # parallel
    )
```

Max concurrency for bundle: 5 checks (domains) or 3 checks (IPs). All I/O-bound (HTTP, DNS, TLS handshakes).

**Scan semaphore:** A global `asyncio.Semaphore` (from `config.scan_semaphore()`, default 5) limits concurrent `_scan_target()` calls to prevent event loop starvation under load.

Total latency per request ≈ `max(scanner_timeout)` + scheduling overhead, not the sum.

---

## Timeout Model

Single enforcement point: `_run_scanner()` wraps each scanner call in `asyncio.wait_for(fn(target, budget), timeout=budget + SCHEDULING_BUFFER)`.

- `budget` = `settings.scanner_timeout` (default 10s)
- `SCHEDULING_BUFFER` = 0.5s (covers asyncio task-switch latency only — scanners must respect their own timeout budget internally)
- Scanners pass `budget` to their I/O libraries as a soft hint
- If a scanner exceeds budget + buffer, `wait_for` cancels it and the orchestrator returns `CheckResult(error="timed out")`

Scanners never call `wait_for` on themselves. See `docs/check_approach.md` for the full timeout contract.

---

## Error Model

All error responses use a consistent shape: `{"error": "<code>", "detail": "<message>"}`. The `detail` key is preserved for backward compatibility; the `error` key provides a machine-readable code.

| Source | Scope | HTTP | Error code | Mechanism |
|--------|-------|------|------------|-----------|
| Blocked target | Whole request | 400 | `blocked_target` | Global exception handler |
| Invalid target | Whole request | 422 | `invalid_target` | Global exception handler |
| Auth rejected | Whole request | 403 | `forbidden` | RapidAPI middleware |
| Unhandled error | Whole request | 500 | `internal_error` | Catch-all handler |
| Scanner not registered | Single check | 200 | — | `CheckResult(error=...)` |
| Scanner timeout | Single check | 200 | — | `wait_for` cancels, `CheckResult(error=...)` |
| Scanner exception | Single check | 200 | — | Catch `Exception`, `CheckResult(error=...)` |

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
       ├── uv sync
       ├── pip-audit (dependency vulnerability scanning)
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

Local dev: `docker-compose.yaml` maps host port 8000 to container port 8080.

---

## Current State

**Deployed:** Live on Google Cloud Run. URL stored in `.envs/deployed.url`, RapidAPI proxy secret in `.envs/rapidapi_proxy_secret.txt`. CI/CD pipeline pushes on every `main` merge.

**Deployment verification:** `scripts/verify_deploy.py` tests scan endpoint against a live instance — health, bundle scan (domain + IP), target auto-detection, output formats (JSON, SARIF, CSV), error handling (SSRF block, validation), and auth enforcement.

**Implemented scanners:** `headers`, `ssl`, `dns`, `web`, `whois` — all registered and run as part of the bundle scan (`POST /v1/scan`).

**Deferred (YAGNI):** retry logic, circuit breakers, connection pooling, caching, rate limiting. Add when there's a concrete need. See `docs/check_approach.md` for the full list.

**User-facing docs:** `docs/guide/` contains API consumer documentation — check descriptions, endpoint examples, output formats, and troubleshooting.

---

## Hardening

Production robustness measures implemented:

- **Config validation:** All numeric settings have Pydantic `Field` constraints; invalid values (e.g. `scanner_timeout=0`) are rejected at startup. `log_level` validated against Python's logging levels.
- **Input limits:** `TargetStr` type enforces `max_length=2048` on all target strings to prevent DoS via oversized payloads.
- **Consistent error shapes:** All error responses use `{"error": "<code>", "detail": "<message>"}`. Catch-all `Exception` handler returns 500 `internal_error`.
- **Scan concurrency:** `asyncio.Semaphore` (configurable, default 5) limits concurrent `_scan_target()` calls to prevent event loop starvation under load.
- **Readiness probe:** `GET /health/ready` returns 200. Separate from liveness (`GET /health`).
- **Prometheus metrics:** `GET /metrics` exposes request count/duration, scanner duration, and active scan gauges. Compatible with Cloud Run metrics scraping and any Prometheus-compatible collector.
- **Dependency scanning:** `pip-audit` runs in CI before tests to catch known vulnerabilities in dependencies.
