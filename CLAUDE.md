# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is InfraProbe

Infrastructure security scanning API built with FastAPI. Accepts target domains/IPs via `POST /scan`, runs security checks (headers, SSL, DNS, tech detection) in parallel, and returns scored JSON results with findings. Designed as an API-first product for CI/CD integration.

## Commands

```bash
# Install dependencies (uses uv, not pip)
uv sync

# Run dev server (hot reload on port 8080)
uv run python main.py

# Run all tests
uv run pytest

# Run a single test
uv run pytest tests/test_scan.py::test_scan_headers_vulnweb

# Lint
uv run ruff check
uv run ruff format --check

# Type check
uv run ty check

# Auto-fix lint issues
uv run ruff check --fix
uv run ruff format

# Docker
docker compose up
```

## Architecture

**Package layout:** `src/infraprobe/` (hatchling build, wheel package = `src/infraprobe`)

**Request flow:** `app.py` → `api/scan.py` (router + orchestrator) → individual scanners → `scoring.py` → response

**Scanner registry pattern:** Scanners are registered in `app.py` via `register_scanner(CheckType, scan_fn)`. The scan router dispatches to registered scanners by check type. Unregistered scanners return graceful errors. Each scanner is `async def scan(target: str, timeout: float) -> CheckResult`.

**Key modules:**
- `app.py` — FastAPI app, scanner registration, health endpoint
- `api/scan.py` — POST /scan route, scanner orchestration with `asyncio.gather`, timeout wrapping
- `scanners/headers.py` — HTTP security headers check (currently the only implemented scanner)
- `models.py` — All Pydantic models: `ScanRequest`, `CheckResult`, `Finding`, `TargetResult`, `ScanResponse`; severity/check enums
- `scoring.py` — Points-based scoring (100 base, deductions per severity) → letter grade (A+ through F)
- `blocklist.py` — SSRF protection: blocks private/reserved IP ranges, resolves domains before checking
- `config.py` — `pydantic-settings` with `INFRAPROBE_` env prefix

**CheckType enum defines planned scanners:** `ssl`, `headers`, `dns`, `tech` — only `headers` is implemented so far.

## Conventions

- Python 3.12, ruff for linting/formatting (line-length=120)
- `ty` for type checking
- Async-first: scanners are async, run in parallel via `asyncio.gather`
- Tests use `fastapi.testclient.TestClient` (sync wrapper); `pytest-asyncio` with `asyncio_mode = "auto"`
- Integration tests hit real external targets (e.g., `testphp.vulnweb.com`) — avoid mocks
- Settings via env vars with `INFRAPROBE_` prefix (see `config.py`)
- uv as package manager (not pip), lockfile at `uv.lock`

## CI/CD

- **CI:** ruff check + ruff format --check + ty check + pytest (GitHub Actions)
- **Deploy:** Push to main → build Docker image → push to GHCR → deploy to Google Cloud Run
