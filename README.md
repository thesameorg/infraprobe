# InfraProbe

Infrastructure security scanning API. Accepts target domains/IPs, runs security checks in parallel, returns scored JSON results with findings.

## Live

Deployed on Google Cloud Run:

```bash
# Health check
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
    https://infraprobe-tzhg2ptrea-uc.a.run.app/health

# Run a scan
curl -X POST -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
    -H "Content-Type: application/json" \
    -d '{"targets": ["example.com"], "checks": ["headers"]}' \
    https://infraprobe-tzhg2ptrea-uc.a.run.app/scan
```

## What it does

**POST /scan** accepts 1-10 targets and runs selected checks concurrently:

| Check | Status | Description |
|-------|--------|-------------|
| `headers` | Implemented | Missing security headers, info-leaking headers, HTTPS detection |
| `ssl` | Planned | TLS certificate, protocol versions, cipher suites |
| `dns` | Planned | DNS security (SPF, DMARC, DNSSEC) |
| `tech` | Planned | Technology fingerprinting |

Results are scored (A+ through F) based on finding severity.

## Local development

```bash
# Install dependencies
uv sync

# Run dev server (port 8080, hot reload)
uv run python main.py

# Run tests
uv run pytest

# Lint & type check
uv run ruff check && uv run ruff format --check
uv run ty check

# Docker
docker compose up
```

## Architecture

```
POST /scan → api/scan.py (orchestrator) → scanners (parallel via asyncio.gather) → scoring → response
```

- Stateless API — no database, no background jobs
- SSRF protection via IP blocklist before any scanner runs
- Each scanner is isolated — one failure doesn't affect others
- Timeout enforcement at orchestrator level (budget + grace)

See [docs/architecture.md](docs/architecture.md) for full details.

## CI/CD

Push to `main` → pytest → build Docker image → push to Artifact Registry → deploy to Cloud Run.
