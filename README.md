# InfraProbe

Infrastructure security scanning API. Accepts target domains/IPs, runs security checks in parallel, returns scored JSON results with findings.

## What it does

Two endpoint styles, all under `/v1`:

- **`POST /v1/scan`** — bundle endpoint. Accepts 1-10 targets and runs selected checks concurrently.
- **`POST /v1/check/{type}`** — individual endpoints per scanner (e.g. `/v1/check/headers`). Single target, single check.

| Check | Description |
|-------|-------------|
| `headers` | Missing security headers, info-leaking headers, HTTPS detection |
| `ssl` | TLS certificate, protocol versions, cipher suites |
| `ssl_deep` | Deep SSL analysis via SSLyze (protocols, vulnerabilities) |
| `dns` | DNS records, SPF, DMARC |
| `dns_deep` | Deep DNS analysis via checkdmarc (SPF/DMARC/DNSSEC) |
| `tech` | Technology fingerprinting |
| `tech_deep` | Deep tech detection via Wappalyzer |
| `blacklist` | DNSBL blacklist checking |

Results are scored (A+ through F) based on finding severity.

## Output formats

All endpoints accept a `?format=` query parameter:

| Format | Content-Type | Description |
|--------|-------------|-------------|
| `json` (default) | `application/json` | Standard JSON response |
| `sarif` | `application/sarif+json` | [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for GitHub Security tab and CI/CD pipelines |

```bash
# Default JSON
curl -X POST localhost:8080/v1/scan -d '{"targets":["example.com"],"checks":["headers"]}'

# SARIF output
curl -X POST "localhost:8080/v1/scan?format=sarif" -d '{"targets":["example.com"],"checks":["headers"]}'

# Works on single-check endpoints too
curl -X POST "localhost:8080/v1/check/headers?format=sarif" -d '{"target":"example.com"}'
```

Error responses (400, 422) are always JSON regardless of the format parameter.

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
POST /v1/scan           → api/scan.py (orchestrator) → scanners (parallel) → scoring → response
POST /v1/check/{type}   → api/scan.py (single check) → one scanner → scoring → response
```

- Stateless API — no database, no background jobs
- SSRF protection via IP blocklist before any scanner runs
- Each scanner is isolated — one failure doesn't affect others
- Timeout enforcement at orchestrator level (budget + grace)

See [docs/architecture.md](docs/architecture.md) for full details.
