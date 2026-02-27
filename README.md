# InfraProbe

Infrastructure security scanning API. Send a domain or IP, get structured security findings back. One endpoint, one request, one response.

## What it does

**`POST /v1/scan`** — send a target, get security results. Always returns `200` with inline results.

- **Domains** get: headers, ssl, dns, web, whois
- **IPs** get: headers, ssl, web

All checks run in parallel. P95 wall-clock ~5s.

```bash
curl -X POST localhost:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

| Check | Description | Targets |
|-------|-------------|---------|
| `headers` | Missing security headers, info-leaking headers | All |
| `ssl` | TLS certificate, protocols, ciphers | All |
| `dns` | DNS records, SPF, DMARC | Domains only |
| `web` | CORS, exposed paths, mixed content, security.txt | All |
| `whois` | Domain registration and expiry | Domains only |

## Quick start

```bash
# Install dependencies
uv sync

# Run dev server (port 8080, hot reload)
uv run python main.py

# Scan a domain — returns 200 with results
curl -X POST localhost:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# SARIF output
curl -X POST "localhost:8080/v1/scan?format=sarif" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

## Output formats

| Format | Query param | Content-Type |
|--------|------------|-------------|
| JSON (default) | `?format=json` | `application/json` |
| SARIF 2.1.0 | `?format=sarif` | `application/sarif+json` |
| CSV | `?format=csv` | `text/csv` |

## Local development

```bash
uv sync                                    # install deps
uv run python main.py                      # dev server (port 8080)
uv run pytest                              # tests
uv run ruff check && uv run ruff format --check  # lint
uv run ty check                            # type check
docker compose up                          # docker
```

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `INFRAPROBE_DEV_BYPASS_AUTH` | For local dev | Set `true` to skip auth |
| `INFRAPROBE_RAPIDAPI_PROXY_SECRET` | Production | RapidAPI proxy secret |

## Architecture

```
POST /v1/scan → api/scan.py (orchestrator) → scanners (parallel) → 200
```

- Always sync — no job polling needed
- All checks run in parallel via `asyncio.gather`
- SSRF protection via IP blocklist before any scanner runs
- Each scanner is isolated — one failure doesn't affect others
- Timeout enforcement at orchestrator level (budget + 0.5s buffer)
- Deployed on Google Cloud Run with CI/CD via GitHub Actions

See [docs/architecture.md](docs/architecture.md) for full details, [docs/guide/](docs/guide/) for API consumer docs.
