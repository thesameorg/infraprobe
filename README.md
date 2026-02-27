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

Individual check endpoints are also available under `/v1/check/{type}` for all 12 scanner types (headers, ssl, ssl_deep, dns, dns_deep, tech, blacklist, blacklist_deep, web, whois, ports, cve).

| Check | Description | In bundle scan |
|-------|-------------|----------------|
| `headers` | Missing security headers, info-leaking headers | Yes |
| `ssl` | TLS certificate, protocols, ciphers | Yes |
| `dns` | DNS records, SPF, DMARC | Yes (domains) |
| `web` | CORS, exposed paths, mixed content, security.txt | Yes |
| `whois` | Domain registration and expiry | Yes (domains) |
| `ssl_deep` | Deep SSLyze analysis | No — `/v1/check/ssl_deep` |
| `dns_deep` | Deep checkdmarc analysis | No — `/v1/check/dns_deep` |
| `tech` | Technology fingerprinting (Wappalyzer) | No — `/v1/check/tech` |
| `blacklist` / `blacklist_deep` | DNSBL checking | No — `/v1/check/blacklist` |
| `ports` | Port scanning — nmap top-20 | No — `/v1/check/ports` |
| `cve` | CVE detection — nmap + NVD API | No — `/v1/check/cve` |

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

# Single check (inline result)
curl -X POST localhost:8080/v1/check/headers \
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
| `INFRAPROBE_NVD_API_KEY` | For CVE scanner | NVD API key |
| `INFRAPROBE_JOB_STORE_BACKEND` | No | `memory` (default) or `firestore` |
| `INFRAPROBE_FIRESTORE_PROJECT` | If firestore | GCP project ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | If firestore locally | Path to SA key JSON |

### Running with Firestore locally

```bash
GOOGLE_APPLICATION_CREDENTIALS=.envs/gcloud_service_key.json \
INFRAPROBE_JOB_STORE_BACKEND=firestore \
INFRAPROBE_FIRESTORE_PROJECT=infrascan-487213 \
INFRAPROBE_DEV_BYPASS_AUTH=true \
uv run python main.py
```

### Running Firestore tests

```bash
# Against real Firestore
GOOGLE_APPLICATION_CREDENTIALS=.envs/gcloud_service_key.json \
INFRAPROBE_FIRESTORE_PROJECT=infrascan-487213 \
uv run pytest tests/test_storage_firestore.py -v

# Against emulator (CI uses this)
docker compose --profile firestore up firestore -d
FIRESTORE_EMULATOR_HOST=localhost:8686 uv run pytest tests/test_storage_firestore.py -v
```

## Architecture

```
POST /v1/scan         → api/scan.py (orchestrator) → scanners (parallel) → 200
POST /v1/check/{type} → api/scan.py (single check) → one scanner → 200 or 202
GET  /v1/scan/{id}    → JobStore → results (for async individual checks)
```

- Bundle scan is always sync — no job polling needed
- All checks run in parallel via `asyncio.gather`
- SSRF protection via IP blocklist before any scanner runs
- Each scanner is isolated — one failure doesn't affect others
- Timeout enforcement at orchestrator level (budget + 0.5s buffer)
- Job storage: in-memory (dev) or Firestore (production, for async individual checks)
- Deployed on Google Cloud Run with CI/CD via GitHub Actions

See [docs/architecture.md](docs/architecture.md) for full details, [docs/guide/](docs/guide/) for API consumer docs.
