# InfraProbe

Infrastructure security scanning API. Accepts target domains/IPs, runs security checks in parallel, returns structured JSON results with findings and severity summaries.

## What it does

Three endpoint styles, all under `/v1`:

- **`POST /v1/scan`** — bundle endpoint, always async (202). Accepts 1-10 targets, runs selected checks concurrently. Poll `GET /v1/scan/{job_id}` for results.
- **`POST /v1/check/{type}`** — individual check endpoints (e.g. `/v1/check/headers`). Fast checks return 200 inline; slow checks (ports, ports_deep, cve) return 202.
- **`GET /v1/scan/{job_id}`** — poll for job status and results. Supports `?format=sarif|csv` and `?fail_on=high,critical`.

| Check | Description | Default |
|-------|-------------|---------|
| `headers` | Missing security headers, info-leaking headers | Yes |
| `ssl` / `ssl_deep` | TLS certificate, protocols, ciphers / deep SSLyze analysis | Yes / opt-in |
| `dns` / `dns_deep` | DNS records, SPF, DMARC / deep checkdmarc analysis | Yes (domains) / opt-in |
| `tech` | Technology fingerprinting (Wappalyzer) | Yes |
| `blacklist` / `blacklist_deep` | DNSBL checking (2 zones / 15 zones) | Yes / opt-in |
| `whois` | Domain registration and expiry | Yes (domains) |
| `web` | CORS, exposed paths, mixed content, security.txt | Opt-in |
| `ports` / `ports_deep` | Port scanning — nmap top-20 / top-1000 + version detection | Opt-in |
| `cve` | CVE detection — nmap version detection + NVD API | Opt-in |

## Quick start

```bash
# Install dependencies
uv sync

# Run dev server (port 8080, hot reload)
uv run python main.py

# Scan a domain (async — returns job_id)
curl -X POST localhost:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'

# Poll for results
curl localhost:8080/v1/scan/<job_id>

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

## CI/CD gating

```bash
# Fail pipeline if high or critical findings exist (returns 422 if threshold exceeded)
curl "localhost:8080/v1/scan/<job_id>?fail_on=high,critical"
```

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
POST /v1/scan         → api/scan.py (orchestrator) → scanners (parallel) → JobStore → 202
POST /v1/check/{type} → api/scan.py (single check) → one scanner → 200 or 202
GET  /v1/scan/{id}    → JobStore → results
```

- Async-first — bundle scans run in background, poll for results
- SSRF protection via IP blocklist before any scanner runs
- Each scanner is isolated — one failure doesn't affect others
- Timeout enforcement at orchestrator level (budget + 0.5s buffer)
- Job storage: in-memory (dev) or Firestore (production, survives scale-to-zero)
- Deployed on Google Cloud Run with CI/CD via GitHub Actions

See [docs/architecture.md](docs/architecture.md) for full details, [docs/guide/](docs/guide/) for API consumer docs.
