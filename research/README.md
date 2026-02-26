# Research

Scanner validation, benchmarks, and target management.

## Targets

**`targets.json`** — curated scan targets used across benchmarks and integration tests. Categories:
- `scan_me` — explicitly permit scanning (scanme.nmap.org, vulnweb, testfire)
- `hardened` — well-configured production sites (cloudflare, github, stripe)
- `interesting` — various security postures (example.com, neverssl, wordpress)
- `badssl` — intentional SSL misconfigs (expired, self-signed, wrong host, legacy TLS)
- `ips` — public DNS/infra IPs with known open ports
- `nmap_subset` — small set for slow nmap-based checks

## Benchmarks

**`benchmark_scanners.py`** — measures per-scanner latency (p50/p75/p90/p95/p99/mean).

```bash
uv run python research/benchmark_scanners.py                # all phases
uv run python research/benchmark_scanners.py --phase smoke   # fast checks only
uv run python research/benchmark_scanners.py --phase medium  # deep inline checks
uv run python research/benchmark_scanners.py --phase long    # nmap-based slow checks
```

Results saved to `benchmark_results/` (CSV + JSON + Markdown summary).

## Validation Scripts

Per-scanner correctness checks against known targets:
- `validate_headers.py`, `validate_ssl.py`, `validate_dns.py`, `validate_tech.py`
- `run_all.py` — runs all validators and reports summary
