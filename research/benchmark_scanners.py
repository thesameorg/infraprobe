#!/usr/bin/env python3
"""
Scanner latency benchmark — measures p50/p75/p90/p95/p99/mean for each scanner.

Calls scanner functions directly (no webserver). Sequential execution only.
Phases: smoke → medium → long/heavy.

Usage:
    uv run python research/benchmark_scanners.py
    uv run python research/benchmark_scanners.py --phase smoke
    uv run python research/benchmark_scanners.py --phase medium
    uv run python research/benchmark_scanners.py --phase long
    uv run python research/benchmark_scanners.py --phase all      # default
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import math
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Adjust sys.path so we can import infraprobe directly
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from infraprobe.models import AuthConfig, CheckResult, CheckType  # noqa: E402
from infraprobe.target import build_context  # noqa: E402

# ---------------------------------------------------------------------------
# Import all scanner functions
# ---------------------------------------------------------------------------
from infraprobe.scanners.headers_drheader import scan as headers_scan  # noqa: E402
from infraprobe.scanners.ssl import scan as ssl_scan  # noqa: E402
from infraprobe.scanners.dns import scan as dns_scan  # noqa: E402
from infraprobe.scanners.tech import scan as tech_scan  # noqa: E402
from infraprobe.scanners.blacklist import scan as blacklist_scan  # noqa: E402
from infraprobe.scanners.blacklist import scan_deep as blacklist_deep_scan  # noqa: E402
from infraprobe.scanners.web import scan as web_scan  # noqa: E402
from infraprobe.scanners.whois_scanner import scan as whois_scan  # noqa: E402
from infraprobe.scanners.ports import scan as ports_scan  # noqa: E402
from infraprobe.scanners.cve import scan as cve_scan  # noqa: E402
from infraprobe.scanners.deep.ssl import scan as ssl_deep_scan  # noqa: E402
from infraprobe.scanners.deep.dns import scan as dns_deep_scan  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BENCHMARK_TIMEOUT = 30.0  # seconds per individual check
RESULTS_DIR = Path(__file__).resolve().parent / "benchmark_results"

# ---------------------------------------------------------------------------
# Target pools — loaded from targets.json
# ---------------------------------------------------------------------------
_TARGETS_FILE = Path(__file__).resolve().parent / "targets.json"


def _load_targets() -> dict[str, list[str]]:
    """Load target pools from targets.json."""
    with open(_TARGETS_FILE) as f:
        data = json.load(f)
    pools: dict[str, list[str]] = {}
    for key, section in data.items():
        if key.startswith("_"):
            continue
        pools[key] = [t["target"] for t in section["targets"]]
    return pools


_POOLS = _load_targets()

DOMAIN_TARGETS = _POOLS["scan_me"] + _POOLS["hardened"] + _POOLS["interesting"] + _POOLS["badssl"]
IP_TARGETS = _POOLS["ips"]
PORT_TARGETS = [t for t in DOMAIN_TARGETS if ":" in t]  # extract port-bearing targets
DOMAIN_TARGETS = [t for t in DOMAIN_TARGETS if ":" not in t]  # strip port targets from domains
NMAP_TARGETS = _POOLS["nmap_subset"]

# ---------------------------------------------------------------------------
# Scanner registry
# ---------------------------------------------------------------------------
@dataclass
class ScannerSpec:
    name: str
    check_type: CheckType
    fn: Any  # async callable
    supports_auth: bool = False
    # Which target pools to use
    use_domains: bool = True
    use_ips: bool = False
    use_port_targets: bool = False
    use_nmap_targets: bool = False  # smaller curated set for slow nmap scans
    # Phase assignment
    phase: str = "smoke"  # smoke | medium | long


SCANNERS: list[ScannerSpec] = [
    # --- SMOKE: fast, lightweight checks ---
    ScannerSpec("headers", CheckType.HEADERS, headers_scan, supports_auth=True,
                use_domains=True, use_ips=False, phase="smoke"),
    ScannerSpec("ssl", CheckType.SSL, ssl_scan,
                use_domains=True, use_ips=False, phase="smoke"),
    ScannerSpec("dns", CheckType.DNS, dns_scan,
                use_domains=True, use_ips=False, phase="smoke"),
    ScannerSpec("tech", CheckType.TECH, tech_scan, supports_auth=True,
                use_domains=True, use_ips=False, phase="smoke"),
    ScannerSpec("blacklist", CheckType.BLACKLIST, blacklist_scan,
                use_domains=True, use_ips=True, phase="smoke"),
    ScannerSpec("whois", CheckType.WHOIS, whois_scan,
                use_domains=True, use_ips=False, phase="smoke"),

    # --- MEDIUM: deeper checks that still return inline ---
    ScannerSpec("web", CheckType.WEB, web_scan, supports_auth=True,
                use_domains=True, use_ips=False, phase="medium"),
    ScannerSpec("ssl_deep", CheckType.SSL_DEEP, ssl_deep_scan,
                use_domains=True, use_ips=False, use_port_targets=True, phase="medium"),
    ScannerSpec("dns_deep", CheckType.DNS_DEEP, dns_deep_scan,
                use_domains=True, use_ips=False, phase="medium"),
    ScannerSpec("blacklist_deep", CheckType.BLACKLIST_DEEP, blacklist_deep_scan,
                use_domains=True, use_ips=True, phase="medium"),

    # --- LONG: nmap-based, genuinely slow ---
    ScannerSpec("ports", CheckType.PORTS, ports_scan,
                use_domains=False, use_ips=True, use_nmap_targets=True, phase="long"),
    ScannerSpec("cve", CheckType.CVE, cve_scan,
                use_domains=False, use_ips=True, use_nmap_targets=True, phase="long"),
]

# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    scanner: str
    target: str
    duration_ms: float
    success: bool
    error: str | None = None
    findings_count: int = 0
    timeout_hit: bool = False


@dataclass
class ScannerStats:
    scanner: str
    phase: str
    runs: int = 0
    successes: int = 0
    errors: int = 0
    timeouts: int = 0
    durations_ms: list[float] = field(default_factory=list)

    @staticmethod
    def _percentile(data: list[float], pct: float) -> float:
        """Linear interpolation percentile (matches numpy default)."""
        if not data:
            return 0.0
        s = sorted(data)
        k = (len(s) - 1) * (pct / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return s[int(k)]
        return s[f] * (c - k) + s[c] * (k - f)

    @property
    def p50(self) -> float:
        return self._percentile(self.durations_ms, 50)

    @property
    def p75(self) -> float:
        return self._percentile(self.durations_ms, 75)

    @property
    def p90(self) -> float:
        return self._percentile(self.durations_ms, 90)

    @property
    def p95(self) -> float:
        return self._percentile(self.durations_ms, 95)

    @property
    def p99(self) -> float:
        return self._percentile(self.durations_ms, 99)

    @property
    def mean(self) -> float:
        return statistics.mean(self.durations_ms) if self.durations_ms else 0.0

    @property
    def min_ms(self) -> float:
        return float(min(self.durations_ms)) if self.durations_ms else 0

    @property
    def max_ms(self) -> float:
        return float(max(self.durations_ms)) if self.durations_ms else 0


# ---------------------------------------------------------------------------
# Target resolution helper
# ---------------------------------------------------------------------------
async def resolve_target(raw: str) -> str:
    """Resolve target to ScanContext string, same as the real scan pipeline."""
    try:
        ctx = await build_context(raw)
        return str(ctx)
    except Exception:
        # If we can't resolve, just return raw — the scanner will handle the error
        return raw


# ---------------------------------------------------------------------------
# Single run
# ---------------------------------------------------------------------------
async def run_single(
    spec: ScannerSpec, target_raw: str, timeout: float = BENCHMARK_TIMEOUT
) -> RunResult:
    """Run a single scanner against a single target, measure wall time."""
    # Resolve target like the real pipeline does
    target = await resolve_target(target_raw)

    start = time.monotonic()
    try:
        result: CheckResult = await asyncio.wait_for(
            spec.fn(target, timeout, None),
            timeout=timeout + 1.0,  # small buffer like _SCHEDULING_BUFFER
        )
        elapsed_ms = (time.monotonic() - start) * 1000
        return RunResult(
            scanner=spec.name,
            target=target_raw,
            duration_ms=elapsed_ms,
            success=result.error is None,
            error=result.error,
            findings_count=len(result.findings),
        )
    except asyncio.TimeoutError:
        elapsed_ms = (time.monotonic() - start) * 1000
        return RunResult(
            scanner=spec.name,
            target=target_raw,
            duration_ms=elapsed_ms,
            success=False,
            error="TIMEOUT",
            timeout_hit=True,
        )
    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        return RunResult(
            scanner=spec.name,
            target=target_raw,
            duration_ms=elapsed_ms,
            success=False,
            error=f"{type(exc).__name__}: {exc}",
        )


# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------
def get_targets_for_scanner(spec: ScannerSpec) -> list[str]:
    """Build the target list for a scanner based on its configuration."""
    targets: list[str] = []
    if spec.use_nmap_targets:
        targets.extend(NMAP_TARGETS)
    elif spec.use_domains:
        targets.extend(DOMAIN_TARGETS)
    if spec.use_ips:
        targets.extend(IP_TARGETS)
    if spec.use_port_targets:
        targets.extend(PORT_TARGETS)
    return targets


async def run_phase(phase: str, repeat: int = 1) -> tuple[list[RunResult], list[ScannerStats]]:
    """Run all scanners in a given phase, sequentially."""
    phase_scanners = [s for s in SCANNERS if s.phase == phase]
    if not phase_scanners:
        print(f"  No scanners in phase '{phase}'")
        return [], []

    all_results: list[RunResult] = []
    stats_map: dict[str, ScannerStats] = {}

    for spec in phase_scanners:
        targets = get_targets_for_scanner(spec)
        stats = ScannerStats(scanner=spec.name, phase=phase)
        stats_map[spec.name] = stats

        print(f"\n  [{spec.name}] {len(targets)} targets x {repeat} repeats = {len(targets) * repeat} runs")

        for iteration in range(repeat):
            for i, target in enumerate(targets):
                label = f"    [{iteration+1}/{repeat}] [{i+1}/{len(targets)}] {spec.name} → {target}"
                print(f"{label} ...", end=" ", flush=True)

                result = await run_single(spec, target)
                all_results.append(result)
                stats.runs += 1
                stats.durations_ms.append(result.duration_ms)

                if result.timeout_hit:
                    stats.timeouts += 1
                    print(f"TIMEOUT ({result.duration_ms:.0f}ms)")
                elif result.success:
                    stats.successes += 1
                    print(f"OK {result.duration_ms:.0f}ms ({result.findings_count} findings)")
                else:
                    stats.errors += 1
                    err_short = (result.error or "")[:80]
                    print(f"ERR {result.duration_ms:.0f}ms — {err_short}")

    return all_results, list(stats_map.values())


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_stats_table(all_stats: list[ScannerStats]) -> None:
    """Print a formatted summary table."""
    if not all_stats:
        return

    header = f"{'Scanner':<20} {'Phase':<8} {'Runs':>5} {'OK':>4} {'Err':>4} {'T/O':>4} | {'p50':>8} {'p75':>8} {'p90':>8} {'p95':>8} {'p99':>8} {'mean':>8} {'min':>8} {'max':>8}"
    sep = "-" * len(header)

    print(f"\n{sep}")
    print(header)
    print(sep)

    for s in sorted(all_stats, key=lambda x: ({"smoke": 0, "medium": 1, "long": 2}.get(x.phase, 3), x.mean)):
        print(
            f"{s.scanner:<20} {s.phase:<8} {s.runs:>5} {s.successes:>4} {s.errors:>4} {s.timeouts:>4} | "
            f"{s.p50:>7.0f}ms {s.p75:>7.0f}ms {s.p90:>7.0f}ms {s.p95:>7.0f}ms {s.p99:>7.0f}ms "
            f"{s.mean:>7.0f}ms {s.min_ms:>7.0f}ms {s.max_ms:>7.0f}ms"
        )

    print(sep)


def save_results(all_results: list[RunResult], all_stats: list[ScannerStats], timestamp: str) -> None:
    """Save raw results to CSV and stats to JSON."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Raw results CSV
    csv_path = RESULTS_DIR / f"raw_{timestamp}.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["scanner", "target", "duration_ms", "success", "error", "findings_count", "timeout_hit"])
        writer.writeheader()
        for r in all_results:
            writer.writerow({
                "scanner": r.scanner,
                "target": r.target,
                "duration_ms": round(r.duration_ms, 1),
                "success": r.success,
                "error": r.error or "",
                "findings_count": r.findings_count,
                "timeout_hit": r.timeout_hit,
            })
    print(f"\nRaw results saved to: {csv_path}")

    # Stats JSON
    stats_path = RESULTS_DIR / f"stats_{timestamp}.json"
    stats_data = []
    for s in all_stats:
        stats_data.append({
            "scanner": s.scanner,
            "phase": s.phase,
            "runs": s.runs,
            "successes": s.successes,
            "errors": s.errors,
            "timeouts": s.timeouts,
            "p50_ms": round(s.p50, 1),
            "p75_ms": round(s.p75, 1),
            "p90_ms": round(s.p90, 1),
            "p95_ms": round(s.p95, 1),
            "p99_ms": round(s.p99, 1),
            "mean_ms": round(s.mean, 1),
            "min_ms": round(s.min_ms, 1),
            "max_ms": round(s.max_ms, 1),
        })
    with open(stats_path, "w") as f:
        json.dump(stats_data, f, indent=2)
    print(f"Stats saved to: {stats_path}")

    # Summary markdown
    md_path = RESULTS_DIR / f"summary_{timestamp}.md"
    with open(md_path, "w") as f:
        f.write("# Scanner Latency Benchmark Results\n\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Timeout per check: {BENCHMARK_TIMEOUT}s\n\n")

        f.write("## Summary\n\n")
        f.write("| Scanner | Phase | Runs | OK | Err | T/O | p50 | p75 | p90 | p95 | p99 | Mean | Min | Max |\n")
        f.write("|---------|-------|------|----|-----|-----|-----|-----|-----|-----|-----|------|-----|-----|\n")
        for s in sorted(all_stats, key=lambda x: ({"smoke": 0, "medium": 1, "long": 2}.get(x.phase, 3), x.mean)):
            f.write(
                f"| {s.scanner} | {s.phase} | {s.runs} | {s.successes} | {s.errors} | {s.timeouts} "
                f"| {s.p50:.0f}ms | {s.p75:.0f}ms | {s.p90:.0f}ms | {s.p95:.0f}ms | {s.p99:.0f}ms "
                f"| {s.mean:.0f}ms | {s.min_ms:.0f}ms | {s.max_ms:.0f}ms |\n"
            )

        f.write("\n## Classification\n\n")
        f.write("Based on p95 latency:\n\n")
        for s in sorted(all_stats, key=lambda x: x.p95):
            if s.p95 < 3000:
                bucket = "FAST (< 3s)"
            elif s.p95 < 10000:
                bucket = "MODERATE (3-10s)"
            elif s.p95 < 20000:
                bucket = "SLOW (10-20s)"
            else:
                bucket = "VERY SLOW (> 20s)"
            f.write(f"- **{s.scanner}** (p95={s.p95:.0f}ms): {bucket}\n")

        f.write("\n## Raw Data\n\n")
        f.write("| Scanner | Target | Duration | Success | Findings | Error |\n")
        f.write("|---------|--------|----------|---------|----------|-------|\n")
        for r in all_results:
            err = (r.error or "")[:50]
            f.write(f"| {r.scanner} | {r.target} | {r.duration_ms:.0f}ms | {r.success} | {r.findings_count} | {err} |\n")

    print(f"Summary saved to: {md_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
PHASE_CONFIG = {
    # phase: (repeat_count, description)
    "smoke": (2, "Fast lightweight checks — 2 repeats per target"),
    "medium": (2, "Deep inline checks — 2 repeats per target"),
    "long": (1, "Nmap-based slow checks — 1 pass (already slow enough)"),
}


async def main() -> int:
    parser = argparse.ArgumentParser(description="Scanner latency benchmark")
    parser.add_argument("--phase", choices=["smoke", "medium", "long", "all"], default="all",
                        help="Which phase to run (default: all)")
    args = parser.parse_args()

    phases = ["smoke", "medium", "long"] if args.phase == "all" else [args.phase]

    timestamp = time.strftime("%Y%m%d_%H%M%S")

    print("=" * 70)
    print("  InfraProbe Scanner Latency Benchmark")
    print(f"  Timeout per check: {BENCHMARK_TIMEOUT}s")
    print(f"  Phases: {', '.join(phases)}")
    print("=" * 70)

    all_results: list[RunResult] = []
    all_stats: list[ScannerStats] = []

    for phase in phases:
        repeat, desc = PHASE_CONFIG[phase]
        print(f"\n{'=' * 70}")
        print(f"  Phase: {phase.upper()} — {desc}")
        print(f"{'=' * 70}")

        results, stats = await run_phase(phase, repeat=repeat)
        all_results.extend(results)
        all_stats.extend(stats)

        # Print intermediate stats after each phase
        print_stats_table(stats)

    # Final combined output
    if len(phases) > 1:
        print(f"\n{'=' * 70}")
        print("  COMBINED RESULTS")
        print(f"{'=' * 70}")
        print_stats_table(all_stats)

    # Save everything
    save_results(all_results, all_stats, timestamp)

    total_time = sum(r.duration_ms for r in all_results) / 1000
    print(f"\nTotal benchmark time: {total_time:.0f}s ({total_time/60:.1f}min)")
    print(f"Total runs: {len(all_results)}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
