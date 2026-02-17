#!/usr/bin/env python3
"""Locust test runner with presets and automatic logging.

Usage:
    # Smoke test against localhost
    python locust/run.py smoke

    # Smoke test against deployed instance (auto-reads secret from .env)
    python locust/run.py smoke --host https://your-vps.example.com

    # Full suite against deployed instance
    python locust/run.py full --host https://your-vps.example.com

    # Single scenario
    python locust/run.py DeepContention --host https://your-vps.example.com

    # Custom params
    python locust/run.py LightThroughput -u 50 -r 5 -t 10m
"""

import argparse
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCUSTFILE = Path(__file__).resolve().parent / "locustfile.py"
LOGS_DIR = Path(__file__).resolve().parent / "logs"
DOTENV = ROOT / ".env"

PRESETS = {
    "smoke": [
        {"scenario": "Smoke", "users": 2, "rate": 1, "duration": "30s"},
    ],
    "full": [
        {"scenario": "Smoke", "users": 2, "rate": 1, "duration": "30s"},
        {"scenario": "LightThroughput", "users": 30, "rate": 3, "duration": "5m"},
        {"scenario": "DeepContention", "users": 15, "rate": 2, "duration": "5m"},
        {"scenario": "MixedWorkload", "users": 30, "rate": 3, "duration": "5m"},
        {"scenario": "AsyncQueueStress", "users": 20, "rate": 5, "duration": "3m"},
        {"scenario": "FailureCascade", "users": 20, "rate": 3, "duration": "3m"},
    ],
    "light": [
        {"scenario": "Smoke", "users": 2, "rate": 1, "duration": "30s"},
        {"scenario": "LightThroughput", "users": 30, "rate": 3, "duration": "5m"},
        {"scenario": "MixedWorkload", "users": 30, "rate": 3, "duration": "5m"},
    ],
}

# Individual scenarios with their default params
SCENARIOS = {
    "Smoke": {"users": 2, "rate": 1, "duration": "30s"},
    "LightThroughput": {"users": 30, "rate": 3, "duration": "5m"},
    "DeepContention": {"users": 15, "rate": 2, "duration": "5m"},
    "MixedWorkload": {"users": 30, "rate": 3, "duration": "5m"},
    "AsyncQueueStress": {"users": 20, "rate": 5, "duration": "3m"},
    "FailureCascade": {"users": 20, "rate": 3, "duration": "3m"},
    "Soak": {"users": 10, "rate": 2, "duration": "30m"},
}


def load_secret() -> str:
    # Check env var first
    if secret := os.environ.get("RAPIDAPI_SECRET", ""):
        return secret
    # Parse .env file for INFRAPROBE_RAPIDAPI_PROXY_SECRET
    if DOTENV.exists():
        for line in DOTENV.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip() == "INFRAPROBE_RAPIDAPI_PROXY_SECRET":
                return value.strip()
    return ""


def run_scenario(
    scenario: str,
    host: str,
    secret: str,
    users: int,
    rate: int,
    duration: str,
    log_dir: Path,
) -> bool:
    log_file = log_dir / f"{scenario}.log"
    html_file = log_dir / f"{scenario}.html"

    cmd = [
        sys.executable, "-m", "locust",
        "-f", str(LOCUSTFILE),
        "--host", host,
        "--headless",
        "-u", str(users),
        "-r", str(rate),
        "-t", duration,
        "--html", str(html_file),
        scenario,
    ]

    env = os.environ.copy()
    if secret:
        env["RAPIDAPI_SECRET"] = secret

    print(f"\n{'=' * 60}")
    print(f"  {scenario}  |  {users} users  |  ramp {rate}/s  |  {duration}")
    print(f"  log: {log_file}")
    print(f"{'=' * 60}\n")

    with open(log_file, "w") as f:
        result = subprocess.run(cmd, env=env, stdout=f, stderr=subprocess.STDOUT)

    if result.returncode != 0:
        print(f"  !! {scenario} exited with code {result.returncode}")

    # Print the scanner metrics block from the log (last ~15 lines)
    text = log_file.read_text()
    marker = "INFRAPROBE SCANNER METRICS"
    idx = text.find(marker)
    if idx != -1:
        # Find the start of the separator line before the marker
        block_start = text.rfind("=" * 10, 0, idx)
        if block_start != -1:
            print(text[block_start:].rstrip())
    else:
        # No scanner metrics — print last 20 lines as fallback
        lines = text.strip().splitlines()
        for line in lines[-20:]:
            print(line)

    print()
    return result.returncode == 0


def main():
    all_choices = list(PRESETS.keys()) + list(SCENARIOS.keys())
    parser = argparse.ArgumentParser(description="Run InfraProbe locust tests")
    parser.add_argument(
        "preset",
        choices=all_choices,
        metavar="PRESET",
        help=f"Preset ({', '.join(PRESETS)}) or scenario ({', '.join(SCENARIOS)})",
    )
    parser.add_argument("--host", default="http://localhost:8080", help="Target host URL")
    parser.add_argument("--secret", default=None, help="RapidAPI secret (auto-read from .env)")
    parser.add_argument("-u", "--users", type=int, default=None, help="Override user count")
    parser.add_argument("-r", "--rate", type=int, default=None, help="Override spawn rate")
    parser.add_argument("-t", "--duration", default=None, help="Override duration (e.g. 5m, 30s)")

    args = parser.parse_args()

    secret = args.secret or load_secret()
    is_remote = not args.host.startswith("http://localhost")
    if is_remote and not secret:
        print("Warning: remote host but no RAPIDAPI_SECRET found (checked .env and env var)")

    # Build scenario list
    if args.preset in PRESETS:
        scenarios = PRESETS[args.preset]
    else:
        defaults = SCENARIOS[args.preset]
        scenarios = [{"scenario": args.preset, **defaults}]

    # Apply CLI overrides
    for s in scenarios:
        if args.users is not None:
            s["users"] = args.users
        if args.rate is not None:
            s["rate"] = args.rate
        if args.duration is not None:
            s["duration"] = args.duration

    # Create log directory with timestamp
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = args.preset
    host_label = args.host.replace("https://", "").replace("http://", "").split(".")[0].split(":")[0]
    log_dir = LOGS_DIR / f"{ts}_{host_label}_{tag}"
    log_dir.mkdir(parents=True, exist_ok=True)

    print(f"InfraProbe Load Test")
    print(f"  Host:      {args.host}")
    print(f"  Preset:    {args.preset} ({len(scenarios)} scenario{'s' if len(scenarios) > 1 else ''})")
    print(f"  Auth:      {'yes' if secret else 'no'}")
    print(f"  Logs:      {log_dir}")

    results = []
    for s in scenarios:
        ok = run_scenario(
            scenario=s["scenario"],
            host=args.host,
            secret=secret,
            users=s["users"],
            rate=s["rate"],
            duration=s["duration"],
            log_dir=log_dir,
        )
        results.append((s["scenario"], ok))

    # Summary
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  {status}  {name}")
    print(f"\nLogs: {log_dir}")
    print(f"{'=' * 60}")

    failed = sum(1 for _, ok in results if not ok)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
