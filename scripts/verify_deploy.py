#!/usr/bin/env python3
"""Verify a deployed InfraProbe instance by hitting the scan endpoint."""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

ENVS_DIR = Path(__file__).resolve().parent.parent / ".envs"
TEST_DOMAIN = "example.com"
TEST_IP = "93.184.216.34"  # example.com


# -- colours -----------------------------------------------------------------

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def ok(text: str) -> str:
    return f"{GREEN}PASS{RESET} {text}"


def fail(text: str) -> str:
    return f"{RED}FAIL{RESET} {text}"


def warn(text: str) -> str:
    return f"{YELLOW}WARN{RESET} {text}"


def section(text: str) -> str:
    return f"\n{BOLD}{CYAN}=== {text} ==={RESET}"


# -- result tracking ---------------------------------------------------------


@dataclass
class Stats:
    passed: int = 0
    failed: int = 0
    warned: int = 0
    details: list[str] = field(default_factory=list)

    def record(self, line: str) -> None:
        self.details.append(line)
        print(line)

    def record_pass(self, msg: str) -> None:
        self.passed += 1
        self.record(ok(msg))

    def record_fail(self, msg: str) -> None:
        self.failed += 1
        self.record(fail(msg))

    def record_warn(self, msg: str) -> None:
        self.warned += 1
        self.record(warn(msg))


# -- helpers -----------------------------------------------------------------


def read_env_file(name: str) -> str:
    path = ENVS_DIR / name
    if not path.exists():
        print(f"{RED}ERROR{RESET}: {path} not found")
        sys.exit(1)
    return path.read_text().strip()


def check_response(
    stats: Stats,
    label: str,
    resp: httpx.Response,
    *,
    expected_status: int = 200,
    must_have_keys: list[str] | None = None,
) -> dict | list | None:
    """Validate response status and optionally check JSON keys. Returns parsed body or None."""
    status = resp.status_code
    duration = resp.elapsed.total_seconds()
    tag = f"{label} [{status}] ({duration:.1f}s)"

    if status != expected_status:
        stats.record_fail(f"{tag}  (expected {expected_status})")
        try:
            body = resp.json()
            print(f"       {DIM}{body}{RESET}")
        except Exception:
            print(f"       {DIM}{resp.text[:200]}{RESET}")
        return None

    try:
        body = resp.json()
    except Exception:
        # non-JSON is fine for CSV/SARIF
        body = None

    if must_have_keys and isinstance(body, dict):
        missing = [k for k in must_have_keys if k not in body]
        if missing:
            stats.record_fail(f"{tag}  missing keys: {missing}")
            return body

    stats.record_pass(tag)
    return body


# -- probes ------------------------------------------------------------------


def probe_health(client: httpx.Client, stats: Stats) -> None:
    print(section("Health"))
    resp = client.get("/health")
    check_response(stats, "GET /health", resp, must_have_keys=["status"])

    resp = client.get("/health/ready")
    check_response(stats, "GET /health/ready", resp, must_have_keys=["status"])


def probe_bundle_scan(client: httpx.Client, stats: Stats) -> None:
    """POST /v1/scan always returns 200 with inline results."""
    print(section("Bundle scan (POST /v1/scan)"))

    # Domain scan — should get 5 checks
    resp = client.post("/v1/scan", json={"target": TEST_DOMAIN})
    body = check_response(stats, "POST /v1/scan (domain)", resp, must_have_keys=["results", "summary"])
    if body and isinstance(body, dict):
        results = body.get("results", [])
        if results:
            tr = results[0]
            checks = list(tr.get("results", {}).keys())
            expected = {"headers", "ssl", "dns", "web", "whois"}
            if set(checks) == expected:
                stats.record_pass(f"Domain checks correct: {checks}")
            else:
                stats.record_fail(f"Domain checks expected {expected}, got {set(checks)}")

    # IP scan — should get 3 checks (no dns, no whois)
    resp = client.post("/v1/scan", json={"target": TEST_IP})
    body = check_response(stats, "POST /v1/scan (IP)", resp, must_have_keys=["results", "summary"])
    if body and isinstance(body, dict):
        results = body.get("results", [])
        if results:
            tr = results[0]
            checks = list(tr.get("results", {}).keys())
            if "dns" not in checks and "whois" not in checks:
                stats.record_pass(f"IP auto-detect excludes DNS/WHOIS (got: {checks})")
            else:
                stats.record_fail(f"IP auto-detect should exclude DNS/WHOIS, got: {checks}")


def probe_output_formats(client: httpx.Client, stats: Stats) -> None:
    """Test format param on scan endpoint."""
    print(section("Output formats"))

    # SARIF
    resp = client.post("/v1/scan", json={"target": TEST_DOMAIN, "format": "sarif"})
    body = check_response(stats, "POST /v1/scan format=sarif", resp)
    if body and isinstance(body, dict):
        if body.get("$schema") or body.get("runs"):
            print(f"       {DIM}valid SARIF structure{RESET}")
        else:
            stats.record_warn("  SARIF response missing expected keys ($schema, runs)")

    # CSV
    resp = client.post("/v1/scan", json={"target": TEST_DOMAIN, "format": "csv"})
    if resp.status_code == 200 and ("target" in resp.text or "severity" in resp.text):
        stats.record_pass(f"POST /v1/scan format=csv [{resp.status_code}] ({resp.elapsed.total_seconds():.1f}s)")
    elif resp.status_code == 200:
        stats.record_warn(f"POST /v1/scan format=csv [{resp.status_code}] — unexpected body")
    else:
        stats.record_fail(f"POST /v1/scan format=csv [{resp.status_code}]")


def probe_error_handling(client: httpx.Client, stats: Stats) -> None:
    print(section("Error handling"))

    # SSRF blocked target
    resp = client.post("/v1/scan", json={"target": "127.0.0.1"})
    if resp.status_code == 400:
        stats.record_pass(f"POST /v1/scan (localhost blocked) [{resp.status_code}]")
    else:
        stats.record_fail(f"POST /v1/scan (localhost should be 400) [{resp.status_code}]")

    # invalid target
    resp = client.post("/v1/scan", json={"target": ""})
    if resp.status_code == 422:
        stats.record_pass(f"POST /v1/scan (empty target rejected) [{resp.status_code}]")
    else:
        stats.record_fail(f"POST /v1/scan (empty target should be 422) [{resp.status_code}]")

    # Check endpoints removed — should 404
    resp = client.post("/v1/check/headers", json={"target": TEST_DOMAIN})
    if resp.status_code in (404, 405):
        stats.record_pass(f"POST /v1/check/headers (removed, 404) [{resp.status_code}]")
    else:
        stats.record_fail(f"POST /v1/check/headers should be 404, got [{resp.status_code}]")


def probe_auth_without_secret(base_url: str, stats: Stats) -> None:
    """Hit an endpoint without the secret header — should get 403 if auth is enabled."""
    print(section("Auth enforcement"))
    no_auth = httpx.Client(base_url=base_url, timeout=30)
    try:
        resp = no_auth.post("/v1/scan", json={"target": TEST_DOMAIN})
        if resp.status_code == 403:
            stats.record_pass("POST /v1/scan (no secret → 403)")
        else:
            stats.record_warn(f"POST /v1/scan (no secret) [{resp.status_code}] — auth may be disabled")
    finally:
        no_auth.close()


# -- main --------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify a deployed InfraProbe instance",
        epilog="Examples:\n"
        "  %(prog)s                          # deployed URL from .envs\n"
        "  %(prog)s http://localhost:8080     # local dev server\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Base URL to test (default: read from .envs/deployed.url)",
    )
    parser.add_argument("--secret", help="RapidAPI proxy secret (default: read from .envs/rapidapi_proxy_secret.txt)")
    args = parser.parse_args()

    base_url = (args.url or read_env_file("deployed.url")).rstrip("/")
    is_local = "localhost" in base_url or "127.0.0.1" in base_url

    # Secret is optional for localhost (no auth middleware in dev)
    secret: str | None = args.secret
    if not secret:
        secret_path = ENVS_DIR / "rapidapi_proxy_secret.txt"
        if secret_path.exists():
            secret = secret_path.read_text().strip()
        elif not is_local:
            print(f"{RED}ERROR{RESET}: no secret provided and {secret_path} not found")
            sys.exit(1)

    print(f"{BOLD}InfraProbe deployment verification{RESET}")
    print(f"  URL:    {base_url}")
    if secret:
        print(f"  Secret: {'*' * (len(secret) - 4)}{secret[-4:]}")
    else:
        print(f"  Secret: {DIM}(none — local mode){RESET}")
    print(f"  Domain: {TEST_DOMAIN}")
    print(f"  IP:     {TEST_IP}")

    headers = {}
    if secret:
        headers["x-rapidapi-proxy-secret"] = secret
    client = httpx.Client(base_url=base_url, headers=headers, timeout=60)
    stats = Stats()

    t0 = time.monotonic()
    try:
        probe_health(client, stats)
        probe_bundle_scan(client, stats)
        probe_output_formats(client, stats)
        probe_error_handling(client, stats)
        if secret:
            probe_auth_without_secret(base_url, stats)
    except httpx.ConnectError as exc:
        print(f"\n{RED}CONNECTION FAILED{RESET}: {exc}")
        sys.exit(2)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted{RESET}")
    finally:
        client.close()

    elapsed = time.monotonic() - t0
    print(section("Summary"))
    p, f, w = stats.passed, stats.failed, stats.warned
    print(f"  {GREEN}{p} passed{RESET}  {RED}{f} failed{RESET}  {YELLOW}{w} warnings{RESET}  ({elapsed:.0f}s)")

    sys.exit(1 if stats.failed else 0)


if __name__ == "__main__":
    main()
