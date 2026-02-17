#!/usr/bin/env python3
"""Verify a deployed InfraProbe instance by hitting every endpoint."""

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

# All check types (fast inline + slow async)
FAST_CHECKS = ["ssl", "headers", "dns", "tech", "blacklist", "web", "whois",
               "ssl_deep", "dns_deep", "blacklist_deep"]
SLOW_CHECKS = ["ports", "ports_deep", "cve"]
DOMAIN_ONLY_CHECKS = {"dns", "dns_deep", "whois"}


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


def poll_job(client: httpx.Client, stats: Stats, job_id: str, label: str, timeout: float = 60) -> dict | None:
    """Poll GET /v1/scan/{job_id} until completed or failed."""
    deadline = time.monotonic() + timeout
    final_status = None
    while time.monotonic() < deadline:
        time.sleep(2)
        poll = client.get(f"/v1/scan/{job_id}")
        if poll.status_code != 200:
            stats.record_fail(f"GET /v1/scan/{job_id} [{poll.status_code}]")
            return None
        job = poll.json()
        final_status = job.get("status")
        print(f"       {DIM}poll: status={final_status}{RESET}")
        if final_status in ("completed", "failed"):
            if final_status == "completed":
                stats.record_pass(f"{label} (completed)")
                return job
            else:
                error = job.get("error", "unknown")
                stats.record_fail(f"{label} failed: {error}")
                return job

    stats.record_fail(f"{label} timed out after {timeout}s (last status={final_status})")
    return None


# -- probes ------------------------------------------------------------------


def probe_health(client: httpx.Client, stats: Stats) -> None:
    print(section("Health"))
    resp = client.get("/health")
    check_response(stats, "GET /health", resp, must_have_keys=["status"])


def probe_fast_checks(client: httpx.Client, stats: Stats) -> None:
    """Fast checks return 200 inline via POST /v1/check/{type}."""
    print(section("Fast checks (POST /v1/check/*)"))

    for ct in FAST_CHECKS:
        path = f"/v1/check/{ct}"
        resp = client.post(path, json={"target": TEST_DOMAIN})
        body = check_response(stats, f"POST {path}", resp, must_have_keys=["target", "results"])
        if body and isinstance(body, dict):
            results = body.get("results", {})
            if ct not in results:
                stats.record_warn(f"  response missing '{ct}' in results keys: {list(results.keys())}")


def probe_slow_checks(client: httpx.Client, stats: Stats) -> None:
    """Slow checks return 202 via POST /v1/check/{type}, then poll."""
    print(section("Slow checks (POST /v1/check/* → 202 → poll)"))

    for ct in SLOW_CHECKS:
        path = f"/v1/check/{ct}"
        resp = client.post(path, json={"target": TEST_DOMAIN})
        body = check_response(stats, f"POST {path}", resp, expected_status=202, must_have_keys=["job_id", "status"])
        if body:
            job_id = body["job_id"]
            print(f"       {DIM}job_id={job_id}{RESET}")
            poll_job(client, stats, job_id, f"POST {path} result")


def probe_bundle_scan(client: httpx.Client, stats: Stats) -> None:
    """POST /v1/scan always returns 202 (async). Submit, then poll for results."""
    print(section("Bundle scan (POST /v1/scan → 202 → poll)"))
    resp = client.post("/v1/scan", json={"targets": [TEST_DOMAIN], "checks": ["headers", "ssl", "dns"]})
    body = check_response(stats, "POST /v1/scan", resp, expected_status=202, must_have_keys=["job_id", "status"])
    if not body:
        return

    job_id = body["job_id"]
    print(f"       {DIM}job_id={job_id}{RESET}")

    job = poll_job(client, stats, job_id, "Bundle scan result")
    if job and job.get("result"):
        results = job["result"].get("results", [])
        if results:
            tr = results[0]
            print(f"       {DIM}target={tr.get('target')}  checks={list(tr.get('results', {}).keys())}{RESET}")


def probe_target_auto_detect(client: httpx.Client, stats: Stats) -> None:
    """Verify auto-detection: IP targets get IP_CHECKS defaults, DNS checks on IPs rejected."""
    print(section("Target auto-detection"))

    # IP target with auto-detect defaults — should exclude DNS/WHOIS
    resp = client.post("/v1/scan", json={"targets": [TEST_IP]})
    body = check_response(stats, "POST /v1/scan (IP, auto-detect)", resp, expected_status=202,
                          must_have_keys=["job_id"])
    if body:
        job = poll_job(client, stats, body["job_id"], "IP auto-detect scan")
        if job and job.get("result"):
            result_keys = list(job["result"]["results"][0].get("results", {}).keys())
            if "dns" not in result_keys and "whois" not in result_keys:
                stats.record_pass(f"IP auto-detect excludes DNS/WHOIS (got: {result_keys})")
            else:
                stats.record_fail(f"IP auto-detect should exclude DNS/WHOIS, got: {result_keys}")

    # DNS check on IP target — should be rejected
    resp = client.post("/v1/scan", json={"targets": [TEST_IP], "checks": ["dns"]})
    if resp.status_code == 422:
        stats.record_pass(f"POST /v1/scan (DNS on IP rejected) [{resp.status_code}]")
    else:
        stats.record_fail(f"POST /v1/scan (DNS on IP should be 422) [{resp.status_code}]")

    # WHOIS check on IP — rejected
    resp = client.post("/v1/check/whois", json={"target": TEST_IP})
    if resp.status_code == 422:
        stats.record_pass(f"POST /v1/check/whois (IP rejected) [{resp.status_code}]")
    else:
        stats.record_fail(f"POST /v1/check/whois (IP should be 422) [{resp.status_code}]")


def probe_output_formats(client: httpx.Client, stats: Stats) -> None:
    """Test format param on inline check and on poll endpoint."""
    print(section("Output formats"))

    # SARIF on inline check
    resp = client.post("/v1/check/headers?format=sarif", json={"target": TEST_DOMAIN})
    body = check_response(stats, "POST /v1/check/headers?format=sarif", resp)
    if body and isinstance(body, dict):
        if body.get("$schema") or body.get("runs"):
            print(f"       {DIM}valid SARIF structure{RESET}")
        else:
            stats.record_warn("  SARIF response missing expected keys ($schema, runs)")

    # CSV on inline check
    resp = client.post("/v1/check/headers?format=csv", json={"target": TEST_DOMAIN})
    if resp.status_code == 200 and ("target" in resp.text or "severity" in resp.text):
        stats.record_pass(f"POST /v1/check/headers?format=csv [{resp.status_code}] ({resp.elapsed.total_seconds():.1f}s)")
    elif resp.status_code == 200:
        stats.record_warn(f"POST /v1/check/headers?format=csv [{resp.status_code}] — unexpected body")
    else:
        stats.record_fail(f"POST /v1/check/headers?format=csv [{resp.status_code}]")

    # SARIF on poll endpoint
    resp = client.post("/v1/scan", json={"targets": [TEST_DOMAIN], "checks": ["headers"]})
    if resp.status_code == 202:
        job_id = resp.json()["job_id"]
        job = poll_job(client, stats, job_id, "Format test scan")
        if job and job.get("status") == "completed":
            resp = client.get(f"/v1/scan/{job_id}?format=sarif")
            body = check_response(stats, f"GET /v1/scan/{job_id}?format=sarif", resp)
            if body and isinstance(body, dict) and (body.get("$schema") or body.get("runs")):
                print(f"       {DIM}valid SARIF from poll endpoint{RESET}")


def probe_error_handling(client: httpx.Client, stats: Stats) -> None:
    print(section("Error handling"))

    # SSRF blocked target
    resp = client.post("/v1/check/headers", json={"target": "127.0.0.1"})
    if resp.status_code == 400:
        stats.record_pass(f"POST /v1/check/headers (localhost blocked) [{resp.status_code}]")
    else:
        stats.record_fail(f"POST /v1/check/headers (localhost should be 400) [{resp.status_code}]")

    # invalid target
    resp = client.post("/v1/check/headers", json={"target": ""})
    if resp.status_code == 422:
        stats.record_pass(f"POST /v1/check/headers (empty target rejected) [{resp.status_code}]")
    else:
        stats.record_fail(f"POST /v1/check/headers (empty target should be 422) [{resp.status_code}]")

    # invalid check type — no matching route → 404
    resp = client.post("/v1/check/nonexistent", json={"target": TEST_DOMAIN})
    if resp.status_code in (404, 422):
        stats.record_pass(f"POST /v1/check/nonexistent (invalid type rejected) [{resp.status_code}]")
    else:
        stats.record_fail(f"POST /v1/check/nonexistent (should be 404/422) [{resp.status_code}]")

    # 404 for bogus job
    resp = client.get("/v1/scan/nonexistent-job-id")
    if resp.status_code == 404:
        stats.record_pass("GET /v1/scan/<bogus> (404)")
    else:
        stats.record_fail(f"GET /v1/scan/<bogus> expected 404, got {resp.status_code}")


def probe_auth_without_secret(base_url: str, stats: Stats) -> None:
    """Hit an endpoint without the secret header — should get 403 if auth is enabled."""
    print(section("Auth enforcement"))
    no_auth = httpx.Client(base_url=base_url, timeout=30)
    try:
        resp = no_auth.post("/v1/check/headers", json={"target": TEST_DOMAIN})
        if resp.status_code == 403:
            stats.record_pass(f"POST /v1/check/headers (no secret → 403)")
        else:
            stats.record_warn(f"POST /v1/check/headers (no secret) [{resp.status_code}] — auth may be disabled")
    finally:
        no_auth.close()


# -- main --------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify a deployed InfraProbe instance",
        epilog="Examples:\n"
        "  %(prog)s                          # deployed URL from .envs\n"
        "  %(prog)s http://localhost:8080     # local dev server\n"
        "  %(prog)s https://my-url --skip-deep\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Base URL to test (default: read from .envs/deployed.url)",
    )
    parser.add_argument("--secret", help="RapidAPI proxy secret (default: read from .envs/rapidapi_proxy_secret.txt)")
    parser.add_argument("--skip-deep", action="store_true", help="Skip deep and slow scanner checks")
    parser.add_argument("--skip-slow", action="store_true", help="Skip slow (nmap) checks only")
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
        probe_fast_checks(client, stats)
        if not args.skip_deep and not args.skip_slow:
            probe_slow_checks(client, stats)
        probe_bundle_scan(client, stats)
        probe_target_auto_detect(client, stats)
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
    print(f"  {GREEN}{stats.passed} passed{RESET}  {RED}{stats.failed} failed{RESET}  {YELLOW}{stats.warned} warnings{RESET}  ({elapsed:.0f}s)")

    sys.exit(1 if stats.failed else 0)


if __name__ == "__main__":
    main()
