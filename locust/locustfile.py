"""
InfraProbe load tests — real stress scenarios.

Each user class answers a specific question about production readiness.
Run one at a time with the recommended config:

    # 1. Find throughput ceiling (light scans)
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 30 -r 3 -t 5m LightThroughput

    # 2. Find throughput ceiling (deep scans)
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 15 -r 2 -t 5m DeepContention

    # 3. Simulate real production traffic
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 30 -r 3 -t 5m MixedWorkload

    # 4. Test async job queue under pressure
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 20 -r 5 -t 3m AsyncQueueStress

    # 5. Test graceful degradation with bad targets
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 20 -r 3 -t 3m FailureCascade

    # 6. Soak test for memory leaks / connection leaks
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 10 -r 2 -t 30m Soak

    # 7. Smoke test (quick sanity check, not a real load test)
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 2 -r 1 -t 30s Smoke

Deployed instances:
    RAPIDAPI_SECRET=xxx locust -f locust/locustfile.py --host https://...
"""

import logging
import os
import random
import time

from locust import HttpUser, between, events, task

from targets import (
    IP_LIGHT_CHECKS,
    LIGHT_CHECKS,
    domain_with_failures,
    domains_with_failures,
    random_domain,
    random_domains,
    random_ip,
    random_target,
    random_targets,
    weighted_domain,
)

logger = logging.getLogger(__name__)

_RAPIDAPI_SECRET = os.environ.get("RAPIDAPI_SECRET", "")

# ---------------------------------------------------------------------------
# Custom metrics — the numbers that actually matter
# ---------------------------------------------------------------------------

_stats = {
    "scanner_timeouts": 0,  # scanners that returned error containing "timed out"
    "scanner_errors": 0,  # scanners that returned any error
    "scanner_ok": 0,  # scanners that completed without error
    "http_errors": 0,  # non-2xx HTTP responses (excluding expected errors)
    "requests_total": 0,
}


def _parse_scan_response(resp) -> None:
    """Extract per-scanner success/timeout/error counts from a scan response."""
    if resp.status_code not in (200, 202):
        return
    try:
        body = resp.json()
    except Exception:
        return
    results_list = body.get("results", [])
    for target_result in results_list:
        for _check_name, check_result in target_result.get("results", {}).items():
            error = check_result.get("error")
            if error is None:
                _stats["scanner_ok"] += 1
            elif "timed out" in error.lower():
                _stats["scanner_timeouts"] += 1
            else:
                _stats["scanner_errors"] += 1


@events.request.add_listener
def _on_request(request_type, name, response_time, response_length, exception, context, **kwargs):
    _stats["requests_total"] += 1
    if exception:
        _stats["http_errors"] += 1


@events.test_stop.add_listener
def _on_test_stop(environment, **kwargs):
    total_scanners = _stats["scanner_ok"] + _stats["scanner_errors"] + _stats["scanner_timeouts"]
    timeout_pct = (_stats["scanner_timeouts"] / total_scanners * 100) if total_scanners else 0
    error_pct = (_stats["scanner_errors"] / total_scanners * 100) if total_scanners else 0

    print("\n" + "=" * 70)
    print("INFRAPROBE SCANNER METRICS")
    print("=" * 70)
    print(f"  HTTP requests total:    {_stats['requests_total']}")
    print(f"  HTTP errors (non-2xx):  {_stats['http_errors']}")
    print(f"  Scanner results total:  {total_scanners}")
    print(f"  Scanner OK:             {_stats['scanner_ok']}")
    print(f"  Scanner timeouts:       {_stats['scanner_timeouts']} ({timeout_pct:.1f}%)")
    print(f"  Scanner errors:         {_stats['scanner_errors']} ({error_pct:.1f}%)")
    print("=" * 70)

    if timeout_pct > 20:
        print("  !! HIGH TIMEOUT RATE — scanners can't keep up at this load")
    if _stats["http_errors"] > 0:
        print(f"  !! {_stats['http_errors']} HTTP-level errors — server may be overloaded")
    print()


# ---------------------------------------------------------------------------
# Base user
# ---------------------------------------------------------------------------


class InfraProbeUser(HttpUser):
    """Base class — sets auth headers. Not runnable directly."""

    abstract = True

    def on_start(self):
        if _RAPIDAPI_SECRET:
            self.client.headers["x-rapidapi-proxy-secret"] = _RAPIDAPI_SECRET

    def _scan(self, payload: dict, name: str):
        """POST /v1/scan with response parsing for scanner metrics."""
        with self.client.post("/v1/scan", json=payload, name=name, catch_response=True) as resp:
            if resp.status_code == 200:
                _parse_scan_response(resp)
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")

    def _check(self, check_type: str, target: str, deep: bool = False):
        """POST /v1/check/{type} or /v1/check_deep/{type}."""
        prefix = "check_deep" if deep else "check"
        self.client.post(
            f"/v1/{prefix}/{check_type}",
            json={"target": target},
            name=f"/v1/{prefix}/{check_type}",
        )


# ===================================================================
# SCENARIO 1: Light Throughput Ceiling
#
# Question: How many concurrent light scans can we sustain before
#           scanner timeout rate climbs above 10%?
#
# Run: locust ... -u 30 -r 3 -t 5m LightThroughput
# Watch: Scanner timeout % in final report. p95 latency trend.
# ===================================================================


class LightThroughput(InfraProbeUser):
    wait_time = between(0.5, 2)

    @task(5)
    def single_target(self):
        self._scan(
            {"targets": [weighted_domain()]},
            "/v1/scan [1t light]",
        )

    @task(3)
    def two_targets(self):
        self._scan(
            {"targets": random_domains(2)},
            "/v1/scan [2t light]",
        )

    @task(1)
    def three_targets(self):
        self._scan(
            {"targets": random_domains(3)},
            "/v1/scan [3t light]",
        )


# ===================================================================
# SCENARIO 2: Deep Scan Contention
#
# Question: What happens when many users request deep scans?
#           nmap_max_concurrent=3 — do requests queue, timeout, or fail?
#
# Run: locust ... -u 15 -r 2 -t 5m DeepContention
# Watch: Scanner timeout %, p95 response time, whether it climbs
#        over time (queuing) or stays flat.
# ===================================================================


class DeepContention(InfraProbeUser):
    wait_time = between(1, 3)

    @task(4)
    def deep_single(self):
        self._scan(
            {"targets": [random_domain()], "checks": ["ssl_deep", "dns_deep", "tech_deep"]},
            "/v1/scan [1t deep]",
        )

    @task(2)
    def deep_with_ports(self):
        """Hits nmap_max_concurrent bottleneck."""
        self._scan(
            {"targets": [random_domain()], "checks": ["ssl_deep", "dns_deep", "ports_deep"]},
            "/v1/scan [1t deep+ports]",
        )

    @task(1)
    def deep_multi(self):
        self._scan(
            {"targets": random_domains(2), "checks": ["ssl_deep", "dns_deep", "tech_deep"]},
            "/v1/scan [2t deep]",
        )


# ===================================================================
# SCENARIO 3: Mixed Workload
#
# Question: Does the system behave well under realistic traffic?
#           Light scans shouldn't slow down because deep scans are
#           hogging resources.
#
# Run: locust ... -u 30 -r 3 -t 5m MixedWorkload
# Watch: Per-endpoint p95. Do light scan latencies degrade when
#        deep scans are running?
# ===================================================================


class MixedWorkload(InfraProbeUser):
    wait_time = between(0.5, 2)

    @task(40)
    def light_bundle(self):
        n = random.choice([1, 1, 1, 2, 3])  # mostly single-target
        self._scan(
            {"targets": random_targets(n)},
            f"/v1/scan [{n}t light]",
        )

    @task(25)
    def individual_check(self):
        check = random.choice(LIGHT_CHECKS)
        target = random_domain() if check in ("dns", "whois") else random_target()
        self._check(check, target)

    @task(10)
    def deep_bundle(self):
        self._scan(
            {"targets": [random_domain()], "checks": ["ssl_deep", "dns_deep"]},
            "/v1/scan [1t deep]",
        )

    @task(10)
    def ip_scan(self):
        self._scan(
            {"targets": [random_ip()], "checks": IP_LIGHT_CHECKS},
            "/v1/scan [1t ip]",
        )

    @task(10)
    def async_submit(self):
        """Submit async job — don't poll (that's a separate scenario)."""
        self.client.post(
            "/v1/scan/async",
            json={"targets": [weighted_domain()], "checks": ["headers", "ssl"]},
            name="/v1/scan/async [submit]",
        )

    @task(5)
    def sarif_output(self):
        self.client.post(
            "/v1/scan?format=sarif",
            json={"targets": [random_target()]},
            name="/v1/scan [1t sarif]",
        )


# ===================================================================
# SCENARIO 4: Async Queue Stress
#
# Question: Can the job store handle many concurrent async jobs?
#           Do polls stay fast? Does memory grow?
#
# Run: locust ... -u 20 -r 5 -t 3m AsyncQueueStress
# Watch: Poll latency (should stay <10ms). Submit latency.
#        Monitor server memory externally.
# ===================================================================


class AsyncQueueStress(InfraProbeUser):
    wait_time = between(0.2, 1)

    @task(3)
    def submit_and_poll(self):
        """Full lifecycle: submit → poll until done → fetch report."""
        with self.client.post(
            "/v1/scan/async",
            json={"targets": [weighted_domain()], "checks": ["headers", "ssl", "tech"]},
            name="/v1/scan/async [submit]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 202:
                resp.failure(f"Expected 202, got {resp.status_code}")
                return
            job_id = resp.json()["job_id"]

        deadline = time.time() + 60
        polls = 0
        while time.time() < deadline:
            polls += 1
            with self.client.get(
                f"/v1/scan/{job_id}",
                name="/v1/scan/[job_id] [poll]",
                catch_response=True,
            ) as resp:
                if resp.status_code != 200:
                    resp.failure(f"Poll returned {resp.status_code}")
                    return
                data = resp.json()
                status = data.get("status")
                if status == "completed":
                    # Parse scanner results from the completed job
                    result = data.get("result")
                    if result:
                        for target_result in result.get("results", []):
                            for _cn, cr in target_result.get("results", {}).items():
                                err = cr.get("error")
                                if err is None:
                                    _stats["scanner_ok"] += 1
                                elif "timed out" in err.lower():
                                    _stats["scanner_timeouts"] += 1
                                else:
                                    _stats["scanner_errors"] += 1
                    break
                if status == "failed":
                    resp.failure(f"Job failed: {data.get('error')}")
                    return
            time.sleep(1)

        # Fetch report
        self.client.get(
            f"/v1/scan/{job_id}/report?format=sarif",
            name="/v1/scan/[job_id]/report",
        )

    @task(5)
    def submit_fire_and_forget(self):
        """Submit without polling — pile up jobs in the store."""
        self.client.post(
            "/v1/scan/async",
            json={
                "targets": random_domains(random.randint(1, 3)),
                "checks": random.sample(LIGHT_CHECKS, random.randint(2, 5)),
            },
            name="/v1/scan/async [fire-forget]",
        )

    @task(2)
    def poll_nonexistent(self):
        """Constant background polling for stale/missing jobs."""
        with self.client.get(
            "/v1/scan/00000000000000000000000000000000",
            name="/v1/scan/[job_id] [missing]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 404:
                resp.success()
            else:
                resp.failure(f"Expected 404, got {resp.status_code}")


# ===================================================================
# SCENARIO 5: Failure Cascade
#
# Question: When targets are broken (NXDOMAIN, unreachable), does
#           the server degrade gracefully or do timeouts pile up
#           and affect other requests?
#
# Run: locust ... -u 20 -r 3 -t 3m FailureCascade
# Watch: Scanner error/timeout rates. Do good-target requests
#        stay fast even when bad-target requests are timing out?
# ===================================================================


class FailureCascade(InfraProbeUser):
    wait_time = between(0.5, 2)

    @task(3)
    def scan_mixed_targets(self):
        """Bundle with a mix of good and bad targets."""
        targets = domains_with_failures(3)
        self._scan(
            {"targets": targets},
            "/v1/scan [3t mixed-fail]",
        )

    @task(3)
    def scan_bad_target(self):
        """Single bad target — should timeout/error, not crash."""
        self._scan(
            {"targets": [domain_with_failures()]},
            "/v1/scan [1t maybe-fail]",
        )

    @task(2)
    def scan_good_target(self):
        """Baseline: good target alongside the chaos. Should stay fast."""
        self._scan(
            {"targets": ["example.com"]},
            "/v1/scan [1t good-baseline]",
        )

    @task(1)
    def check_bad_target(self):
        check = random.choice(["headers", "ssl", "tech"])
        self._check(check, domain_with_failures())


# ===================================================================
# SCENARIO 6: Soak Test
#
# Question: Does memory grow over time? Connection leaks?
#           Cache bloat? Run this for 30 minutes and watch
#           docker stats / process memory externally.
#
# Run: locust ... -u 10 -r 2 -t 30m Soak
# Watch: Server memory (docker stats), open FDs, response time
#        trend (should be flat, not climbing).
# ===================================================================


class Soak(InfraProbeUser):
    wait_time = between(1, 3)

    @task(5)
    def light_scan(self):
        self._scan(
            {"targets": [weighted_domain()]},
            "/v1/scan [soak-light]",
        )

    @task(2)
    def individual_check(self):
        check = random.choice(["headers", "ssl", "tech"])
        self._check(check, random_target())

    @task(1)
    def deep_scan(self):
        self._scan(
            {"targets": [random_domain()], "checks": ["ssl_deep", "dns_deep"]},
            "/v1/scan [soak-deep]",
        )

    @task(1)
    def async_lifecycle(self):
        with self.client.post(
            "/v1/scan/async",
            json={"targets": [random_domain()], "checks": ["headers", "ssl"]},
            name="/v1/scan/async [soak]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 202:
                resp.failure(f"Expected 202, got {resp.status_code}")
                return
            job_id = resp.json()["job_id"]

        deadline = time.time() + 30
        while time.time() < deadline:
            with self.client.get(
                f"/v1/scan/{job_id}",
                name="/v1/scan/[job_id] [soak-poll]",
                catch_response=True,
            ) as resp:
                if resp.status_code != 200:
                    break
                if resp.json().get("status") in ("completed", "failed"):
                    break
            time.sleep(2)


# ===================================================================
# SCENARIO 7: Smoke Test (quick sanity check)
#
# NOT a load test. Just verifies every endpoint works.
# Keep this for CI or quick pre-deployment checks.
#
# Run: locust ... -u 2 -r 1 -t 30s Smoke
# ===================================================================


class Smoke(InfraProbeUser):
    wait_time = between(1, 3)

    @task
    def health(self):
        self.client.get("/health", name="/health")

    @task
    def light_scan(self):
        self._scan({"targets": [random_target()]}, "/v1/scan [smoke-light]")

    @task
    def deep_scan(self):
        self._scan(
            {"targets": [random_domain()], "checks": ["ssl_deep", "dns_deep"]},
            "/v1/scan [smoke-deep]",
        )

    @task
    def individual_check(self):
        self._check("headers", random_target())

    @task
    def sarif_format(self):
        self.client.post(
            "/v1/scan?format=sarif",
            json={"targets": [random_target()]},
            name="/v1/scan [smoke-sarif]",
        )

    @task
    def error_blocked(self):
        with self.client.post(
            "/v1/check/headers",
            json={"target": "127.0.0.1"},
            name="/v1/check/headers [blocked→400]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 400:
                resp.success()
            else:
                resp.failure(f"Expected 400, got {resp.status_code}")

    @task
    def async_flow(self):
        with self.client.post(
            "/v1/scan/async",
            json={"targets": [random_domain()], "checks": ["headers"]},
            name="/v1/scan/async [smoke]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 202:
                resp.failure(f"Expected 202, got {resp.status_code}")
                return
            job_id = resp.json()["job_id"]

        deadline = time.time() + 30
        while time.time() < deadline:
            with self.client.get(
                f"/v1/scan/{job_id}", name="/v1/scan/[job_id] [smoke-poll]", catch_response=True
            ) as resp:
                if resp.status_code != 200:
                    break
                if resp.json().get("status") in ("completed", "failed"):
                    break
            time.sleep(2)
