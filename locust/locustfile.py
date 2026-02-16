"""
InfraProbe load tests.

Usage:
    # Web UI (default http://localhost:8089)
    locust -f locust/locustfile.py --host http://localhost:8080

    # Headless quick run
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 10 -r 2 -t 60s

    # Run only a specific user class
    locust -f locust/locustfile.py --host http://localhost:8080 \
        --headless -u 5 -r 1 -t 30s HealthUser

    # Against deployed instance (pass auth header via environment)
    RAPIDAPI_SECRET=xxx locust -f locust/locustfile.py \
        --host https://your-deployed-url --headless -u 20 -r 5 -t 120s
"""

import os
import random
import time

from locust import HttpUser, between, task

from targets import (
    DEEP_CHECKS,
    IP_DEEP_CHECKS,
    IP_LIGHT_CHECKS,
    LIGHT_CHECKS,
    random_domain,
    random_domains,
    random_ip,
    random_ips,
    random_target,
    random_targets,
)

# Optional auth header for deployed instances behind RapidAPI proxy
_RAPIDAPI_SECRET = os.environ.get("RAPIDAPI_SECRET", "")


class InfraProbeUser(HttpUser):
    """Base class — sets common headers and abstract flag."""

    abstract = True
    wait_time = between(1, 3)

    def on_start(self):
        if _RAPIDAPI_SECRET:
            self.client.headers["x-rapidapi-proxy-secret"] = _RAPIDAPI_SECRET


# ---------------------------------------------------------------------------
# 1. Health check — baseline latency, no scanning overhead
# ---------------------------------------------------------------------------


class HealthUser(InfraProbeUser):
    """Hits /health repeatedly. Good for baseline latency measurement."""

    wait_time = between(0.5, 1)
    fixed_count = 1  # only spawn 1 by default in mixed runs

    @task
    def health(self):
        self.client.get("/health", name="/health")

    @task
    def health_ready(self):
        self.client.get("/health/ready", name="/health/ready")


# ---------------------------------------------------------------------------
# 2. Individual light checks — POST /v1/check/{type}
# ---------------------------------------------------------------------------


class LightCheckUser(InfraProbeUser):
    """Tests each light scanner endpoint with random targets."""

    @task(3)
    def check_headers(self):
        self.client.post(
            "/v1/check/headers",
            json={"target": random_target()},
            name="/v1/check/headers",
        )

    @task(3)
    def check_ssl(self):
        self.client.post(
            "/v1/check/ssl",
            json={"target": random_target()},
            name="/v1/check/ssl",
        )

    @task(2)
    def check_dns(self):
        self.client.post(
            "/v1/check/dns",
            json={"target": random_domain()},
            name="/v1/check/dns",
        )

    @task(2)
    def check_tech(self):
        self.client.post(
            "/v1/check/tech",
            json={"target": random_target()},
            name="/v1/check/tech",
        )

    @task(1)
    def check_blacklist(self):
        self.client.post(
            "/v1/check/blacklist",
            json={"target": random_target()},
            name="/v1/check/blacklist",
        )

    @task(1)
    def check_web(self):
        self.client.post(
            "/v1/check/web",
            json={"target": random_domain()},
            name="/v1/check/web",
        )

    @task(1)
    def check_whois(self):
        self.client.post(
            "/v1/check/whois",
            json={"target": random_domain()},
            name="/v1/check/whois",
        )


# ---------------------------------------------------------------------------
# 3. Individual deep checks — POST /v1/check_deep/{type}
# ---------------------------------------------------------------------------


class DeepCheckUser(InfraProbeUser):
    """Tests deep scanner endpoints. These are slower — wider wait times."""

    wait_time = between(3, 8)

    @task(3)
    def check_deep_ssl(self):
        self.client.post(
            "/v1/check_deep/ssl",
            json={"target": random_target()},
            name="/v1/check_deep/ssl",
        )

    @task(2)
    def check_deep_dns(self):
        self.client.post(
            "/v1/check_deep/dns",
            json={"target": random_domain()},
            name="/v1/check_deep/dns",
        )

    @task(2)
    def check_deep_tech(self):
        self.client.post(
            "/v1/check_deep/tech",
            json={"target": random_target()},
            name="/v1/check_deep/tech",
        )

    @task(1)
    def check_deep_blacklist(self):
        self.client.post(
            "/v1/check_deep/blacklist",
            json={"target": random_target()},
            name="/v1/check_deep/blacklist",
        )

    @task(1)
    def check_deep_ports(self):
        self.client.post(
            "/v1/check_deep/ports",
            json={"target": random_target()},
            name="/v1/check_deep/ports",
        )


# ---------------------------------------------------------------------------
# 4. Bundle scan — POST /v1/scan (multiple targets × checks)
# ---------------------------------------------------------------------------


class BundleScanUser(InfraProbeUser):
    """Tests the bundle /v1/scan endpoint with varying target counts."""

    wait_time = between(5, 15)

    @task(3)
    def scan_single_target(self):
        self.client.post(
            "/v1/scan",
            json={"targets": [random_target()]},
            name="/v1/scan [1 target]",
        )

    @task(2)
    def scan_multi_target(self):
        self.client.post(
            "/v1/scan",
            json={"targets": random_targets(3)},
            name="/v1/scan [3 targets]",
        )

    @task(1)
    def scan_custom_checks(self):
        checks = random.sample(LIGHT_CHECKS, k=random.randint(2, 4))
        self.client.post(
            "/v1/scan",
            json={"targets": [random_domain()], "checks": checks},
            name="/v1/scan [custom checks]",
        )

    @task(1)
    def scan_sarif_format(self):
        self.client.post(
            "/v1/scan?format=sarif",
            json={"targets": [random_domain()]},
            name="/v1/scan [sarif]",
        )

    @task(1)
    def scan_csv_format(self):
        self.client.post(
            "/v1/scan?format=csv",
            json={"targets": [random_domain()]},
            name="/v1/scan [csv]",
        )


# ---------------------------------------------------------------------------
# 5. Domain-specific endpoints
# ---------------------------------------------------------------------------


class DomainScanUser(InfraProbeUser):
    """Tests domain-only endpoints: /v1/scan_domain, /v1/check_domain/{type}."""

    wait_time = between(3, 8)

    @task(2)
    def scan_domain(self):
        self.client.post(
            "/v1/scan_domain",
            json={"targets": random_domains(2)},
            name="/v1/scan_domain",
        )

    @task(3)
    def check_domain_random(self):
        check = random.choice(LIGHT_CHECKS)
        self.client.post(
            f"/v1/check_domain/{check}",
            json={"target": random_domain()},
            name="/v1/check_domain/[type]",
        )

    @task(1)
    def check_domain_deep(self):
        check = random.choice(DEEP_CHECKS)
        self.client.post(
            f"/v1/check_domain/{check}_deep",
            json={"target": random_domain()},
            name="/v1/check_domain/[type]_deep",
        )


# ---------------------------------------------------------------------------
# 6. IP-specific endpoints
# ---------------------------------------------------------------------------


class IpScanUser(InfraProbeUser):
    """Tests IP-only endpoints: /v1/scan_ip, /v1/check_ip/{type}."""

    wait_time = between(3, 8)

    @task(2)
    def scan_ip(self):
        self.client.post(
            "/v1/scan_ip",
            json={"targets": random_ips(2)},
            name="/v1/scan_ip",
        )

    @task(3)
    def check_ip_random(self):
        check = random.choice(IP_LIGHT_CHECKS)
        self.client.post(
            f"/v1/check_ip/{check}",
            json={"target": random_ip()},
            name="/v1/check_ip/[type]",
        )

    @task(1)
    def check_ip_deep(self):
        check = random.choice(IP_DEEP_CHECKS)
        self.client.post(
            f"/v1/check_ip/{check}_deep",
            json={"target": random_ip()},
            name="/v1/check_ip/[type]_deep",
        )


# ---------------------------------------------------------------------------
# 7. Async scan flow — submit + poll
# ---------------------------------------------------------------------------


class AsyncScanUser(InfraProbeUser):
    """Tests the async scan flow: POST /v1/scan/async → poll GET /v1/scan/{job_id}."""

    wait_time = between(5, 15)

    @task
    def async_scan_and_poll(self):
        # Submit async job
        with self.client.post(
            "/v1/scan/async",
            json={"targets": [random_domain()]},
            name="/v1/scan/async [submit]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 202:
                resp.failure(f"Expected 202, got {resp.status_code}")
                return
            job = resp.json()

        job_id = job["job_id"]

        # Poll until completed or timeout (max 60s)
        deadline = time.time() + 60
        while time.time() < deadline:
            with self.client.get(
                f"/v1/scan/{job_id}",
                name="/v1/scan/[job_id] [poll]",
                catch_response=True,
            ) as resp:
                if resp.status_code != 200:
                    resp.failure(f"Poll returned {resp.status_code}")
                    return
                status = resp.json().get("status")
                if status in ("completed", "failed"):
                    if status == "failed":
                        resp.failure(f"Job failed: {resp.json().get('error')}")
                    return
            time.sleep(2)

    @task
    def async_scan_report(self):
        """Submit, wait for completion, then fetch the report in SARIF format."""
        with self.client.post(
            "/v1/scan/async",
            json={"targets": [random_domain()], "checks": ["headers", "ssl"]},
            name="/v1/scan/async [submit]",
            catch_response=True,
        ) as resp:
            if resp.status_code != 202:
                resp.failure(f"Expected 202, got {resp.status_code}")
                return
            job_id = resp.json()["job_id"]

        deadline = time.time() + 60
        while time.time() < deadline:
            resp = self.client.get(f"/v1/scan/{job_id}", name="/v1/scan/[job_id] [poll]")
            if resp.json().get("status") in ("completed", "failed"):
                break
            time.sleep(2)

        self.client.get(
            f"/v1/scan/{job_id}/report?format=sarif",
            name="/v1/scan/[job_id]/report [sarif]",
        )


# ---------------------------------------------------------------------------
# 8. Output format variants
# ---------------------------------------------------------------------------


class FormatUser(InfraProbeUser):
    """Tests output format variants (JSON, SARIF, CSV) across endpoints."""

    wait_time = between(2, 5)

    @task
    def check_json(self):
        self.client.post(
            "/v1/check/headers?format=json",
            json={"target": random_domain()},
            name="/v1/check/headers [json]",
        )

    @task
    def check_sarif(self):
        self.client.post(
            "/v1/check/headers?format=sarif",
            json={"target": random_domain()},
            name="/v1/check/headers [sarif]",
        )

    @task
    def check_csv(self):
        self.client.post(
            "/v1/check/headers?format=csv",
            json={"target": random_domain()},
            name="/v1/check/headers [csv]",
        )

    @task
    def scan_sarif(self):
        self.client.post(
            "/v1/scan?format=sarif",
            json={"targets": [random_domain()]},
            name="/v1/scan [sarif fmt]",
        )

    @task
    def scan_csv(self):
        self.client.post(
            "/v1/scan?format=csv",
            json={"targets": [random_domain()]},
            name="/v1/scan [csv fmt]",
        )


# ---------------------------------------------------------------------------
# 9. Error path testing
# ---------------------------------------------------------------------------


class ErrorPathUser(InfraProbeUser):
    """Tests error paths: blocked targets, invalid inputs, 404 jobs."""

    wait_time = between(1, 3)

    @task
    def blocked_target(self):
        """SSRF-blocked private IP should return 400."""
        with self.client.post(
            "/v1/check/headers",
            json={"target": "127.0.0.1"},
            name="/v1/check/headers [blocked]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 400:
                resp.success()
            else:
                resp.failure(f"Expected 400 for blocked target, got {resp.status_code}")

    @task
    def invalid_target(self):
        """Empty target should return 422."""
        with self.client.post(
            "/v1/check/headers",
            json={"target": ""},
            name="/v1/check/headers [invalid]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 422:
                resp.success()
            else:
                resp.failure(f"Expected 422 for invalid target, got {resp.status_code}")

    @task
    def not_found_job(self):
        """Non-existent job_id should return 404."""
        with self.client.get(
            "/v1/scan/nonexistent-job-id",
            name="/v1/scan/[job_id] [404]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 404:
                resp.success()
            else:
                resp.failure(f"Expected 404 for missing job, got {resp.status_code}")

    @task
    def dns_check_on_ip(self):
        """DNS check on an IP target should return 422 via check_ip."""
        with self.client.post(
            "/v1/check_ip/dns",
            json={"target": "8.8.8.8"},
            name="/v1/check_ip/dns [rejected]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 422:
                resp.success()
            else:
                resp.failure(f"Expected 422 for DNS on IP, got {resp.status_code}")
