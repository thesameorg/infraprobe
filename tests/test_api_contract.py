"""API contract tests for the InfraProbe v1 API surface.

Verifies:
- POST /v1/scan returns 200 (always sync, fixed checks)
- GET /v1/scan/{job_id} returns poll + results + format
- POST /v1/check/{type} returns 200 (fast) or 202 (slow)
- Summary field computed correctly
- Removed routes return 404
- Health / readiness / metrics endpoints
"""

from datetime import UTC, datetime

import pytest
from helpers import submit_scan

from infraprobe.models import (
    CheckResult,
    CheckType,
    Finding,
    Job,
    JobStatus,
    ScanRequest,
    ScanResponse,
    Severity,
    TargetResult,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# POST /v1/scan — always sync (200), fixed check bundle
# ---------------------------------------------------------------------------


class TestScanEndpoint:
    def test_scan_returns_200(self, client):
        """Scan always returns sync 200 with direct ScanResponse."""
        resp = client.post("/v1/scan", json={"target": "example.com"})
        assert resp.status_code == 200
        body = resp.json()
        assert "results" in body
        assert "summary" in body

    def test_scan_auto_detects_domain_checks(self, client):
        """Domain target → headers, ssl, dns, web, whois."""
        result = submit_scan(client, {"target": "example.com"})
        target_result = result["results"][0]
        expected = {"headers", "ssl", "dns", "web", "whois"}
        assert set(target_result["results"].keys()) == expected

    def test_scan_ip_auto_detects_ip_checks(self, client):
        """IP target → headers, ssl, web (no dns, no whois)."""
        result = submit_scan(client, {"target": "93.184.216.34"})
        target_result = result["results"][0]
        assert "dns" not in target_result["results"]
        assert "whois" not in target_result["results"]
        assert "headers" in target_result["results"]
        assert "web" in target_result["results"]

    def test_scan_missing_target_422(self, client):
        resp = client.post("/v1/scan", json={})
        assert resp.status_code == 422

    def test_scan_blocked_target_400(self, client):
        resp = client.post("/v1/scan", json={"target": "127.0.0.1"})
        assert resp.status_code == 400
        assert resp.json()["error"] == "blocked_target"


# ---------------------------------------------------------------------------
# GET /v1/scan/{job_id} — poll + results
# ---------------------------------------------------------------------------


class TestGetScanJob:
    def test_nonexistent_job_404(self, client):
        resp = client.get("/v1/scan/does-not-exist")
        assert resp.status_code == 404
        assert resp.json()["error"] == "not_found"

    def test_pending_job_returns_200(self, client):
        """A running job returns 200 with status, not 4xx."""
        store = client.app.state.job_store
        now = datetime.now(UTC)
        store._jobs["running-contract"] = Job(
            job_id="running-contract",
            status=JobStatus.RUNNING,
            created_at=now,
            updated_at=now,
            request=ScanRequest(target="example.com", checks=[CheckType.HEADERS]),
        )
        resp = client.get("/v1/scan/running-contract")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"
        assert data["result"] is None

    def test_failed_job_returns_error(self, client):
        store = client.app.state.job_store
        now = datetime.now(UTC)
        store._jobs["failed-contract"] = Job(
            job_id="failed-contract",
            status=JobStatus.FAILED,
            created_at=now,
            updated_at=now,
            request=ScanRequest(target="example.com", checks=[CheckType.HEADERS]),
            error="network timeout",
        )
        resp = client.get("/v1/scan/failed-contract")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "failed"
        assert data["error"] == "network timeout"


# ---------------------------------------------------------------------------
# POST /v1/check/{type} — fast vs slow
# ---------------------------------------------------------------------------


class TestCheckEndpoint:
    def test_fast_check_returns_200(self, client):
        """Headers check is fast → returns 200 inline."""
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["target"] == "example.com"
        assert "headers" in data["results"]
        assert "duration_ms" in data

    def test_ssl_check_returns_200(self, client):
        resp = client.post("/v1/check/ssl", json={"target": "example.com"})
        assert resp.status_code == 200
        assert "ssl" in resp.json()["results"]

    def test_dns_check_returns_200(self, client):
        resp = client.post("/v1/check/dns", json={"target": "example.com"})
        assert resp.status_code == 200
        assert "dns" in resp.json()["results"]

    def test_ports_check_returns_200(self, client):
        """Ports check is sync (nmap top-20 is fast enough)."""
        resp = client.post("/v1/check/ports", json={"target": "scanme.nmap.org"})
        assert resp.status_code == 200
        data = resp.json()
        assert "ports" in data["results"]

    def test_async_check_cve_returns_202(self, client):
        """CVE check is async → returns 202 with job_id."""
        resp = client.post("/v1/check/cve", json={"target": "scanme.nmap.org"})
        assert resp.status_code == 202
        assert "job_id" in resp.json()

    def test_check_blocked_target_400(self, client):
        resp = client.post("/v1/check/headers", json={"target": "127.0.0.1"})
        assert resp.status_code == 400
        assert resp.json()["error"] == "blocked_target"

    def test_check_dns_on_ip_rejected(self, client):
        resp = client.post("/v1/check/dns", json={"target": "93.184.216.34"})
        assert resp.status_code == 422

    def test_check_whois_on_ip_rejected(self, client):
        resp = client.post("/v1/check/whois", json={"target": "8.8.8.8"})
        assert resp.status_code == 422

    def test_check_nonexistent_type_404(self, client):
        resp = client.post("/v1/check/nonexistent", json={"target": "example.com"})
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Summary field
# ---------------------------------------------------------------------------


class TestSummaryField:
    def test_target_result_has_summary(self, client):
        """TargetResult from inline check should include a summary with severity counts."""
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        assert resp.status_code == 200
        data = resp.json()
        summary = data["summary"]
        assert "critical" in summary
        assert "high" in summary
        assert "medium" in summary
        assert "low" in summary
        assert "info" in summary
        assert "total" in summary
        # Total should equal sum of all severity counts
        assert summary["total"] == (
            summary["critical"] + summary["high"] + summary["medium"] + summary["low"] + summary["info"]
        )

    def test_scan_response_has_summary(self, client):
        """ScanResponse from bundle scan should include an aggregate summary."""
        result = submit_scan(client, {"target": "example.com"})
        assert "summary" in result
        summary = result["summary"]
        assert summary["total"] >= 0
        # Per-target summary should also be present
        target_summary = result["results"][0]["summary"]
        assert target_summary["total"] == summary["total"]  # single target: same

    def test_summary_unit_computation(self):
        """Summary should be computed correctly from findings."""
        findings = [
            Finding(severity=Severity.CRITICAL, title="A", description="d"),
            Finding(severity=Severity.HIGH, title="B", description="d"),
            Finding(severity=Severity.HIGH, title="C", description="d"),
            Finding(severity=Severity.INFO, title="D", description="d"),
        ]
        cr = CheckResult(check=CheckType.HEADERS, findings=findings)
        tr = TargetResult(target="example.com", results={"headers": cr}, duration_ms=100)
        assert tr.summary.critical == 1
        assert tr.summary.high == 2
        assert tr.summary.medium == 0
        assert tr.summary.low == 0
        assert tr.summary.info == 1
        assert tr.summary.total == 4

    def test_scan_response_summary_aggregates_targets(self):
        """ScanResponse summary should aggregate across all targets."""
        f1 = Finding(severity=Severity.HIGH, title="A", description="d")
        f2 = Finding(severity=Severity.CRITICAL, title="B", description="d")
        tr1 = TargetResult(
            target="a.com",
            results={"headers": CheckResult(check=CheckType.HEADERS, findings=[f1])},
            duration_ms=50,
        )
        tr2 = TargetResult(
            target="b.com",
            results={"ssl": CheckResult(check=CheckType.SSL, findings=[f2])},
            duration_ms=50,
        )
        resp = ScanResponse(results=[tr1, tr2])
        assert resp.summary.high == 1
        assert resp.summary.critical == 1
        assert resp.summary.total == 2


# ---------------------------------------------------------------------------
# Removed routes → 404
# ---------------------------------------------------------------------------


class TestRemovedRoutes:
    """Old API routes that were removed should return 404."""

    def test_scan_domain_removed(self, client):
        resp = client.post("/v1/scan_domain", json={"target": "example.com"})
        assert resp.status_code in (404, 405)

    def test_scan_ip_removed(self, client):
        resp = client.post("/v1/scan_ip", json={"target": "93.184.216.34"})
        assert resp.status_code in (404, 405)

    def test_check_domain_removed(self, client):
        resp = client.post("/v1/check_domain/headers", json={"target": "example.com"})
        assert resp.status_code in (404, 405)

    def test_check_ip_removed(self, client):
        resp = client.post("/v1/check_ip/headers", json={"target": "93.184.216.34"})
        assert resp.status_code in (404, 405)

    def test_check_deep_removed(self, client):
        resp = client.post("/v1/check_deep/ssl", json={"target": "example.com"})
        assert resp.status_code in (404, 405)

    def test_scan_async_removed(self, client):
        resp = client.post("/v1/scan/async", json={"target": "example.com"})
        # /scan/async is now matched by /scan/{job_id} with job_id="async" → 404 from store
        # or it might match POST /scan and fail differently — either way, not the old 202 behavior
        assert resp.status_code != 202

    def test_scan_report_removed(self, client):
        resp = client.get("/v1/scan/some-job-id/report")
        assert resp.status_code == 404

    def test_unversioned_scan_removed(self, client):
        resp = client.post("/scan", json={"target": "example.com"})
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Health / readiness / metrics
# ---------------------------------------------------------------------------


class TestInternalEndpoints:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_ready(self, client):
        resp = client.get("/health/ready")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

    def test_metrics(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        # Prometheus metrics format
        assert "infraprobe" in resp.text or "python" in resp.text


# ---------------------------------------------------------------------------
# Response structure validation
# ---------------------------------------------------------------------------


class TestResponseStructure:
    def test_sync_scan_response_shape(self, client):
        """POST /v1/scan → 200 with ScanResponse shape."""
        resp = client.post("/v1/scan", json={"target": "example.com"})
        assert resp.status_code == 200
        body = resp.json()
        assert "results" in body
        assert "summary" in body
        assert len(body["results"]) == 1

    def test_job_completed_shape(self, client):
        """Completed job has all Job fields (no webhook fields)."""
        store = client.app.state.job_store
        now = datetime.now(UTC)
        finding = Finding(severity=Severity.HIGH, title="Test", description="d")
        tr = TargetResult(
            target="example.com",
            results={"headers": CheckResult(check=CheckType.HEADERS, findings=[finding])},
            duration_ms=100,
        )
        store._jobs["shape-test"] = Job(
            job_id="shape-test",
            status=JobStatus.COMPLETED,
            created_at=now,
            updated_at=now,
            request=ScanRequest(target="example.com", checks=[CheckType.HEADERS]),
            result=ScanResponse(results=[tr]),
        )
        resp = client.get("/v1/scan/shape-test")
        assert resp.status_code == 200
        job = resp.json()
        expected_keys = {
            "job_id",
            "status",
            "created_at",
            "updated_at",
            "request",
            "result",
            "error",
        }
        assert set(job.keys()) == expected_keys
        assert job["status"] == "completed"
        assert job["result"] is not None
        assert job["error"] is None

    def test_target_result_shape(self, client):
        """Inline check returns TargetResult with expected fields."""
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        data = resp.json()
        assert "target" in data
        assert "results" in data
        assert "duration_ms" in data
        assert "summary" in data

    def test_check_result_shape(self, client):
        """Each CheckResult in results has check, findings, raw, error, timing."""
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        cr = resp.json()["results"]["headers"]
        assert "check" in cr
        assert "findings" in cr
        assert "raw" in cr
        assert "error" in cr
        assert "duration_ms" in cr
        assert "timeout_ms" in cr

    def test_finding_shape(self, client):
        """Each Finding has severity, title, description, details."""
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        findings = resp.json()["results"]["headers"]["findings"]
        assert len(findings) > 0
        f = findings[0]
        expected_keys = {"severity", "title", "description", "details"}
        assert set(f.keys()) == expected_keys
        assert f["severity"] in {"critical", "high", "medium", "low", "info"}
