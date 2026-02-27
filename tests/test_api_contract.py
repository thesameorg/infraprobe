"""API contract tests for the InfraProbe v1 API surface.

Verifies:
- POST /v1/scan returns 200 (always sync, fixed checks)
- Summary field computed correctly
- Removed routes return 404
- Health / readiness / metrics endpoints
"""

import pytest
from helpers import submit_scan

from infraprobe.models import (
    CheckResult,
    CheckType,
    Finding,
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
# Summary field
# ---------------------------------------------------------------------------


class TestSummaryField:
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

    def test_check_endpoint_removed(self, client):
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        assert resp.status_code in (404, 405)

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
