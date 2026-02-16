"""Tests for output format support (JSON default + SARIF + CSV) and GET report endpoint."""

import csv
import io
import json
from datetime import UTC, datetime

import pytest

from infraprobe.formatters.csv import scan_response_to_csv, target_result_to_csv
from infraprobe.formatters.sarif import scan_response_to_sarif, target_result_to_sarif
from infraprobe.models import (
    CheckResult,
    CheckType,
    Finding,
    Job,
    JobStatus,
    ScanRequest,
    ScanResponse,
    Severity,
    SeveritySummary,
    TargetResult,
)

# ---------------------------------------------------------------------------
# Helpers — build model objects without network calls
# ---------------------------------------------------------------------------


def _finding(severity: Severity, title: str, description: str = "desc") -> Finding:
    return Finding(severity=severity, title=title, description=description)


def _check_result(check: CheckType, findings: list[Finding] | None = None, error: str | None = None) -> CheckResult:
    return CheckResult(check=check, findings=findings or [], error=error)


def _target_result(target: str, results: dict[str, CheckResult]) -> TargetResult:
    return TargetResult(
        target=target,
        score="B",
        summary=SeveritySummary(),
        results=results,
        duration_ms=100,
    )


# ---------------------------------------------------------------------------
# Unit tests — SARIF converter (no network)
# ---------------------------------------------------------------------------


class TestSarifStructure:
    """Verify the SARIF 2.1.0 envelope is well-formed."""

    def test_basic_structure(self):
        finding = _finding(Severity.HIGH, "Missing HSTS")
        tr = _target_result("example.com", {"headers": _check_result(CheckType.HEADERS, [finding])})
        sarif = target_result_to_sarif(tr)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "InfraProbe"
        assert "version" in run["tool"]["driver"]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1

    def test_empty_findings_produces_valid_sarif(self):
        tr = _target_result("example.com", {"headers": _check_result(CheckType.HEADERS)})
        sarif = target_result_to_sarif(tr)

        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["rules"] == []
        assert run["results"] == []

    def test_errored_check_with_no_findings_omitted(self):
        tr = _target_result(
            "example.com",
            {
                "headers": _check_result(CheckType.HEADERS, error="Scanner timed out"),
                "ssl": _check_result(CheckType.SSL, [_finding(Severity.LOW, "Weak cipher")]),
            },
        )
        sarif = target_result_to_sarif(tr)
        run = sarif["runs"][0]
        # Only the ssl finding should appear
        assert len(run["results"]) == 1
        assert run["results"][0]["ruleId"] == "ssl/weak-cipher"


class TestSeverityMapping:
    """Each severity maps to the correct SARIF level and security-severity."""

    @pytest.mark.parametrize(
        "severity,expected_level,expected_score",
        [
            (Severity.CRITICAL, "error", "9.5"),
            (Severity.HIGH, "error", "8.0"),
            (Severity.MEDIUM, "warning", "5.5"),
            (Severity.LOW, "note", "3.0"),
            (Severity.INFO, "note", "1.0"),
        ],
    )
    def test_severity_to_sarif(self, severity, expected_level, expected_score):
        tr = _target_result("t.com", {"headers": _check_result(CheckType.HEADERS, [_finding(severity, "Test")])})
        sarif = target_result_to_sarif(tr)
        run = sarif["runs"][0]

        assert run["results"][0]["level"] == expected_level
        assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == expected_score


class TestRuleDeduplication:
    """Same finding title across targets should produce one rule, multiple results."""

    def test_dedup_across_targets(self):
        finding = _finding(Severity.HIGH, "Missing HSTS")
        tr1 = _target_result("a.com", {"headers": _check_result(CheckType.HEADERS, [finding])})
        tr2 = _target_result("b.com", {"headers": _check_result(CheckType.HEADERS, [finding])})
        resp = ScanResponse(results=[tr1, tr2])
        sarif = scan_response_to_sarif(resp)
        run = sarif["runs"][0]

        # One rule, two results
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 2
        assert run["results"][0]["ruleId"] == run["results"][1]["ruleId"]

    def test_different_titles_different_rules(self):
        tr = _target_result(
            "a.com",
            {
                "headers": _check_result(
                    CheckType.HEADERS,
                    [_finding(Severity.HIGH, "Missing HSTS"), _finding(Severity.MEDIUM, "No CSP")],
                )
            },
        )
        sarif = target_result_to_sarif(tr)
        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 2


class TestSarifLocations:
    """Verify artifact location and region."""

    def test_target_in_artifact_uri(self):
        finding = _finding(Severity.LOW, "Old TLS")
        tr = _target_result("example.com:8443", {"ssl": _check_result(CheckType.SSL, [finding])})
        sarif = target_result_to_sarif(tr)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "example.com:8443"
        assert loc["region"]["startLine"] == 1


class TestRuleIdFormat:
    """Rule IDs should be {check}/{slugified-title}."""

    def test_rule_id_slugified(self):
        tr = _target_result(
            "x.com",
            {"headers": _check_result(CheckType.HEADERS, [_finding(Severity.HIGH, "Server Header Leak (info)")])},
        )
        sarif = target_result_to_sarif(tr)
        rule_id = sarif["runs"][0]["results"][0]["ruleId"]
        assert rule_id == "headers/server-header-leak-info"


# ---------------------------------------------------------------------------
# Integration tests — format query parameter on real endpoints
# ---------------------------------------------------------------------------


class TestFormatQueryParam:
    """Test ?format= query parameter on live endpoints."""

    def test_default_format_is_json(self, client):
        resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["headers"]})
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        # Should be normal JSON (has "results" key)
        assert "results" in resp.json()

    def test_explicit_json_format(self, client):
        resp = client.post("/v1/scan?format=json", json={"targets": ["example.com"], "checks": ["headers"]})
        assert resp.status_code == 200
        assert "results" in resp.json()

    def test_sarif_format_on_scan(self, client):
        resp = client.post("/v1/scan?format=sarif", json={"targets": ["example.com"], "checks": ["headers"]})
        assert resp.status_code == 200
        assert "sarif" in resp.headers["content-type"]

        sarif = resp.json()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "InfraProbe"
        # Should have at least one result (example.com has header findings)
        assert len(sarif["runs"][0]["results"]) > 0

    def test_sarif_format_on_check_headers(self, client):
        resp = client.post("/v1/check/headers?format=sarif", json={"target": "example.com"})
        assert resp.status_code == 200
        assert "sarif" in resp.headers["content-type"]

        sarif = resp.json()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) > 0

    def test_sarif_format_on_check_domain(self, client):
        resp = client.post("/v1/check_domain/headers?format=sarif", json={"target": "example.com"})
        assert resp.status_code == 200
        assert "sarif" in resp.headers["content-type"]

        sarif = resp.json()
        assert sarif["version"] == "2.1.0"

    def test_invalid_format_returns_422(self, client):
        resp = client.post("/v1/scan?format=xml", json={"targets": ["example.com"], "checks": ["headers"]})
        assert resp.status_code == 422

    def test_sarif_is_valid_json(self, client):
        """SARIF response should be parseable JSON."""
        resp = client.post("/v1/check/headers?format=sarif", json={"target": "example.com"})
        assert resp.status_code == 200
        # Should not raise
        sarif = json.loads(resp.content)
        assert isinstance(sarif, dict)

    def test_error_responses_stay_json(self, client):
        """Error responses (blocked target) should always be JSON, not SARIF."""
        resp = client.post("/v1/scan?format=sarif", json={"targets": ["127.0.0.1"], "checks": ["headers"]})
        assert resp.status_code == 400
        assert resp.headers["content-type"].startswith("application/json")
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# Unit tests — CSV converter (no network)
# ---------------------------------------------------------------------------


def _parse_csv(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


class TestCsvStructure:
    """Verify CSV output structure."""

    def test_header_row(self):
        tr = _target_result("example.com", {"headers": _check_result(CheckType.HEADERS)})
        rows = _parse_csv(target_result_to_csv(tr))
        assert rows[0] == ["target", "check", "severity", "title", "description", "details", "score"]

    def test_finding_produces_row(self):
        finding = _finding(Severity.HIGH, "Missing HSTS", "No HSTS header found")
        tr = _target_result("example.com", {"headers": _check_result(CheckType.HEADERS, [finding])})
        rows = _parse_csv(target_result_to_csv(tr))
        assert len(rows) == 2  # header + 1 finding
        row = rows[1]
        assert row[0] == "example.com"
        assert row[1] == "headers"
        assert row[2] == "high"
        assert row[3] == "Missing HSTS"
        assert row[4] == "No HSTS header found"
        assert row[6] == "B"

    def test_multiple_findings(self):
        findings = [
            _finding(Severity.HIGH, "Missing HSTS"),
            _finding(Severity.MEDIUM, "No CSP"),
        ]
        tr = _target_result("a.com", {"headers": _check_result(CheckType.HEADERS, findings)})
        rows = _parse_csv(target_result_to_csv(tr))
        assert len(rows) == 3  # header + 2 findings

    def test_error_check_produces_error_row(self):
        tr = _target_result("a.com", {"ssl": _check_result(CheckType.SSL, error="Connection refused")})
        rows = _parse_csv(target_result_to_csv(tr))
        assert len(rows) == 2
        row = rows[1]
        assert row[2] == "error"
        assert row[3] == "Scanner error"
        assert row[4] == "Connection refused"

    def test_clean_check_omitted(self):
        """Checks with no findings and no error produce no rows."""
        tr = _target_result("a.com", {"headers": _check_result(CheckType.HEADERS)})
        rows = _parse_csv(target_result_to_csv(tr))
        assert len(rows) == 1  # header only

    def test_multi_target_csv(self):
        finding = _finding(Severity.LOW, "Old TLS")
        tr1 = _target_result("a.com", {"ssl": _check_result(CheckType.SSL, [finding])})
        tr2 = _target_result("b.com", {"ssl": _check_result(CheckType.SSL, [finding])})
        resp = ScanResponse(results=[tr1, tr2])
        rows = _parse_csv(scan_response_to_csv(resp))
        assert len(rows) == 3  # header + 2 findings
        assert rows[1][0] == "a.com"
        assert rows[2][0] == "b.com"

    def test_details_json_encoded(self):
        finding = Finding(severity=Severity.INFO, title="Tech", description="d", details={"name": "nginx"})
        tr = _target_result("x.com", {"tech": _check_result(CheckType.TECH, [finding])})
        rows = _parse_csv(target_result_to_csv(tr))
        parsed = json.loads(rows[1][5])
        assert parsed == {"name": "nginx"}

    def test_empty_details_is_blank(self):
        finding = _finding(Severity.INFO, "Test")
        tr = _target_result("x.com", {"headers": _check_result(CheckType.HEADERS, [finding])})
        rows = _parse_csv(target_result_to_csv(tr))
        assert rows[1][5] == ""

    def test_column_count_consistent(self):
        findings = [_finding(Severity.HIGH, "A"), _finding(Severity.LOW, "B")]
        tr = _target_result(
            "x.com",
            {
                "headers": _check_result(CheckType.HEADERS, findings),
                "ssl": _check_result(CheckType.SSL, error="timeout"),
            },
        )
        rows = _parse_csv(target_result_to_csv(tr))
        for row in rows:
            assert len(row) == 7


# ---------------------------------------------------------------------------
# Integration tests — CSV format query parameter on real endpoints
# ---------------------------------------------------------------------------


class TestCsvFormatQueryParam:
    """Test ?format=csv query parameter on live endpoints."""

    def test_csv_format_on_scan(self, client):
        resp = client.post("/v1/scan?format=csv", json={"targets": ["example.com"], "checks": ["headers"]})
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        rows = _parse_csv(resp.text)
        assert rows[0] == ["target", "check", "severity", "title", "description", "details", "score"]
        assert len(rows) > 1  # at least one finding

    def test_csv_format_on_check_headers(self, client):
        resp = client.post("/v1/check/headers?format=csv", json={"target": "example.com"})
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        rows = _parse_csv(resp.text)
        assert rows[0][0] == "target"
        assert len(rows) > 1

    def test_csv_format_on_check_domain(self, client):
        resp = client.post("/v1/check_domain/headers?format=csv", json={"target": "example.com"})
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")

    def test_csv_error_responses_stay_json(self, client):
        """Error responses (blocked target) should always be JSON, not CSV."""
        resp = client.post("/v1/scan?format=csv", json={"targets": ["127.0.0.1"], "checks": ["headers"]})
        assert resp.status_code == 400
        assert resp.headers["content-type"].startswith("application/json")
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# GET /v1/scan/{job_id}/report — unit tests (seed jobs directly in store)
# ---------------------------------------------------------------------------


def _completed_job(job_id: str = "test-job") -> Job:
    finding = Finding(severity=Severity.HIGH, title="Missing HSTS", description="No HSTS header")
    tr = _target_result("example.com", {"headers": _check_result(CheckType.HEADERS, [finding])})
    now = datetime.now(UTC)
    return Job(
        job_id=job_id,
        status=JobStatus.COMPLETED,
        created_at=now,
        updated_at=now,
        request=ScanRequest(targets=["example.com"], checks=[CheckType.HEADERS]),
        result=ScanResponse(results=[tr]),
    )


class TestGetScanReport:
    """Test GET /v1/scan/{job_id}/report endpoint."""

    def test_report_not_found(self, client):
        resp = client.get("/v1/scan/nonexistent/report")
        assert resp.status_code == 404

    def test_report_pending_job_returns_409(self, client):
        store = client.app.state.job_store
        now = datetime.now(UTC)
        store._jobs["pending-job"] = Job(
            job_id="pending-job",
            status=JobStatus.RUNNING,
            created_at=now,
            updated_at=now,
            request=ScanRequest(targets=["example.com"], checks=[CheckType.HEADERS]),
        )
        resp = client.get("/v1/scan/pending-job/report")
        assert resp.status_code == 409
        assert "running" in resp.json()["detail"]

    def test_report_json(self, client):
        store = client.app.state.job_store
        job = _completed_job("json-job")
        store._jobs[job.job_id] = job

        resp = client.get("/v1/scan/json-job/report")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        data = resp.json()
        assert "results" in data
        assert data["results"][0]["target"] == "example.com"

    def test_report_sarif(self, client):
        store = client.app.state.job_store
        job = _completed_job("sarif-job")
        store._jobs[job.job_id] = job

        resp = client.get("/v1/scan/sarif-job/report?format=sarif")
        assert resp.status_code == 200
        assert "sarif" in resp.headers["content-type"]
        sarif = resp.json()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1

    def test_report_csv(self, client):
        store = client.app.state.job_store
        job = _completed_job("csv-job")
        store._jobs[job.job_id] = job

        resp = client.get("/v1/scan/csv-job/report?format=csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        rows = _parse_csv(resp.text)
        assert rows[0] == ["target", "check", "severity", "title", "description", "details", "score"]
        assert len(rows) == 2
        assert rows[1][0] == "example.com"

    def test_report_failed_job_returns_409(self, client):
        store = client.app.state.job_store
        now = datetime.now(UTC)
        store._jobs["failed-job"] = Job(
            job_id="failed-job",
            status=JobStatus.FAILED,
            created_at=now,
            updated_at=now,
            request=ScanRequest(targets=["example.com"], checks=[CheckType.HEADERS]),
            error="Something broke",
        )
        resp = client.get("/v1/scan/failed-job/report")
        assert resp.status_code == 409
        assert "failed" in resp.json()["detail"]
