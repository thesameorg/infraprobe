"""Tests for output format support (JSON default + SARIF)."""

import json

import pytest

from infraprobe.formatters.sarif import scan_response_to_sarif, target_result_to_sarif
from infraprobe.models import (
    CheckResult,
    CheckType,
    Finding,
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
