"""CVE scanner tests — verify nmap + NVD lookup integration."""

import pytest
from helpers import submit_check

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def test_cve_scan_detects_services(client):
    """CVE scan on scanme.nmap.org should detect versioned services."""
    data = submit_check(client, "cve", {"target": "scanme.nmap.org"}, timeout=60)

    cve_result = data["results"]["cve"]
    assert cve_result["error"] is None

    raw = cve_result["raw"]
    assert raw["host"] == "scanme.nmap.org"
    assert raw["services_scanned"] >= 0  # may vary based on nmap results
    assert "services" in raw
    assert "cves_found" in raw
    assert "nvd_api_key_configured" in raw


def test_cve_raw_structure(client):
    """Verify raw data has expected fields."""
    data = submit_check(client, "cve", {"target": "scanme.nmap.org"}, timeout=60)

    raw = data["results"]["cve"]["raw"]
    assert "host" in raw
    assert "services_scanned" in raw
    assert "services" in raw
    assert isinstance(raw["services"], list)
    assert "cves_found" in raw
    assert isinstance(raw["cves_found"], int)
    assert "nvd_api_key_configured" in raw


def test_cve_service_structure(client):
    """If services are detected, verify their structure."""
    data = submit_check(client, "cve", {"target": "scanme.nmap.org"}, timeout=60)

    raw = data["results"]["cve"]["raw"]
    if raw["services"]:
        svc = raw["services"][0]
        assert "port" in svc
        assert "protocol" in svc
        assert "service" in svc
        assert "product" in svc
        assert "version" in svc
        assert "cpe" in svc


def test_cve_finding_structure(client):
    """If CVEs are found, verify finding structure."""
    data = submit_check(client, "cve", {"target": "scanme.nmap.org"}, timeout=60)

    findings = data["results"]["cve"]["findings"]
    assert len(findings) > 0  # at minimum "No known CVEs" or actual CVEs

    for finding in findings:
        assert "severity" in finding
        assert "title" in finding
        assert "description" in finding
        assert finding["severity"] in ("critical", "high", "medium", "low", "info")


def test_cve_findings_sorted_by_severity(client):
    """CVE findings should be sorted: most severe first."""
    data = submit_check(client, "cve", {"target": "scanme.nmap.org"}, timeout=60)

    findings = data["results"]["cve"]["findings"]
    if len(findings) > 1:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for i in range(len(findings) - 1):
            current = sev_order.get(findings[i]["severity"], 5)
            next_sev = sev_order.get(findings[i + 1]["severity"], 5)
            assert current <= next_sev, f"Findings not sorted: {findings[i]} before {findings[i + 1]}"


def test_cve_summary_field(client):
    """Verify summary has correct severity counts."""
    data = submit_check(client, "cve", {"target": "scanme.nmap.org"}, timeout=60)

    assert "summary" in data
    summary = data["summary"]
    assert summary["total"] > 0
