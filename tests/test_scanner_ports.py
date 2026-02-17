"""Integration tests for the port scanner — real targets, no mocks.

These tests run nmap against live hosts and are SLOW.
"""

import pytest
from helpers import submit_check

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def test_port_scan_scanme(client):
    """Scan scanme.nmap.org — should find open ports (at least SSH/22 or HTTP/80)."""
    data = submit_check(client, "ports", {"target": "scanme.nmap.org"}, timeout=60)

    assert data["target"] == "scanme.nmap.org"
    ports_result = data["results"]["ports"]
    assert ports_result["error"] is None

    raw = ports_result["raw"]
    assert raw["open_count"] > 0, "Expected open ports on scanme.nmap.org, got none"

    # scanme.nmap.org should have at least SSH (22) or HTTP (80)
    open_port_numbers = [p["port"] for p in raw["open_ports"]]
    assert 22 in open_port_numbers or 80 in open_port_numbers, (
        f"Expected port 22 or 80 open on scanme.nmap.org, got: {open_port_numbers}"
    )

    # Findings should exist and match open ports
    assert len(ports_result["findings"]) > 0
    finding_titles = [f["title"] for f in ports_result["findings"]]
    assert any("open" in t.lower() for t in finding_titles), f"Expected 'open' in finding titles, got: {finding_titles}"


def test_port_scan_raw_structure(client):
    """Verify raw has: host, ports (list as open_ports), open_count."""
    data = submit_check(client, "ports", {"target": "scanme.nmap.org"}, timeout=60)

    ports_result = data["results"]["ports"]
    assert ports_result["error"] is None

    raw = ports_result["raw"]
    # Required top-level keys
    assert "host" in raw
    assert "open_ports" in raw
    assert "open_count" in raw
    assert "command_line" in raw

    # Types
    assert isinstance(raw["open_ports"], list)
    assert isinstance(raw["open_count"], int)
    assert raw["open_count"] == len(raw["open_ports"])

    # Each port entry should have the expected fields
    if raw["open_count"] > 0:
        port_entry = raw["open_ports"][0]
        assert "port" in port_entry
        assert "protocol" in port_entry
        assert "state" in port_entry
        assert "service" in port_entry
        assert "product" in port_entry
        assert "version" in port_entry
        assert port_entry["state"] == "open"
        assert isinstance(port_entry["port"], int)


def test_port_risk_classification(client):
    """Verify findings have severity levels (CRITICAL for Redis/MongoDB, HIGH for FTP, etc.)."""
    data = submit_check(client, "ports", {"target": "scanme.nmap.org"}, timeout=60)

    ports_result = data["results"]["ports"]
    assert ports_result["error"] is None
    assert len(ports_result["findings"]) > 0

    valid_severities = {"critical", "high", "medium", "low", "info"}
    for finding in ports_result["findings"]:
        assert finding["severity"] in valid_severities, (
            f"Invalid severity '{finding['severity']}' for finding: {finding['title']}"
        )

    # SSH (port 22) should be classified as INFO if present
    ssh_findings = [f for f in ports_result["findings"] if f.get("details", {}).get("port") == 22]
    if ssh_findings:
        assert ssh_findings[0]["severity"] == "info", f"SSH should be INFO severity, got: {ssh_findings[0]['severity']}"

    # HTTP (port 80) should be classified as INFO if present
    http_findings = [f for f in ports_result["findings"] if f.get("details", {}).get("port") == 80]
    if http_findings:
        assert http_findings[0]["severity"] == "info", (
            f"HTTP should be INFO severity, got: {http_findings[0]['severity']}"
        )


def test_port_scan_example_com(client):
    """Scan example.com — should find HTTP/HTTPS open."""
    data = submit_check(client, "ports", {"target": "example.com"}, timeout=60)

    assert data["target"] == "example.com"
    ports_result = data["results"]["ports"]
    assert ports_result["error"] is None

    raw = ports_result["raw"]
    open_port_numbers = [p["port"] for p in raw["open_ports"]]

    # example.com should have at least HTTP (80) or HTTPS (443) open
    assert 80 in open_port_numbers or 443 in open_port_numbers, (
        f"Expected port 80 or 443 open on example.com, got: {open_port_numbers}"
    )

    # Verify the services are correctly identified
    for port_entry in raw["open_ports"]:
        if port_entry["port"] == 80:
            assert port_entry["service"] in ("http", "http-alt", ""), (
                f"Expected HTTP service on port 80, got: {port_entry['service']}"
            )
        if port_entry["port"] == 443:
            assert port_entry["service"] in ("https", "http", "https-alt", ""), (
                f"Expected HTTPS service on port 443, got: {port_entry['service']}"
            )
