"""Integration tests for the WHOIS scanner — real targets, no mocks."""

import pytest

pytestmark = pytest.mark.integration


def test_whois_google(client):
    """Scan google.com — should return registrar info, created/expires dates."""
    resp = client.post("/v1/check/whois", json={"target": "google.com"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["target"] == "google.com"
    whois_result = data["results"]["whois"]
    assert whois_result["error"] is None

    # Should have meaningful findings
    assert len(whois_result["findings"]) > 0

    titles = [f["title"] for f in whois_result["findings"]]
    assert "Registrar identified" in titles, f"Expected registrar finding, got: {titles}"
    assert "Domain age" in titles, f"Expected domain age finding, got: {titles}"
    assert "Domain expiration" in titles, f"Expected domain expiration finding, got: {titles}"

    # Raw should contain registrar and dates
    raw = whois_result["raw"]
    assert raw["domain"] == "google.com"
    assert raw.get("registrar"), "google.com should have a registrar"
    assert raw.get("created"), "google.com should have a creation date"
    assert raw.get("expires"), "google.com should have an expiration date"

    # summary should be present at the TargetResult level
    summary = data["summary"]
    assert summary["total"] > 0


def test_whois_raw_structure(client):
    """Verify raw has: domain, registrar, created, expires, dnssec, name_servers."""
    resp = client.post("/v1/check/whois", json={"target": "google.com"})
    assert resp.status_code == 200

    whois_result = resp.json()["results"]["whois"]
    assert whois_result["error"] is None

    raw = whois_result["raw"]
    assert "domain" in raw
    assert "registrar" in raw
    assert "created" in raw
    assert "expires" in raw
    assert "dnssec" in raw
    assert "name_servers" in raw

    # domain should be the queried domain
    assert raw["domain"] == "google.com"
    # registrar should be a non-empty string
    assert isinstance(raw["registrar"], str)
    assert len(raw["registrar"]) > 0
    # name_servers should be a list
    assert isinstance(raw["name_servers"], list)
    assert len(raw["name_servers"]) > 0


def test_whois_expiry_finding(client):
    """google.com should not be expiring soon (no HIGH finding for expiry)."""
    resp = client.post("/v1/check/whois", json={"target": "google.com"})
    assert resp.status_code == 200

    whois_result = resp.json()["results"]["whois"]
    assert whois_result["error"] is None

    # google.com is renewed well in advance — should NOT have HIGH severity expiry findings
    for finding in whois_result["findings"]:
        if "expir" in finding["title"].lower():
            assert finding["severity"] != "high", (
                f"google.com should not be expiring soon, but got HIGH finding: {finding}"
            )
            assert finding["severity"] != "critical", f"google.com should not have critical expiry finding: {finding}"

    # The expiry finding should be INFO (well in the future)
    expiry_findings = [f for f in whois_result["findings"] if "expir" in f["title"].lower()]
    assert len(expiry_findings) > 0, "Expected at least one expiry-related finding"
    assert expiry_findings[0]["severity"] == "info", (
        f"Expected INFO severity for google.com expiry, got: {expiry_findings[0]['severity']}"
    )

    # google.com is not a new domain either
    titles = [f["title"] for f in whois_result["findings"]]
    assert "Very new domain" not in titles
    assert "Domain expired" not in titles
    assert "Domain expires soon" not in titles


def test_whois_rejected_for_ip(client):
    """WHOIS is a DNS-only check — sending an IP target to /v1/check/whois should return 422."""
    resp = client.post("/v1/check/whois", json={"target": "8.8.8.8"})
    assert resp.status_code == 422
