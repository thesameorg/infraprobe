"""Integration tests: hit real targets, verify real results."""

import pytest


def test_scan_headers_vulnweb(client):
    """Scan deliberately vulnerable site — should find missing security headers + info leaks."""
    resp = client.post("/scan", json={"targets": ["testphp.vulnweb.com"], "checks": ["headers"]})
    assert resp.status_code == 200

    data = resp.json()
    result = data["results"][0]
    assert result["target"] == "testphp.vulnweb.com"
    assert result["score"] in ("A+", "A", "B+", "B", "C", "D", "F")
    assert result["duration_ms"] > 0

    # vulnweb leaks Server and X-Powered-By, so we expect findings
    headers_result = result["results"]["headers"]
    assert headers_result["error"] is None
    titles = [f["title"] for f in headers_result["findings"]]

    # testphp.vulnweb.com should be missing HSTS at minimum
    assert any("HSTS" in t for t in titles), f"Expected HSTS finding, got: {titles}"
    # Should detect Server header leak
    assert any("server" in t.lower() and "leak" in t.lower() for t in titles), f"Expected server leak, got: {titles}"


def test_scan_blocked_ip(client):
    resp = client.post("/scan", json={"targets": ["127.0.0.1"], "checks": ["headers"]})
    assert resp.status_code == 400
    assert "blocked" in resp.json()["detail"].lower()


def test_scan_invalid_target(client):
    resp = client.post("/scan", json={"targets": ["this-does-not-exist-xyz987.com"], "checks": ["headers"]})
    assert resp.status_code == 422


def test_scan_empty_targets(client):
    resp = client.post("/scan", json={"targets": [], "checks": ["headers"]})
    assert resp.status_code == 422


def test_scan_unimplemented_scanner(client):
    """Requesting a scanner that's not registered should return gracefully."""
    resp = client.post("/scan", json={"targets": ["example.com"], "checks": ["dns"]})
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["results"]["dns"]["error"] is not None


@pytest.mark.slow
def test_scan_example_com(client):
    """Scan example.com (behind Cloudflare) — different profile than vulnweb."""
    resp = client.post("/scan", json={"targets": ["example.com"], "checks": ["headers"]})
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["score"] is not None
    assert len(result["results"]["headers"]["findings"]) > 0


# --- SSL scanner tests ---


def test_scan_ssl_valid_cert(client):
    """Scan a site with a valid TLS certificate — should have no critical/high findings."""
    resp = client.post("/scan", json={"targets": ["example.com"], "checks": ["ssl"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    ssl_result = result["results"]["ssl"]
    assert ssl_result["error"] is None

    # Valid cert should not have critical findings
    severities = [f["severity"] for f in ssl_result["findings"]]
    assert "critical" not in severities, f"Unexpected critical finding: {ssl_result['findings']}"

    # Verify raw data has expected fields
    raw = ssl_result["raw"]
    assert raw["host"] == "example.com"
    assert raw["port"] == 443
    assert "TLS" in raw["protocol_version"]
    assert raw["cipher"] != ""
    assert raw["cipher_bits"] > 0
    assert raw["key_type"] in ("RSA", "EC")
    assert raw["key_bits"] > 0
    assert raw["days_until_expiry"] > 0
    assert len(raw["san"]) > 0


def test_scan_ssl_google(client):
    """Scan google.com — cert data should be present in raw."""
    resp = client.post("/scan", json={"targets": ["google.com"], "checks": ["ssl"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    ssl_result = result["results"]["ssl"]
    assert ssl_result["error"] is None

    raw = ssl_result["raw"]
    assert raw["host"] == "google.com"
    assert raw["issuer"] != ""
    assert raw["subject"] != ""
    assert raw["not_valid_before"] != ""
    assert raw["not_valid_after"] != ""


def test_scan_ssl_combined(client):
    """Scan with both headers and SSL checks — both results should be present."""
    resp = client.post("/scan", json={"targets": ["example.com"], "checks": ["headers", "ssl"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    assert "headers" in result["results"]
    assert "ssl" in result["results"]
    assert result["results"]["headers"]["error"] is None
    assert result["results"]["ssl"]["error"] is None


def test_scan_ssl_no_tls(client):
    """Scan a target on port 80 (no TLS) — should return a graceful error."""
    resp = client.post("/scan", json={"targets": ["example.com:80"], "checks": ["ssl"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    ssl_result = result["results"]["ssl"]
    assert ssl_result["error"] is not None
    assert ssl_result["findings"] == []
