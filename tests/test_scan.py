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
    """Requesting a scanner that's registered but not yet implemented should return gracefully."""
    resp = client.post("/scan", json={"targets": ["example.com"], "checks": ["ssl"]})
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["results"]["ssl"]["error"] is not None


@pytest.mark.slow
def test_scan_example_com(client):
    """Scan example.com (behind Cloudflare) — different profile than vulnweb."""
    resp = client.post("/scan", json={"targets": ["example.com"], "checks": ["headers"]})
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["score"] is not None
    assert len(result["results"]["headers"]["findings"]) > 0
