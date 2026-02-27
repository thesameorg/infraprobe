"""Integration tests: hit real targets, verify real results."""

import pytest
from helpers import submit_scan

pytestmark = pytest.mark.integration


def test_scan_headers_vulnweb(client):
    """Scan deliberately vulnerable site — should find missing security headers + info leaks."""
    result = submit_scan(client, {"target": "testphp.vulnweb.com"})
    target = result["results"][0]

    assert target["target"] == "testphp.vulnweb.com"
    assert target["duration_ms"] > 0

    # vulnweb leaks Server and X-Powered-By, so we expect findings
    headers_result = target["results"]["headers"]
    assert headers_result["error"] is None
    titles = [f["title"] for f in headers_result["findings"]]

    # testphp.vulnweb.com should be missing HSTS at minimum
    assert any("hsts" in t.lower() or "strict-transport-security" in t.lower() for t in titles), (
        f"Expected HSTS finding, got: {titles}"
    )
    # Should detect Server header leak
    assert any("server" in t.lower() and ("leak" in t.lower() or "should not" in t.lower()) for t in titles), (
        f"Expected server leak, got: {titles}"
    )


def test_scan_blocked_ip(client):
    resp = client.post("/v1/scan", json={"target": "127.0.0.1"})
    assert resp.status_code == 400
    body = resp.json()
    assert "blocked" in body["detail"].lower()
    assert body["error"] == "blocked_target"


def test_scan_invalid_target(client):
    resp = client.post("/v1/scan", json={"target": "this-does-not-exist-xyz987.com"})
    assert resp.status_code == 422


def test_scan_missing_target(client):
    resp = client.post("/v1/scan", json={})
    assert resp.status_code == 422


@pytest.mark.slow
def test_scan_example_com(client):
    """Scan example.com — different profile than vulnweb."""
    result = submit_scan(client, {"target": "example.com"})
    target = result["results"][0]
    assert len(target["results"]["headers"]["findings"]) > 0


# --- SSL scanner tests ---


def test_scan_ssl_valid_cert(client):
    """Scan a site with a valid TLS certificate — should have no critical/high findings."""
    result = submit_scan(client, {"target": "example.com"})
    target = result["results"][0]

    ssl_result = target["results"]["ssl"]
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


def test_scan_ssl_combined(client):
    """Default scan includes both headers and SSL — both results should be present."""
    data = submit_scan(client, {"target": "example.com"})

    result = data["results"][0]
    assert "headers" in result["results"]
    assert "ssl" in result["results"]
    assert result["results"]["headers"]["error"] is None
    assert result["results"]["ssl"]["error"] is None


# --- DNS scanner tests ---


def test_scan_dns_google(client):
    """Scan google.com DNS — should resolve records and return raw data."""
    data = submit_scan(client, {"target": "google.com"})
    target = data["results"][0]

    dns_result = target["results"]["dns"]
    assert dns_result["error"] is None

    raw = dns_result["raw"]
    assert raw["domain"] == "google.com"
    # google.com should have A records
    assert len(raw["a"]) > 0
    # google.com should have MX records
    assert len(raw["mx"]) > 0
    # google.com should have NS records
    assert len(raw["ns"]) > 0


def test_scan_dns_spf_dmarc(client):
    """Scan google.com DNS — should have SPF and DMARC (no findings for missing)."""
    data = submit_scan(client, {"target": "google.com"})
    target = data["results"][0]

    dns_result = target["results"]["dns"]
    assert dns_result["error"] is None

    titles = [f["title"] for f in dns_result["findings"]]
    # google.com has SPF and DMARC, so those "missing" findings should NOT appear
    assert "No SPF record" not in titles, f"google.com should have SPF, got: {titles}"
    assert "No DMARC record" not in titles, f"google.com should have DMARC, got: {titles}"

    # SPF and DMARC should be in raw
    raw = dns_result["raw"]
    assert "spf" in raw
    assert "v=spf1" in raw["spf"].lower()
    assert "dmarc" in raw
    assert "v=dmarc1" in raw["dmarc"].lower()


def test_scan_dns_combined(client):
    """Default domain scan includes DNS + headers — both results should be present."""
    data = submit_scan(client, {"target": "example.com"})

    result = data["results"][0]
    assert "dns" in result["results"]
    assert "headers" in result["results"]
    assert result["results"]["dns"]["error"] is None
    assert result["results"]["headers"]["error"] is None


def test_scan_all_checks(client):
    """Default domain scan runs all 5 default checks."""
    data = submit_scan(client, {"target": "example.com"})

    result = data["results"][0]
    for check in ["headers", "ssl", "dns", "web", "whois"]:
        assert check in result["results"], f"Missing result for {check}"
        error = result["results"][check]["error"]
        assert error is None, f"{check} returned error: {error}"


# --- /v1/ API prefix tests ---


def test_v1_scan_sync_fast_checks(client):
    """/v1/scan always returns 200 with inline ScanResponse."""
    resp = client.post("/v1/scan", json={"target": "example.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert "results" in body
    result = body["results"][0]
    assert result["results"]["headers"]["error"] is None


def test_v1_default_checks_are_light(client):
    """Default checks should be headers, ssl, dns, web, whois — no deep/deprecated."""
    data = submit_scan(client, {"target": "example.com"})
    result = data["results"][0]
    expected = {"headers", "ssl", "dns", "web", "whois"}
    assert set(result["results"].keys()) == expected


# --- Web scanner tests ---


def test_scan_web_vulnweb(client):
    """Web scan of vulnweb — should find CORS/path/security.txt findings."""
    data = submit_scan(client, {"target": "testphp.vulnweb.com"})
    target = data["results"][0]

    assert target["target"] == "testphp.vulnweb.com"
    web_result = target["results"]["web"]
    assert web_result["error"] is None

    # Should have findings (at minimum security.txt missing and path probe results)
    assert len(web_result["findings"]) > 0
    titles = [f["title"] for f in web_result["findings"]]
    # Should report on CORS (either present or absent)
    assert any("cors" in t.lower() for t in titles), f"Expected CORS finding, got: {titles}"

    # Raw should have expected keys
    raw = web_result["raw"]
    assert "url" in raw
    assert "exposed_paths" in raw
    assert isinstance(raw["exposed_paths"], list)


def test_scan_web_example_com(client):
    """Web scan of example.com — well-configured site."""
    data = submit_scan(client, {"target": "example.com"})
    target = data["results"][0]

    web_result = target["results"]["web"]
    assert web_result["error"] is None

    raw = web_result["raw"]
    assert raw["url"].startswith("http")
    assert "status_code" in raw
    assert "security_txt" in raw


def test_scan_includes_web_check(client):
    """Web check is included in the default bundle scan."""
    data = submit_scan(client, {"target": "example.com"})

    result = data["results"][0]
    assert "web" in result["results"]
    assert result["results"]["web"]["error"] is None


# --- Domain/IP auto-detect and validation tests ---


def test_scan_domain_works(client):
    """POST /v1/scan with a domain — auto-detect uses DOMAIN_CHECKS (includes dns)."""
    data = submit_scan(client, {"target": "testphp.vulnweb.com"})
    result = data["results"][0]
    assert result["target"] == "testphp.vulnweb.com"
    # Default domain checks include dns
    assert "dns" in result["results"]


def test_scan_ip_auto_detect_uses_ip_checks(client):
    """POST /v1/scan with an IP — uses IP_CHECKS (headers, ssl, web)."""
    data = submit_scan(client, {"target": "44.228.249.3"})
    result = data["results"][0]
    assert result["target"] == "44.228.249.3"
    # IP checks: headers, ssl, web — no dns, no whois
    assert "dns" not in result["results"]
    assert "whois" not in result["results"]
    assert "ssl" in result["results"]
    assert "headers" in result["results"]
    assert "web" in result["results"]


def test_unversioned_scan_removed(client):
    """Unversioned /scan should no longer be routed — expect 404."""
    resp = client.post("/scan", json={"target": "example.com"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# WHOIS scanner
# ---------------------------------------------------------------------------


def test_scan_whois_google(client):
    """WHOIS lookup for google.com — should return registrar, dates, and no errors."""
    data = submit_scan(client, {"target": "google.com"})
    target = data["results"][0]

    whois_result = target["results"]["whois"]
    assert whois_result["error"] is None

    raw = whois_result["raw"]
    assert raw["domain"] == "google.com"
    assert raw.get("registrar"), "google.com should have a registrar"
    assert raw.get("created"), "google.com should have a creation date"
    assert raw.get("expires"), "google.com should have an expiration date"

    titles = [f["title"] for f in whois_result["findings"]]
    assert "Registrar identified" in titles
    assert "Domain age" in titles
    assert "Domain expiration" in titles
    # google.com is not new and not expiring soon
    assert "Very new domain" not in titles
    assert "Domain expires soon" not in titles


def test_scan_whois_in_default_domain_checks(client):
    """WHOIS should be included in the default domain scan bundle."""
    data = submit_scan(client, {"target": "google.com"})
    result = data["results"][0]
    assert "whois" in result["results"], f"whois missing from default scan, got: {list(result['results'].keys())}"
