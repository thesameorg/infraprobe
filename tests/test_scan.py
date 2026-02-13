"""Integration tests: hit real targets, verify real results."""

import pytest


def test_scan_headers_vulnweb(client):
    """Scan deliberately vulnerable site — should find missing security headers + info leaks."""
    resp = client.post("/v1/scan", json={"targets": ["testphp.vulnweb.com"], "checks": ["headers"]})
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
    assert any("hsts" in t.lower() or "strict-transport-security" in t.lower() for t in titles), (
        f"Expected HSTS finding, got: {titles}"
    )
    # Should detect Server header leak
    assert any("server" in t.lower() and ("leak" in t.lower() or "should not" in t.lower()) for t in titles), (
        f"Expected server leak, got: {titles}"
    )


def test_scan_blocked_ip(client):
    resp = client.post("/v1/scan", json={"targets": ["127.0.0.1"], "checks": ["headers"]})
    assert resp.status_code == 400
    assert "blocked" in resp.json()["detail"].lower()


def test_scan_invalid_target(client):
    resp = client.post("/v1/scan", json={"targets": ["this-does-not-exist-xyz987.com"], "checks": ["headers"]})
    assert resp.status_code == 422


def test_scan_empty_targets(client):
    resp = client.post("/v1/scan", json={"targets": [], "checks": ["headers"]})
    assert resp.status_code == 422


def test_scan_invalid_check_type(client):
    """Requesting an unknown check type should return 422."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["nonexistent"]})
    assert resp.status_code == 422


@pytest.mark.slow
def test_scan_example_com(client):
    """Scan example.com (behind Cloudflare) — different profile than vulnweb."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["headers"]})
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["score"] is not None
    assert len(result["results"]["headers"]["findings"]) > 0


# --- SSL scanner tests ---


def test_scan_ssl_valid_cert(client):
    """Scan a site with a valid TLS certificate — should have no critical/high findings."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["ssl"]})
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
    resp = client.post("/v1/scan", json={"targets": ["google.com"], "checks": ["ssl"]})
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
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["headers", "ssl"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    assert "headers" in result["results"]
    assert "ssl" in result["results"]
    assert result["results"]["headers"]["error"] is None
    assert result["results"]["ssl"]["error"] is None


def test_scan_ssl_no_tls(client):
    """Scan a target on port 80 (no TLS) — should return a graceful error."""
    resp = client.post("/v1/scan", json={"targets": ["example.com:80"], "checks": ["ssl"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    ssl_result = result["results"]["ssl"]
    assert ssl_result["error"] is not None
    assert ssl_result["findings"] == []


# --- DNS scanner tests ---


def test_scan_dns_google(client):
    """Scan google.com DNS — should resolve records and return raw data."""
    resp = client.post("/v1/scan", json={"targets": ["google.com"], "checks": ["dns"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    dns_result = result["results"]["dns"]
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
    resp = client.post("/v1/scan", json={"targets": ["google.com"], "checks": ["dns"]})
    assert resp.status_code == 200

    dns_result = resp.json()["results"][0]["results"]["dns"]
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
    """Scan with DNS + headers — both results should be present."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["dns", "headers"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    assert "dns" in result["results"]
    assert "headers" in result["results"]
    assert result["results"]["dns"]["error"] is None
    assert result["results"]["headers"]["error"] is None


def test_scan_dns_strips_port(client):
    """DNS scanner should ignore port in target."""
    resp = client.post("/v1/scan", json={"targets": ["google.com:443"], "checks": ["dns"]})
    assert resp.status_code == 200

    dns_result = resp.json()["results"][0]["results"]["dns"]
    assert dns_result["error"] is None
    assert dns_result["raw"]["domain"] == "google.com"


# --- Tech detection scanner tests ---


def test_scan_tech_vulnweb(client):
    """Scan vulnweb — should detect server tech (Nginx/PHP)."""
    resp = client.post("/v1/scan", json={"targets": ["testphp.vulnweb.com"], "checks": ["tech"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    tech_result = result["results"]["tech"]
    assert tech_result["error"] is None

    raw = tech_result["raw"]
    assert raw["technologies_count"] > 0
    detected_names = [t["name"] for t in raw["detected"]]
    # vulnweb runs Nginx + PHP
    assert "Nginx" in detected_names or "PHP" in detected_names, f"Expected Nginx or PHP, got: {detected_names}"


def test_scan_tech_google(client):
    """Scan google.com — should detect something (at least a web server or CDN)."""
    resp = client.post("/v1/scan", json={"targets": ["google.com"], "checks": ["tech"]})
    assert resp.status_code == 200

    tech_result = resp.json()["results"][0]["results"]["tech"]
    assert tech_result["error"] is None
    assert isinstance(tech_result["raw"]["detected"], list)


def test_scan_tech_raw_structure(client):
    """Verify tech scanner raw data structure."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["tech"]})
    assert resp.status_code == 200

    tech_result = resp.json()["results"][0]["results"]["tech"]
    assert tech_result["error"] is None

    raw = tech_result["raw"]
    assert "url" in raw
    assert "detected" in raw
    assert "technologies_count" in raw
    assert isinstance(raw["detected"], list)
    assert raw["technologies_count"] == len(raw["detected"])


def test_scan_all_checks(client):
    """Scan with all 5 check types — all results should be present."""
    resp = client.post(
        "/v1/scan",
        json={"targets": ["example.com"], "checks": ["headers", "ssl", "dns", "tech", "blacklist"]},
    )
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    for check in ["headers", "ssl", "dns", "tech", "blacklist"]:
        assert check in result["results"], f"Missing result for {check}"
        error = result["results"][check]["error"]
        # blacklist uses DNSBL which can timeout in CI environments
        if check == "blacklist" and error and "timed out" in error:
            continue
        assert error is None, f"{check} returned error: {error}"


# --- Blacklist (DNSBL) scanner tests ---


def test_scan_blacklist_google(client):
    """Light blacklist scan — 2 major DNSBL sources, should be fast."""
    resp = client.post("/v1/scan", json={"targets": ["google.com"], "checks": ["blacklist"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    bl_result = result["results"]["blacklist"]
    if bl_result["error"] and "timed out" in bl_result["error"]:
        pytest.skip("DNSBL timed out (CI environment)")

    assert bl_result["error"] is None

    raw = bl_result["raw"]
    assert raw["ip"] != ""
    assert raw["total_checked"] == 2  # light = 2 major sources
    assert isinstance(raw["listings"], dict)
    for zone, status in raw["listings"].items():
        assert status in ("listed", "clean", "timeout"), f"Unexpected status for {zone}: {status}"


def test_scan_blacklist_raw_structure(client):
    """Verify blacklist scanner raw data structure."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["blacklist"]})
    assert resp.status_code == 200

    bl_result = resp.json()["results"][0]["results"]["blacklist"]
    if bl_result["error"] and "timed out" in bl_result["error"]:
        pytest.skip("DNSBL timed out (CI environment)")

    assert bl_result["error"] is None

    raw = bl_result["raw"]
    assert "ip" in raw
    assert "reversed_ip" in raw
    assert "listings" in raw
    assert "listed_count" in raw
    assert "total_checked" in raw
    # Verify reverse IP format
    octets = raw["ip"].split(".")
    reversed_octets = raw["reversed_ip"].split(".")
    assert octets == list(reversed(reversed_octets))


def test_scan_blacklist_deep(client):
    """Deep blacklist scan — all 15 DNSBL sources with per-zone timeout."""
    resp = client.post("/v1/scan", json={"targets": ["google.com"], "checks": ["blacklist_deep"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    bl_result = result["results"]["blacklist_deep"]
    if bl_result["error"] and "timed out" in bl_result["error"]:
        pytest.skip("DNSBL timed out (CI environment)")

    assert bl_result["error"] is None

    raw = bl_result["raw"]
    assert raw["ip"] != ""
    # Deep checks all 15 sources, some may timeout
    assert raw["total_checked"] > 5
    assert isinstance(raw["listings"], dict)
    assert len(raw["listings"]) == 15  # all zones attempted
    for zone, status in raw["listings"].items():
        assert status in ("listed", "clean", "timeout"), f"Unexpected status for {zone}: {status}"


# --- /v1/ API prefix tests ---


def test_v1_scan_works(client):
    """/v1/scan should work."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["headers"]})
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["results"]["headers"]["error"] is None


def test_v1_default_checks_are_light(client):
    """Default checks should only include light checks, not deep ones."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"]})
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    # Should have light checks
    assert "headers" in result["results"]
    # Should NOT have deep checks by default
    assert "ssl_deep" not in result["results"]
    assert "tech_deep" not in result["results"]


# --- Deep scanner tests ---


def test_scan_ssl_deep(client):
    """SSL deep scan (SSLyze) — should return protocol/vuln data."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["ssl_deep"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    ssl_result = result["results"]["ssl_deep"]
    assert ssl_result["error"] is None

    raw = ssl_result["raw"]
    assert raw["host"] == "example.com"
    assert len(raw["supported_protocols"]) > 0
    assert "vulnerabilities" in raw
    assert raw["vulnerabilities"]["heartbleed"] is False


def test_scan_dns_deep(client):
    """DNS deep scan (checkdmarc) — should return SPF/DMARC/DNSSEC data."""
    resp = client.post("/v1/scan", json={"targets": ["google.com"], "checks": ["dns_deep"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    dns_result = result["results"]["dns_deep"]
    assert dns_result["error"] is None

    raw = dns_result["raw"]
    assert raw["domain"] == "google.com"
    assert "spf" in raw
    assert "v=spf1" in raw["spf"].lower()
    assert "dmarc" in raw
    assert "v=dmarc1" in raw["dmarc"].lower()
    assert raw["dmarc_policy"] == "reject"
    assert "dnssec" in raw


def test_scan_tech_deep(client):
    """Tech deep scan (wappalyzer) — should detect technologies."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["tech_deep"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    tech_result = result["results"]["tech_deep"]
    assert tech_result["error"] is None

    raw = tech_result["raw"]
    assert "detected" in raw
    assert "technologies_count" in raw
    assert isinstance(raw["detected"], list)


# --- Single-check endpoint tests ---


def test_check_headers(client):
    """POST /v1/check/headers — returns a single TargetResult."""
    resp = client.post("/v1/check/headers", json={"target": "example.com"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["target"] == "example.com"
    assert data["score"] is not None
    assert "headers" in data["results"]
    assert data["results"]["headers"]["error"] is None
    assert data["duration_ms"] > 0


def test_check_ssl(client):
    """POST /v1/check/ssl — returns SSL result for a single target."""
    resp = client.post("/v1/check/ssl", json={"target": "example.com"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["target"] == "example.com"
    assert "ssl" in data["results"]
    assert data["results"]["ssl"]["error"] is None


def test_check_dns(client):
    """POST /v1/check/dns — returns DNS result for a single target."""
    resp = client.post("/v1/check/dns", json={"target": "google.com"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["target"] == "google.com"
    assert "dns" in data["results"]
    assert data["results"]["dns"]["error"] is None


def test_check_invalid_type(client):
    """POST /v1/check/nonexistent — no matching route, should return 404."""
    resp = client.post("/v1/check/nonexistent", json={"target": "example.com"})
    assert resp.status_code == 404


def test_check_blocked_target(client):
    """POST /v1/check/headers with blocked IP — should return 400."""
    resp = client.post("/v1/check/headers", json={"target": "127.0.0.1"})
    assert resp.status_code == 400
    assert "blocked" in resp.json()["detail"].lower()


def test_unversioned_scan_removed(client):
    """Unversioned /scan should no longer be routed — expect 404."""
    resp = client.post("/scan", json={"targets": ["example.com"], "checks": ["headers"]})
    assert resp.status_code == 404


# --- Web scanner tests ---


def test_check_web_vulnweb(client):
    """Web scan of vulnweb — should find CORS/path/security.txt findings."""
    resp = client.post("/v1/check/web", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["target"] == "testphp.vulnweb.com"
    web_result = data["results"]["web"]
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


def test_check_web_example_com(client):
    """Web scan of example.com — well-configured site."""
    resp = client.post("/v1/check/web", json={"target": "example.com"})
    assert resp.status_code == 200

    data = resp.json()
    web_result = data["results"]["web"]
    assert web_result["error"] is None

    raw = web_result["raw"]
    assert raw["url"].startswith("http")
    assert "status_code" in raw
    assert "security_txt" in raw


def test_check_web_cors_raw(client):
    """Web scan should include CORS details in raw data."""
    resp = client.post("/v1/check/web", json={"target": "example.com"})
    assert resp.status_code == 200

    raw = resp.json()["results"]["web"]["raw"]
    assert "cors" in raw
    assert "access_control_allow_origin" in raw["cors"]


def test_scan_with_web_check(client):
    """Web check can be included in a bundle scan."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["web"]})
    assert resp.status_code == 200

    result = resp.json()["results"][0]
    assert "web" in result["results"]
    assert result["results"]["web"]["error"] is None


def test_web_not_in_default_checks(client):
    """Web check should NOT be in default light checks (it's opt-in)."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"]})
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert "web" not in result["results"]


# --- Domain endpoint tests ---


def test_scan_domain_works(client):
    """POST /v1/scan_domain — domain scan with default checks."""
    resp = client.post("/v1/scan_domain", json={"targets": ["testphp.vulnweb.com"]})
    assert resp.status_code == 200

    data = resp.json()
    result = data["results"][0]
    assert result["target"] == "testphp.vulnweb.com"
    assert result["score"] is not None
    # Default domain checks include dns
    assert "dns" in result["results"]


def test_scan_domain_rejects_ip(client):
    """POST /v1/scan_domain with an IP — should return 422."""
    resp = client.post("/v1/scan_domain", json={"targets": ["93.184.216.34"]})
    assert resp.status_code == 422
    assert "expected a domain" in resp.json()["detail"].lower()


def test_check_domain_headers(client):
    """POST /v1/check_domain/headers — single domain check."""
    resp = client.post("/v1/check_domain/headers", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["target"] == "testphp.vulnweb.com"
    assert "headers" in data["results"]
    assert data["results"]["headers"]["error"] is None


def test_check_domain_rejects_ip(client):
    """POST /v1/check_domain/headers with an IP — should return 422."""
    resp = client.post("/v1/check_domain/headers", json={"target": "93.184.216.34"})
    assert resp.status_code == 422


# --- IP endpoint tests ---


def test_scan_ip_works(client):
    """POST /v1/scan_ip — IP scan with default checks (no DNS)."""
    resp = client.post("/v1/scan_ip", json={"targets": ["44.228.249.3"]})
    assert resp.status_code == 200

    data = resp.json()
    result = data["results"][0]
    assert result["target"] == "44.228.249.3"
    assert result["score"] is not None
    # IP default checks should NOT include dns
    assert "dns" not in result["results"]
    # Should include ssl and headers
    assert "ssl" in result["results"]
    assert "headers" in result["results"]


def test_scan_ip_rejects_domain(client):
    """POST /v1/scan_ip with a domain — should return 422."""
    resp = client.post("/v1/scan_ip", json={"targets": ["testphp.vulnweb.com"]})
    assert resp.status_code == 422
    assert "expected an ip" in resp.json()["detail"].lower()


def test_scan_ip_rejects_dns_check(client):
    """POST /v1/scan_ip with dns check — should return 422."""
    resp = client.post("/v1/scan_ip", json={"targets": ["44.228.249.3"], "checks": ["dns"]})
    assert resp.status_code == 422
    assert "dns" in resp.json()["detail"].lower()


def test_check_ip_ssl(client):
    """POST /v1/check_ip/ssl — single IP check."""
    resp = client.post("/v1/check_ip/ssl", json={"target": "44.228.249.3"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["target"] == "44.228.249.3"
    assert "ssl" in data["results"]


def test_check_ip_rejects_dns(client):
    """POST /v1/check_ip/dns — should return 422."""
    resp = client.post("/v1/check_ip/dns", json={"target": "44.228.249.3"})
    assert resp.status_code == 422


def test_check_ip_rejects_domain(client):
    """POST /v1/check_ip/headers with a domain — should return 422."""
    resp = client.post("/v1/check_ip/headers", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 422
