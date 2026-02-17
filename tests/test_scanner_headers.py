"""Comprehensive integration tests for the headers scanner.

Tests hit real external targets (testphp.vulnweb.com, google.com, etc.)
and verify that the scanner delivers actionable security findings.
"""

import pytest

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# 1. Missing security headers on a deliberately vulnerable site
# ---------------------------------------------------------------------------


def test_missing_security_headers_vulnweb(client):
    """testphp.vulnweb.com should be missing critical security headers:
    HSTS, CSP, and X-Content-Type-Options at minimum."""
    resp = client.post("/v1/check/headers", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    data = resp.json()
    headers_result = data["results"]["headers"]
    assert headers_result["error"] is None
    assert len(headers_result["findings"]) > 0

    titles_lower = [f["title"].lower() for f in headers_result["findings"]]

    # HSTS (Strict-Transport-Security) should be flagged as missing
    assert any("strict-transport-security" in t or "hsts" in t for t in titles_lower), (
        f"Expected HSTS finding, got titles: {titles_lower}"
    )

    # Content-Security-Policy should be flagged as missing
    assert any("content-security-policy" in t or "csp" in t for t in titles_lower), (
        f"Expected CSP finding, got titles: {titles_lower}"
    )

    # X-Content-Type-Options should be flagged as missing
    assert any("x-content-type-options" in t for t in titles_lower), (
        f"Expected X-Content-Type-Options finding, got titles: {titles_lower}"
    )

    # Every finding must have a valid severity
    valid_severities = {"critical", "high", "medium", "low", "info"}
    for finding in headers_result["findings"]:
        assert finding["severity"] in valid_severities, (
            f"Invalid severity '{finding['severity']}' in finding: {finding['title']}"
        )


# ---------------------------------------------------------------------------
# 2. Server header information leak
# ---------------------------------------------------------------------------


def test_server_header_leak(client):
    """testphp.vulnweb.com leaks its Server header (nginx) --
    the scanner should flag this as an information disclosure."""
    resp = client.post("/v1/check/headers", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    headers_result = resp.json()["results"]["headers"]
    assert headers_result["error"] is None

    # The Server header leak should be in the findings
    server_findings = [f for f in headers_result["findings"] if "server" in f["title"].lower()]
    assert len(server_findings) > 0, (
        f"Expected a Server header finding, got titles: {[f['title'] for f in headers_result['findings']]}"
    )

    # Server header should also appear in raw response headers
    raw_headers = headers_result["raw"].get("headers", {})
    raw_headers_lower = {k.lower(): v for k, v in raw_headers.items()}
    assert "server" in raw_headers_lower, "Server header should be present in raw headers"
    assert len(raw_headers_lower["server"]) > 0, "Server header value should not be empty"


# ---------------------------------------------------------------------------
# 3. Well-configured site -- should have findings but fewer critical ones
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_well_configured_site(client):
    """google.com is well-configured -- should still have findings
    (e.g. missing CSP) but should NOT have critical severity findings."""
    resp = client.post("/v1/check/headers", json={"target": "google.com"})
    assert resp.status_code == 200

    headers_result = resp.json()["results"]["headers"]
    assert headers_result["error"] is None

    # Even well-configured sites get some findings (info-level at minimum)
    assert len(headers_result["findings"]) > 0

    # Should NOT have critical-severity findings
    critical_findings = [f for f in headers_result["findings"] if f["severity"] == "critical"]
    assert len(critical_findings) == 0, (
        f"Well-configured site should not have critical findings: {[f['title'] for f in critical_findings]}"
    )

    # google.com serves over HTTPS -- should have the HTTPS-enabled info finding
    https_findings = [
        f for f in headers_result["findings"] if "https" in f["title"].lower() and "enabled" in f["title"].lower()
    ]
    assert len(https_findings) > 0, (
        f"Expected HTTPS-enabled info finding, got titles: {[f['title'] for f in headers_result['findings']]}"
    )


# ---------------------------------------------------------------------------
# 4. Raw data structure validation
# ---------------------------------------------------------------------------


def test_raw_data_structure(client):
    """Verify raw dict contains the expected fields: url, status_code, headers (dict)."""
    resp = client.post("/v1/check/headers", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    raw = resp.json()["results"]["headers"]["raw"]

    # Required fields
    assert "url" in raw, "raw must contain 'url'"
    assert "status_code" in raw, "raw must contain 'status_code'"
    assert "headers" in raw, "raw must contain 'headers'"

    # Type checks
    assert isinstance(raw["url"], str), "url must be a string"
    assert raw["url"].startswith("http"), f"url must start with http, got: {raw['url']}"
    assert isinstance(raw["status_code"], int), "status_code must be an integer"
    assert 100 <= raw["status_code"] < 600, f"status_code out of range: {raw['status_code']}"
    assert isinstance(raw["headers"], dict), "headers must be a dict"
    assert len(raw["headers"]) > 0, "headers dict should not be empty"

    # Headers should contain common HTTP response headers
    raw_headers_lower = {k.lower() for k in raw["headers"]}
    assert "content-type" in raw_headers_lower or "server" in raw_headers_lower, (
        "Expected at least content-type or server in response headers"
    )


# ---------------------------------------------------------------------------
# 5. HTTPS detection -- HTTP-only target should be flagged
# ---------------------------------------------------------------------------


def test_https_detection(client):
    """Scanning a target that falls back to HTTP should produce an
    'HTTP (not HTTPS)' high-severity finding."""
    # testphp.vulnweb.com does not serve HTTPS, falls back to HTTP
    resp = client.post("/v1/check/headers", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    headers_result = resp.json()["results"]["headers"]
    assert headers_result["error"] is None

    raw = headers_result["raw"]
    url = raw["url"]

    # If the target actually responded over HTTP (not HTTPS), the scanner should flag it
    if url.startswith("http://"):
        http_findings = [
            f for f in headers_result["findings"] if "http" in f["title"].lower() and "not https" in f["title"].lower()
        ]
        assert len(http_findings) > 0, (
            f"HTTP-only site should have 'not HTTPS' finding, got titles: "
            f"{[f['title'] for f in headers_result['findings']]}"
        )
        # This should be a high-severity finding
        assert http_findings[0]["severity"] == "high", (
            f"HTTP-only finding should be high severity, got: {http_findings[0]['severity']}"
        )
    else:
        # Site now serves HTTPS -- should have the HTTPS-enabled info finding instead
        https_findings = [
            f for f in headers_result["findings"] if "https" in f["title"].lower() and "enabled" in f["title"].lower()
        ]
        assert len(https_findings) > 0, (
            f"HTTPS site should have 'HTTPS enabled' info finding, got titles: "
            f"{[f['title'] for f in headers_result['findings']]}"
        )


# ---------------------------------------------------------------------------
# 6. Redirect detection
# ---------------------------------------------------------------------------


def test_redirect_detection(client):
    """When the target responds with a redirect (3xx), raw should contain
    redirect_location and a redirect finding should be emitted."""
    # http://www.google.com redirects to http://www.google.com/ (or https variant)
    # We use a target known to issue redirects.
    # google.com typically redirects with 301 from HTTP to HTTPS.
    resp = client.post("/v1/check/headers", json={"target": "google.com"})
    assert resp.status_code == 200

    headers_result = resp.json()["results"]["headers"]
    assert headers_result["error"] is None

    raw = headers_result["raw"]
    status_code = raw["status_code"]

    if status_code in (301, 302, 303, 307, 308):
        # If we got a redirect, verify redirect_location is present
        assert "redirect_location" in raw, (
            f"Redirect response (HTTP {status_code}) should include redirect_location in raw"
        )
        assert len(raw["redirect_location"]) > 0, "redirect_location should not be empty"

        # Should have a redirect-related finding
        redirect_findings = [f for f in headers_result["findings"] if "redirect" in f["title"].lower()]
        assert len(redirect_findings) > 0, (
            f"Redirect response should produce a redirect finding, got titles: "
            f"{[f['title'] for f in headers_result['findings']]}"
        )

        # Redirect finding should have details with status_code and location
        details = redirect_findings[0].get("details", {})
        assert "status_code" in details, "Redirect finding should include status_code in details"
        assert "location" in details, "Redirect finding should include location in details"
    else:
        # Non-redirect response -- redirect_location should NOT be in raw
        assert "redirect_location" not in raw, f"Non-redirect (HTTP {status_code}) should not include redirect_location"


# ---------------------------------------------------------------------------
# 7. Summary field with severity counts
# ---------------------------------------------------------------------------


def test_summary_field(client):
    """Response-level summary should have severity counts matching the
    actual findings from the headers check."""
    resp = client.post("/v1/check/headers", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    data = resp.json()

    # Summary should exist at the target-result level
    assert "summary" in data, "Response must include a 'summary' field"
    summary = data["summary"]

    # Summary should have all severity count fields
    for severity in ("critical", "high", "medium", "low", "info", "total"):
        assert severity in summary, f"summary must include '{severity}' count"
        assert isinstance(summary[severity], int), f"summary.{severity} must be an integer"
        assert summary[severity] >= 0, f"summary.{severity} must be non-negative"

    # Total should equal the sum of all severity counts
    assert summary["total"] == (
        summary["critical"] + summary["high"] + summary["medium"] + summary["low"] + summary["info"]
    ), "summary.total must equal sum of all severity counts"

    # Verify counts match the actual findings
    findings = data["results"]["headers"]["findings"]
    assert summary["total"] == len(findings), (
        f"summary.total ({summary['total']}) must match findings count ({len(findings)})"
    )

    # Count findings per severity and compare to summary
    from collections import Counter

    severity_counts = Counter(f["severity"] for f in findings)
    for severity in ("critical", "high", "medium", "low", "info"):
        expected = severity_counts.get(severity, 0)
        assert summary[severity] == expected, (
            f"summary.{severity} ({summary[severity]}) does not match actual count ({expected})"
        )


# ---------------------------------------------------------------------------
# 8. Auth config (bearer token) accepted in request
# ---------------------------------------------------------------------------


def test_auth_header_forwarding(client):
    """The headers scanner should accept an auth config with a bearer token.
    The request should succeed (200) and produce findings -- auth does not
    prevent analysis."""
    resp = client.post(
        "/v1/check/headers",
        json={
            "target": "testphp.vulnweb.com",
            "auth": {
                "type": "bearer",
                "token": "test-token-12345",
            },
        },
    )
    assert resp.status_code == 200

    data = resp.json()
    headers_result = data["results"]["headers"]
    assert headers_result["error"] is None, (
        f"Auth config should not cause scanner errors, got: {headers_result['error']}"
    )
    # Should still find missing security headers
    assert len(headers_result["findings"]) > 0, "Scanner should produce findings even with auth config"

    # Raw should still have the standard structure
    raw = headers_result["raw"]
    assert "url" in raw
    assert "status_code" in raw
    assert "headers" in raw
