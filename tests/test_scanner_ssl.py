"""Comprehensive integration tests for the SSL scanner via POST /v1/scan.

All tests hit real external targets -- no mocks.
"""

import pytest

from tests.helpers import submit_scan

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPECTED_RAW_FIELDS = {
    "host",
    "port",
    "protocol_version",
    "cipher",
    "cipher_bits",
    "issuer",
    "subject",
    "not_valid_before",
    "not_valid_after",
    "days_until_expiry",
    "serial_number",
    "san",
    "key_type",
    "key_bits",
}


def _ssl_result(client, target: str) -> dict:
    """Run a bundle scan and return the TargetResult dict."""
    data = submit_scan(client, {"target": target})
    return data["results"][0]


# ---------------------------------------------------------------------------
# 1. Valid certificate -- no critical findings, raw populated
# ---------------------------------------------------------------------------


def test_valid_certificate(client):
    """Scan example.com -- should have no critical findings and complete raw data."""
    tr = _ssl_result(client, "example.com")

    assert tr["target"] == "example.com"
    ssl_result = tr["results"]["ssl"]
    assert ssl_result["error"] is None

    # No critical findings on a well-configured site
    severities = [f["severity"] for f in ssl_result["findings"]]
    assert "critical" not in severities, f"Unexpected critical finding: {ssl_result['findings']}"

    # Verify essential raw fields
    raw = ssl_result["raw"]
    assert raw["host"] == "example.com"
    assert raw["port"] == 443
    assert "TLS" in raw["protocol_version"]
    assert isinstance(raw["cipher"], str) and raw["cipher"] != ""
    assert raw["cipher_bits"] > 0
    assert raw["key_type"] in ("RSA", "EC")
    assert raw["key_bits"] > 0
    assert raw["days_until_expiry"] > 0
    assert isinstance(raw["san"], list) and len(raw["san"]) > 0


# ---------------------------------------------------------------------------
# 2. TLS version detection
# ---------------------------------------------------------------------------


def test_tls_version_detected(client):
    """Scan google.com -- should negotiate TLS 1.2 or TLS 1.3."""
    tr = _ssl_result(client, "google.com")

    ssl_result = tr["results"]["ssl"]
    assert ssl_result["error"] is None

    protocol = ssl_result["raw"]["protocol_version"]
    assert protocol in ("TLSv1.2", "TLSv1.3"), f"Unexpected protocol version: {protocol}"


# ---------------------------------------------------------------------------
# 3. Strong key detected
# ---------------------------------------------------------------------------


def test_strong_key_detected(client):
    """Scan example.com -- RSA key >= 2048 bits, or EC key of any size."""
    tr = _ssl_result(client, "example.com")

    ssl_result = tr["results"]["ssl"]
    assert ssl_result["error"] is None

    raw = ssl_result["raw"]
    key_type = raw["key_type"]
    key_bits = raw["key_bits"]

    if key_type == "RSA":
        assert key_bits >= 2048, f"RSA key too small: {key_bits} bits"
    elif key_type == "EC":
        # EC keys are inherently strong; any size negotiated by a modern server is fine
        assert key_bits > 0, f"EC key_bits should be positive, got {key_bits}"
    else:
        pytest.fail(f"Unexpected key type: {key_type}")

    # There should be no "Weak RSA key" finding
    titles = [f["title"] for f in ssl_result["findings"]]
    assert not any("weak rsa" in t.lower() for t in titles), f"Unexpected weak-key finding: {titles}"


# ---------------------------------------------------------------------------
# 4. Positive (INFO-level) findings for a valid cert
# ---------------------------------------------------------------------------


def test_valid_cert_positive_findings(client):
    """Verify INFO-level positive findings exist (valid cert, strong key, etc.)."""
    tr = _ssl_result(client, "example.com")

    ssl_result = tr["results"]["ssl"]
    assert ssl_result["error"] is None

    info_findings = [f for f in ssl_result["findings"] if f["severity"] == "info"]
    info_titles = [f["title"] for f in info_findings]

    # At least one positive finding should confirm a valid certificate
    assert any("valid certificate" in t.lower() for t in info_titles), (
        f"Expected an INFO finding about valid certificate, got: {info_titles}"
    )

    # Should also have a key-strength finding (RSA or EC)
    assert any("rsa" in t.lower() or "ec key" in t.lower() for t in info_titles), (
        f"Expected an INFO finding about key strength, got: {info_titles}"
    )


# ---------------------------------------------------------------------------
# 5. Port 80 -- no TLS
# ---------------------------------------------------------------------------


def test_port_80_no_tls(client):
    """Scan example.com:80 -- SSL result should have an error (no TLS on port 80)."""
    tr = _ssl_result(client, "example.com:80")

    ssl_result = tr["results"]["ssl"]
    assert ssl_result["error"] is not None, "Expected an error for port 80 (no TLS)"
    assert ssl_result["findings"] == [], "No findings expected when TLS connection fails"
    assert ssl_result["raw"] == {}, "No raw data expected when TLS connection fails"


# ---------------------------------------------------------------------------
# 6. Raw data completeness
# ---------------------------------------------------------------------------


def test_raw_data_completeness(client):
    """Verify all expected raw fields are present and have sensible types."""
    tr = _ssl_result(client, "example.com")

    ssl_result = tr["results"]["ssl"]
    assert ssl_result["error"] is None

    raw = ssl_result["raw"]

    # Every expected field must be present
    missing = EXPECTED_RAW_FIELDS - set(raw.keys())
    assert not missing, f"Missing raw fields: {missing}"

    # Type checks
    assert isinstance(raw["host"], str) and raw["host"] != ""
    assert isinstance(raw["port"], int) and raw["port"] > 0
    assert isinstance(raw["protocol_version"], str) and raw["protocol_version"] != ""
    assert isinstance(raw["cipher"], str) and raw["cipher"] != ""
    assert isinstance(raw["cipher_bits"], int) and raw["cipher_bits"] > 0
    assert isinstance(raw["issuer"], str) and raw["issuer"] != ""
    assert isinstance(raw["subject"], str) and raw["subject"] != ""
    assert isinstance(raw["not_valid_before"], str) and raw["not_valid_before"] != ""
    assert isinstance(raw["not_valid_after"], str) and raw["not_valid_after"] != ""
    assert isinstance(raw["days_until_expiry"], int) and raw["days_until_expiry"] >= 0
    assert isinstance(raw["serial_number"], str) and raw["serial_number"] != ""
    assert isinstance(raw["san"], list)
    assert isinstance(raw["key_type"], str) and raw["key_type"] in ("RSA", "EC")
    assert isinstance(raw["key_bits"], int) and raw["key_bits"] > 0


# ---------------------------------------------------------------------------
# 7. Summary field
# ---------------------------------------------------------------------------


def test_summary_field(client):
    """Verify the response summary has correct structure and counts."""
    tr = _ssl_result(client, "example.com")

    assert "summary" in tr, f"Missing summary in TargetResult, keys: {list(tr.keys())}"
    summary = tr["summary"]

    # Structure check
    for key in ("critical", "high", "medium", "low", "info", "total"):
        assert key in summary, f"Missing summary key: {key}"
        assert isinstance(summary[key], int), f"summary[{key}] should be int, got {type(summary[key])}"
        assert summary[key] >= 0, f"summary[{key}] should be non-negative"

    # Total must equal sum of individual counts
    computed_total = summary["critical"] + summary["high"] + summary["medium"] + summary["low"] + summary["info"]
    assert summary["total"] == computed_total, (
        f"Total mismatch: {summary['total']} != {computed_total} (individual counts)"
    )

    # SSL findings should contribute to the total
    ssl_result = tr["results"]["ssl"]
    assert summary["total"] >= len(ssl_result["findings"]), "Summary total should include SSL findings"

    # For a valid site like example.com we expect INFO findings but no critical
    assert summary["critical"] == 0
    assert summary["info"] > 0, "Expected at least one INFO finding for a valid certificate"
