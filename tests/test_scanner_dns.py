"""Comprehensive integration tests for the DNS scanner via POST /v1/check/dns."""

import pytest

pytestmark = pytest.mark.integration


def _dns_check(client, target: str) -> dict:
    """POST /v1/check/dns and return the full response dict.

    Skips the test if the DNS scanner times out (network-dependent).
    """
    resp = client.post("/v1/check/dns", json={"target": target})
    assert resp.status_code == 200
    data = resp.json()
    dns_result = data["results"]["dns"]
    if dns_result["error"] and "timed out" in dns_result["error"]:
        pytest.skip("DNS scanner timed out (network-dependent)")
    return data


# ---------------------------------------------------------------------------
# 1. Core DNS records present
# ---------------------------------------------------------------------------


def test_dns_records_present(client):
    """Scan google.com -- should resolve A, NS, and MX records."""
    data = _dns_check(client, "google.com")
    assert data["target"] == "google.com"

    dns_result = data["results"]["dns"]
    assert dns_result["error"] is None

    raw = dns_result["raw"]
    assert raw["domain"] == "google.com"
    assert len(raw["a"]) > 0, f"google.com should have A records, got: {raw['a']}"
    assert len(raw["ns"]) > 0, f"google.com should have NS records, got: {raw['ns']}"
    assert len(raw["mx"]) > 0, f"google.com should have MX records, got: {raw['mx']}"


# ---------------------------------------------------------------------------
# 2. SPF record detection
# ---------------------------------------------------------------------------


def test_spf_record_detected(client):
    """Scan google.com -- should detect SPF record and produce an SPF-present finding."""
    data = _dns_check(client, "google.com")

    dns_result = data["results"]["dns"]
    assert dns_result["error"] is None

    # SPF should appear in raw data
    raw = dns_result["raw"]
    assert "spf" in raw, f"google.com should have SPF in raw, keys: {list(raw.keys())}"
    assert "v=spf1" in raw["spf"].lower()

    # There should be a TXT record containing the SPF policy
    txt_records = raw.get("txt", [])
    spf_txts = [t for t in txt_records if "v=spf1" in t.lower()]
    assert len(spf_txts) > 0, f"Expected SPF in TXT records, got: {txt_records}"

    # Findings should include an "SPF record present" info finding (not "No SPF record")
    titles = [f["title"] for f in dns_result["findings"]]
    assert "SPF record present" in titles, f"Expected 'SPF record present' finding, got: {titles}"
    assert "No SPF record" not in titles, f"google.com should not flag missing SPF, got: {titles}"


# ---------------------------------------------------------------------------
# 3. DMARC record detection
# ---------------------------------------------------------------------------


def test_dmarc_record_detected(client):
    """Scan google.com -- should detect DMARC record from _dmarc subdomain."""
    data = _dns_check(client, "google.com")

    dns_result = data["results"]["dns"]
    assert dns_result["error"] is None

    raw = dns_result["raw"]
    assert "dmarc" in raw, f"google.com should have DMARC in raw, keys: {list(raw.keys())}"
    assert "v=dmarc1" in raw["dmarc"].lower()

    # _dmarc TXT records should be populated
    assert len(raw.get("dmarc_txt", [])) > 0, "Expected _dmarc TXT records in raw"

    # Findings should confirm DMARC is present
    titles = [f["title"] for f in dns_result["findings"]]
    assert "DMARC record present" in titles, f"Expected 'DMARC record present' finding, got: {titles}"
    assert "No DMARC record" not in titles, f"google.com should not flag missing DMARC, got: {titles}"


# ---------------------------------------------------------------------------
# 4. CAA records
# ---------------------------------------------------------------------------


def test_caa_records(client):
    """Scan google.com -- should have CAA records restricting certificate issuance."""
    data = _dns_check(client, "google.com")

    dns_result = data["results"]["dns"]
    assert dns_result["error"] is None

    raw = dns_result["raw"]
    assert len(raw.get("caa", [])) > 0, f"google.com should have CAA records, got: {raw.get('caa')}"

    # Findings should confirm CAA is present (not "No CAA records")
    titles = [f["title"] for f in dns_result["findings"]]
    assert "CAA records present" in titles, f"Expected 'CAA records present' finding, got: {titles}"
    assert "No CAA records" not in titles, f"google.com should not flag missing CAA, got: {titles}"


# ---------------------------------------------------------------------------
# 5. Missing security records
# ---------------------------------------------------------------------------


def test_missing_security_records(client):
    """Scan example.com -- likely missing DMARC and/or SPF, should flag them."""
    data = _dns_check(client, "example.com")

    dns_result = data["results"]["dns"]
    assert dns_result["error"] is None

    titles = [f["title"] for f in dns_result["findings"]]
    severities = {f["title"]: f["severity"] for f in dns_result["findings"]}

    # example.com typically lacks SPF and/or DMARC and/or CAA.
    # At least one "missing" finding should be present.
    missing_findings = [t for t in titles if "no " in t.lower() or "missing" in t.lower()]
    assert len(missing_findings) > 0, (
        f"example.com should flag at least one missing security record, got findings: {titles}"
    )

    # Any "No SPF", "No DMARC", or "No CAA" finding should have severity >= low
    for title in missing_findings:
        assert severities[title] in ("medium", "low", "high", "critical"), (
            f"Missing-record finding '{title}' should be medium/low/high severity, got: {severities[title]}"
        )


# ---------------------------------------------------------------------------
# 6. Raw data structure
# ---------------------------------------------------------------------------


def test_raw_data_structure(client):
    """Verify the raw dict contains all expected DNS record type keys."""
    data = _dns_check(client, "google.com")

    dns_result = data["results"]["dns"]
    assert dns_result["error"] is None

    raw = dns_result["raw"]

    # Must have the domain field
    assert "domain" in raw
    assert raw["domain"] == "google.com"

    # All record types from _RECORD_TYPES should appear as lowercase keys
    expected_keys = ["a", "aaaa", "mx", "ns", "txt", "cname", "caa"]
    for key in expected_keys:
        assert key in raw, f"Missing expected key '{key}' in raw, got keys: {list(raw.keys())}"
        assert isinstance(raw[key], list), f"raw['{key}'] should be a list, got: {type(raw[key])}"

    # DMARC-specific keys
    assert "dmarc_txt" in raw
    assert isinstance(raw["dmarc_txt"], list)


# ---------------------------------------------------------------------------
# 7. Summary field with severity counts
# ---------------------------------------------------------------------------


def test_summary_field(client):
    """Verify summary has correct severity counts matching the findings."""
    data = _dns_check(client, "google.com")

    assert "summary" in data, f"Response should have summary field, got keys: {list(data.keys())}"

    summary = data["summary"]
    # Summary should have all severity count fields
    for level in ("critical", "high", "medium", "low", "info", "total"):
        assert level in summary, f"Summary missing '{level}' field"
        assert isinstance(summary[level], int), f"summary['{level}'] should be int"
        assert summary[level] >= 0, f"summary['{level}'] should be non-negative"

    # Total should equal sum of individual counts
    assert summary["total"] == (
        summary["critical"] + summary["high"] + summary["medium"] + summary["low"] + summary["info"]
    ), f"Total mismatch: {summary}"

    # Cross-check against actual findings
    dns_result = data["results"]["dns"]
    findings = dns_result["findings"]
    assert summary["total"] == len(findings), (
        f"Summary total ({summary['total']}) should match findings count ({len(findings)})"
    )

    # Verify individual severity counts match
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f["severity"]] += 1

    for level in ("critical", "high", "medium", "low", "info"):
        assert summary[level] == severity_counts[level], (
            f"Summary {level} count ({summary[level]}) != actual ({severity_counts[level]})"
        )
