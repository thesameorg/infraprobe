"""Integration tests for the web scanner (/v1/check/web).

Hits real targets — no mocks. Verifies CORS, exposed paths, robots.txt,
mixed content, security.txt checks and the summary severity counts.
"""

import pytest

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Raw section expectations
# ---------------------------------------------------------------------------
# Always present after a successful scan:
_ALWAYS_PRESENT_RAW_SECTIONS = {"cors", "exposed_paths", "security_txt"}
# Conditionally present (robots_txt only if the site has one; mixed_content
# only if the page was served over HTTPS):
_CONDITIONAL_RAW_SECTIONS = {"robots_txt", "mixed_content"}
_ALL_RAW_SECTIONS = _ALWAYS_PRESENT_RAW_SECTIONS | _CONDITIONAL_RAW_SECTIONS


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def test_cors_check(client):
    """Scan testphp.vulnweb.com — should check CORS and include cors section in raw."""
    resp = client.post("/v1/check/web", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    data = resp.json()
    web_result = data["results"]["web"]
    assert web_result["error"] is None

    # Raw must contain a cors section with the ACAO field
    raw = web_result["raw"]
    assert "cors" in raw, f"cors section missing from raw: {list(raw.keys())}"
    assert "access_control_allow_origin" in raw["cors"]
    assert "access_control_allow_credentials" in raw["cors"]

    # There should be at least one finding that mentions CORS (present, absent, or misconfigured)
    titles = [f["title"].lower() for f in web_result["findings"]]
    assert any("cors" in t for t in titles), f"Expected a CORS finding, got: {titles}"


# ---------------------------------------------------------------------------
# Exposed paths
# ---------------------------------------------------------------------------


def test_exposed_paths_check(client):
    """Scan testphp.vulnweb.com — should probe for exposed paths."""
    resp = client.post("/v1/check/web", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    web_result = resp.json()["results"]["web"]
    assert web_result["error"] is None

    raw = web_result["raw"]
    assert "exposed_paths" in raw, f"exposed_paths missing from raw: {list(raw.keys())}"
    assert isinstance(raw["exposed_paths"], list)

    # Whether or not paths are actually exposed, there should be a finding about it
    titles = [f["title"].lower() for f in web_result["findings"]]
    path_related = [t for t in titles if "path" in t or "accessible" in t or ".env" in t or ".git" in t]
    assert len(path_related) > 0, f"Expected at least one path-related finding, got titles: {titles}"


# ---------------------------------------------------------------------------
# security.txt
# ---------------------------------------------------------------------------


def test_security_txt_check(client):
    """Scan example.com — should check for security.txt presence."""
    resp = client.post("/v1/check/web", json={"target": "example.com"})
    assert resp.status_code == 200

    web_result = resp.json()["results"]["web"]
    assert web_result["error"] is None

    raw = web_result["raw"]
    assert "security_txt" in raw, f"security_txt missing from raw: {list(raw.keys())}"
    assert isinstance(raw["security_txt"], bool)

    # There should be a finding about security.txt (present or absent)
    titles = [f["title"].lower() for f in web_result["findings"]]
    assert any("security.txt" in t for t in titles), f"Expected security.txt finding, got: {titles}"


# ---------------------------------------------------------------------------
# robots.txt
# ---------------------------------------------------------------------------


def test_robots_txt_analysis(client):
    """Scan a site that has robots.txt — should analyze it.

    google.com is known to have a robots.txt, so raw should include robots_txt data.
    """
    resp = client.post("/v1/check/web", json={"target": "google.com"})
    assert resp.status_code == 200

    web_result = resp.json()["results"]["web"]
    assert web_result["error"] is None

    raw = web_result["raw"]
    # robots_txt may or may not appear if the site does not have one, but google.com does
    if "robots_txt" in raw:
        robots = raw["robots_txt"]
        assert robots["found"] is True
        assert "disallowed_count" in robots
        assert isinstance(robots["disallowed_count"], int)
        assert robots["disallowed_count"] > 0, "google.com robots.txt should have disallow entries"
        assert "sensitive_paths" in robots
        assert isinstance(robots["sensitive_paths"], list)


# ---------------------------------------------------------------------------
# Raw data structure completeness
# ---------------------------------------------------------------------------


def test_raw_data_structure(client):
    """Verify raw dict has expected sections after a full web scan.

    cors, exposed_paths, and security_txt are always populated.
    robots_txt appears only if the target has a robots.txt (status 200).
    mixed_content appears only if the page was fetched over HTTPS.
    """
    resp = client.post("/v1/check/web", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    web_result = resp.json()["results"]["web"]
    assert web_result["error"] is None

    raw = web_result["raw"]
    # Must have base fields
    assert "url" in raw, f"url missing from raw: {list(raw.keys())}"
    assert "status_code" in raw, f"status_code missing from raw: {list(raw.keys())}"
    assert isinstance(raw["status_code"], int)
    assert raw["url"].startswith("http")

    # Always-present sections
    missing_required = _ALWAYS_PRESENT_RAW_SECTIONS - set(raw.keys())
    assert not missing_required, f"Missing required raw sections: {missing_required}. Present keys: {list(raw.keys())}"

    # No unexpected keys outside the known set (plus base fields url/status_code)
    known_keys = _ALL_RAW_SECTIONS | {"url", "status_code"}
    unexpected = set(raw.keys()) - known_keys
    assert not unexpected, f"Unexpected raw keys: {unexpected}"

    # Type checks for each section that is present
    assert isinstance(raw["cors"], dict)
    assert isinstance(raw["exposed_paths"], list)
    assert isinstance(raw["security_txt"], bool)

    if "robots_txt" in raw:
        assert isinstance(raw["robots_txt"], dict)
        assert "found" in raw["robots_txt"]
    if "mixed_content" in raw:
        assert isinstance(raw["mixed_content"], list)


# ---------------------------------------------------------------------------
# Summary field (severity counts)
# ---------------------------------------------------------------------------


def test_summary_field(client):
    """Verify the response summary has correct severity counts matching findings."""
    resp = client.post("/v1/check/web", json={"target": "testphp.vulnweb.com"})
    assert resp.status_code == 200

    data = resp.json()
    web_result = data["results"]["web"]
    assert web_result["error"] is None
    assert len(web_result["findings"]) > 0, "Expected at least one finding"

    # summary is computed at the TargetResult level across all check results
    summary = data["summary"]
    assert "critical" in summary
    assert "high" in summary
    assert "medium" in summary
    assert "low" in summary
    assert "info" in summary
    assert "total" in summary

    # Manually count severities from findings and verify they match the summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in web_result["findings"]:
        sev = finding["severity"]
        assert sev in counts, f"Unknown severity: {sev}"
        counts[sev] += 1

    # Since we only ran the web check, summary should equal findings counts
    assert summary["total"] == sum(counts.values())
    assert summary["critical"] == counts["critical"]
    assert summary["high"] == counts["high"]
    assert summary["medium"] == counts["medium"]
    assert summary["low"] == counts["low"]
    assert summary["info"] == counts["info"]
