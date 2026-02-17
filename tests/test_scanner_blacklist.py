"""Blacklist (DNSBL) scanner tests — verify real DNSBL lookups."""

import pytest

pytestmark = pytest.mark.integration


def test_blacklist_clean_domain(client):
    """google.com should not be listed on any major DNSBL."""
    resp = client.post("/v1/check/blacklist", json={"target": "google.com"})
    assert resp.status_code == 200

    data = resp.json()
    bl_result = data["results"]["blacklist"]
    assert bl_result["error"] is None

    raw = bl_result["raw"]
    assert "ip" in raw
    assert "listings" in raw
    assert raw["listed_count"] == 0
    assert raw["total_checked"] == 2  # light = 2 major zones

    # Should have positive "not listed" finding
    titles = [f["title"] for f in bl_result["findings"]]
    assert any("not listed" in t.lower() for t in titles)


def test_blacklist_raw_structure(client):
    """Verify raw data has all expected fields."""
    resp = client.post("/v1/check/blacklist", json={"target": "example.com"})
    assert resp.status_code == 200

    raw = resp.json()["results"]["blacklist"]["raw"]
    assert "ip" in raw
    assert "reversed_ip" in raw
    assert "listings" in raw
    assert "listed_count" in raw
    assert "total_checked" in raw
    assert isinstance(raw["listings"], dict)


def test_blacklist_resolves_domain_to_ip(client):
    """Should resolve domain to IPv4 before DNSBL lookup."""
    resp = client.post("/v1/check/blacklist", json={"target": "google.com"})
    assert resp.status_code == 200

    raw = resp.json()["results"]["blacklist"]["raw"]
    # IP should be a valid IPv4
    parts = raw["ip"].split(".")
    assert len(parts) == 4
    # Reversed IP should be the reverse
    reversed_parts = raw["reversed_ip"].split(".")
    assert reversed_parts == list(reversed(parts))


@pytest.mark.slow
def test_blacklist_deep_more_zones(client):
    """Deep blacklist check should query more zones than light."""
    resp = client.post("/v1/check/blacklist_deep", json={"target": "google.com"})
    assert resp.status_code == 200

    raw = resp.json()["results"]["blacklist_deep"]["raw"]
    # Deep checks 15 zones (some may timeout)
    assert raw["total_checked"] > 2
    assert len(raw["listings"]) > 2


def test_blacklist_summary_field(client):
    """Verify summary has correct severity counts."""
    resp = client.post("/v1/check/blacklist", json={"target": "google.com"})
    assert resp.status_code == 200

    data = resp.json()
    assert "summary" in data
    summary = data["summary"]
    assert "total" in summary
    assert summary["total"] > 0  # at least the "not listed" INFO finding
    assert summary["info"] > 0
