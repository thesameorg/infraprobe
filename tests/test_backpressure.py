"""Tests for nmap backpressure (429 when all nmap slots exhausted)."""

from contextlib import contextmanager

import pytest

from infraprobe.config import nmap_semaphore

pytestmark = pytest.mark.integration


@contextmanager
def _exhaust_nmap_slots():
    """Temporarily set nmap semaphore to 0 slots, restore original value on exit."""
    sem = nmap_semaphore()
    original = sem._value
    sem._value = 0
    try:
        yield
    finally:
        sem._value = original


def test_nmap_backpressure_ports_check_times_out(client):
    """Ports check is sync — when nmap slots are exhausted, it times out inline."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/ports", json={"target": "scanme.nmap.org"})
        assert resp.status_code == 200
        body = resp.json()
        # Should have a timeout error in the ports check result
        ports_result = body["results"]["ports"]
        assert ports_result["error"] is not None
        assert "timed out" in ports_result["error"].lower()


def test_nmap_backpressure_slow_cve_returns_202(client):
    """CVE scan is an async check — always returns 202 even when nmap slots are exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/cve", json={"target": "scanme.nmap.org"})
        assert resp.status_code == 202
        body = resp.json()
        assert "job_id" in body


def test_nmap_backpressure_bundle_scan_ports_sync(client):
    """Bundle scan with only ports (fast) → sync 200, times out when nmap slots exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/scan", json={"targets": ["scanme.nmap.org"], "checks": ["ports"]})
        assert resp.status_code == 200
        body = resp.json()
        ports_result = body["results"][0]["results"]["ports"]
        assert ports_result["error"] is not None


def test_nmap_backpressure_non_nmap_unaffected(client):
    """Non-nmap checks should NOT be affected by exhausted nmap slots."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        assert resp.status_code == 200


def test_nmap_backpressure_bundle_async_queues(client):
    """Bundle scan with async_mode=True queues nmap checks even when slots exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post(
            "/v1/scan",
            json={"targets": ["scanme.nmap.org"], "checks": ["ports"], "async_mode": True},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert "job_id" in body
