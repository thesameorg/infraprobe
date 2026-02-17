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


def test_nmap_backpressure_sync_ports(client):
    """Sync port scan should return 429 when nmap slots are exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/ports", json={"target": "scanme.nmap.org"})
        assert resp.status_code == 429
        body = resp.json()
        assert body["error"] == "too_many_requests"
        assert "nmap" in body["detail"].lower()


def test_nmap_backpressure_sync_cve(client):
    """Sync CVE scan should return 429 when nmap slots are exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/cve", json={"target": "scanme.nmap.org"})
        assert resp.status_code == 429
        body = resp.json()
        assert body["error"] == "too_many_requests"


def test_nmap_backpressure_bundle_scan(client):
    """Bundle scan with ports check should return 429 when nmap slots exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/scan", json={"targets": ["scanme.nmap.org"], "checks": ["ports"]})
        assert resp.status_code == 429
        body = resp.json()
        assert body["error"] == "too_many_requests"


def test_nmap_backpressure_non_nmap_unaffected(client):
    """Non-nmap checks should NOT be affected by exhausted nmap slots."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        assert resp.status_code == 200


def test_nmap_backpressure_async_bypasses(client):
    """Async endpoint should accept nmap checks even when slots exhausted (queues them)."""
    with _exhaust_nmap_slots():
        resp = client.post(
            "/v1/scan/async",
            json={"targets": ["scanme.nmap.org"], "checks": ["ports"]},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert "job_id" in body
