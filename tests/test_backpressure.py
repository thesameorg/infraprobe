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


def test_nmap_backpressure_slow_ports_returns_202(client):
    """Port scan is now a slow check — always returns 202 (async), even when nmap slots exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/ports", json={"target": "scanme.nmap.org"})
        assert resp.status_code == 202
        body = resp.json()
        assert "job_id" in body


def test_nmap_backpressure_slow_cve_returns_202(client):
    """CVE scan is now a slow check — always returns 202 (async), even when nmap slots exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/cve", json={"target": "scanme.nmap.org"})
        assert resp.status_code == 202
        body = resp.json()
        assert "job_id" in body


def test_nmap_backpressure_bundle_scan_returns_202(client):
    """Bundle scan is always async (202) — queues the job even when nmap slots exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/scan", json={"targets": ["scanme.nmap.org"], "checks": ["ports"]})
        assert resp.status_code == 202
        body = resp.json()
        assert "job_id" in body


def test_nmap_backpressure_non_nmap_unaffected(client):
    """Non-nmap checks should NOT be affected by exhausted nmap slots."""
    with _exhaust_nmap_slots():
        resp = client.post("/v1/check/headers", json={"target": "example.com"})
        assert resp.status_code == 200


def test_nmap_backpressure_scan_always_async(client):
    """POST /v1/scan is always async — queues nmap checks even when slots exhausted."""
    with _exhaust_nmap_slots():
        resp = client.post(
            "/v1/scan",
            json={"targets": ["scanme.nmap.org"], "checks": ["ports"]},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert "job_id" in body
