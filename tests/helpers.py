"""Shared test helpers for the new always-async scan API."""

import time

import pytest
from fastapi.testclient import TestClient


def poll_until_done(client: TestClient, job_id: str, timeout: float = 30) -> dict:
    """Poll GET /v1/scan/{job_id} until completed or failed."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = client.get(f"/v1/scan/{job_id}")
        assert resp.status_code == 200
        job = resp.json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.5)
    pytest.fail(f"Job {job_id} did not complete within {timeout}s")


def submit_scan(client: TestClient, payload: dict, timeout: float = 30) -> dict:
    """Submit POST /v1/scan and wait for completion. Returns ScanResponse dict."""
    resp = client.post("/v1/scan", json=payload)
    assert resp.status_code == 202, f"Expected 202, got {resp.status_code}: {resp.text}"
    job = poll_until_done(client, resp.json()["job_id"], timeout)
    assert job["status"] == "completed", f"Scan failed: {job.get('error')}"
    return job["result"]


def submit_check(client: TestClient, check_type: str, payload: dict, timeout: float = 30) -> dict:
    """Submit POST /v1/check/{type}. Returns TargetResult dict (handles both inline and async)."""
    resp = client.post(f"/v1/check/{check_type}", json=payload)
    if resp.status_code == 200:
        return resp.json()  # Inline TargetResult
    assert resp.status_code == 202, f"Expected 200 or 202, got {resp.status_code}: {resp.text}"
    job = poll_until_done(client, resp.json()["job_id"], timeout)
    assert job["status"] == "completed", f"Check failed: {job.get('error')}"
    # Async check wraps in ScanResponse — extract the TargetResult
    return job["result"]["results"][0]
