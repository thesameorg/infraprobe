"""Shared test helpers for InfraProbe scan API."""

from fastapi.testclient import TestClient


def submit_scan(client: TestClient, payload: dict, timeout: float = 30) -> dict:
    """Submit POST /v1/scan. Always returns 200 with ScanResponse dict."""
    resp = client.post("/v1/scan", json=payload)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    return resp.json()
