from fastapi.testclient import TestClient

from tests.helpers import submit_scan


def test_sync_scan_returns_200(client: TestClient):
    """Scan always returns 200 with inline ScanResponse."""
    result = submit_scan(client, {"target": "example.com"})
    assert "results" in result
    assert len(result["results"]) == 1
    assert "summary" in result


def test_get_nonexistent_job_returns_404(client: TestClient):
    resp = client.get("/v1/scan/nonexistent123")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"] == "Job not found"
    assert body["error"] == "not_found"


def test_scan_blocked_target_returns_400(client: TestClient):
    resp = client.post("/v1/scan", json={"target": "127.0.0.1"})
    assert resp.status_code == 400


def test_scan_invalid_target_returns_422(client: TestClient):
    resp = client.post("/v1/scan", json={"target": "not a valid target!@#$"})
    assert resp.status_code == 422
