import time

from fastapi.testclient import TestClient

from tests.helpers import submit_scan


def test_async_scan_submit_returns_202(client: TestClient):
    """Force async mode → always 202 regardless of check speed."""
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["headers"], "async_mode": True})
    assert resp.status_code == 202
    body = resp.json()
    assert "job_id" in body
    assert body["status"] == "pending"
    assert "created_at" in body


def test_async_scan_poll_until_completed(client: TestClient):
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["headers"], "async_mode": True})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    # Poll until completed (max ~30s)
    deadline = time.monotonic() + 30
    job = None
    while time.monotonic() < deadline:
        resp = client.get(f"/v1/scan/{job_id}")
        assert resp.status_code == 200
        job = resp.json()
        if job["status"] in ("completed", "failed"):
            break
        time.sleep(0.5)

    assert job is not None
    assert job["status"] == "completed"
    assert job["result"] is not None
    assert len(job["result"]["results"]) == 1
    assert job["result"]["results"][0]["target"] is not None


def test_async_scan_echoes_request(client: TestClient):
    resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["headers"], "async_mode": True})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    # Poll until done
    deadline = time.monotonic() + 30
    job = None
    while time.monotonic() < deadline:
        resp = client.get(f"/v1/scan/{job_id}")
        job = resp.json()
        if job["status"] in ("completed", "failed"):
            break
        time.sleep(0.5)

    assert job is not None
    assert job["request"]["targets"] == ["example.com"]
    assert job["request"]["checks"] == ["headers"]
    assert job["request"]["async_mode"] is True


def test_sync_scan_returns_200_for_fast_checks(client: TestClient):
    """Fast checks without async_mode → 200 with inline ScanResponse."""
    result = submit_scan(client, {"targets": ["example.com"], "checks": ["headers"]})
    assert "results" in result
    assert len(result["results"]) == 1
    assert "summary" in result


def test_get_nonexistent_job_returns_404(client: TestClient):
    resp = client.get("/v1/scan/nonexistent123")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"] == "Job not found"
    assert body["error"] == "not_found"


def test_async_scan_blocked_target_returns_400(client: TestClient):
    resp = client.post("/v1/scan", json={"targets": ["127.0.0.1"], "checks": ["headers"]})
    assert resp.status_code == 400


def test_async_scan_invalid_target_returns_422(client: TestClient):
    resp = client.post("/v1/scan", json={"targets": ["not a valid target!@#$"], "checks": ["headers"]})
    assert resp.status_code == 422
