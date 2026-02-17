import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient
from pytest_httpserver import HTTPServer


def _poll_until_done(client: TestClient, job_id: str, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = client.get(f"/v1/scan/{job_id}")
        assert resp.status_code == 200
        job = resp.json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.5)
    raise TimeoutError(f"Job {job_id} did not complete within {timeout}s")


def test_webhook_delivered_on_scan_complete(client: TestClient, httpserver: HTTPServer, monkeypatch):
    # Allow localhost for webhook (normally blocked by SSRF protection)
    monkeypatch.setattr("infraprobe.api.scan._validate_webhook_url", lambda url: url)

    httpserver.expect_request("/webhook", method="POST").respond_with_data("OK", status=200)
    webhook_url = httpserver.url_for("/webhook")

    resp = client.post(
        "/v1/scan",
        json={"targets": ["example.com"], "checks": ["headers"], "webhook_url": webhook_url},
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    _poll_until_done(client, job_id)

    # Give webhook delivery a moment to complete
    time.sleep(2)

    # Verify the server received the webhook POST
    assert len(httpserver.log) >= 1
    req = httpserver.log[0][0]
    payload = json.loads(req.data)
    assert payload["job_id"] == job_id
    assert payload["event"] in ("scan.completed", "scan.failed")
    assert payload["status"] in ("completed", "failed")
    assert "request" in payload
    assert "created_at" in payload


def test_webhook_includes_hmac_signature(client: TestClient, httpserver: HTTPServer, monkeypatch):
    monkeypatch.setattr("infraprobe.api.scan._validate_webhook_url", lambda url: url)

    httpserver.expect_request("/webhook", method="POST").respond_with_data("OK", status=200)
    webhook_url = httpserver.url_for("/webhook")
    secret = "my-test-secret"

    resp = client.post(
        "/v1/scan",
        json={
            "targets": ["example.com"],
            "checks": ["headers"],
            "webhook_url": webhook_url,
            "webhook_secret": secret,
        },
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    _poll_until_done(client, job_id)
    time.sleep(2)

    assert len(httpserver.log) >= 1
    req = httpserver.log[0][0]
    sig_header = req.headers.get("X-InfraProbe-Signature")
    assert sig_header is not None
    assert sig_header.startswith("sha256=")

    # Verify the signature is correct
    expected_mac = hmac.new(secret.encode(), req.data, hashlib.sha256).hexdigest()
    assert sig_header == f"sha256={expected_mac}"


def test_webhook_invalid_url_returns_422(client: TestClient):
    # Private IP webhook should be rejected (SSRF protection)
    resp = client.post(
        "/v1/scan",
        json={"targets": ["example.com"], "checks": ["headers"], "webhook_url": "http://10.0.0.1/hook"},
    )
    assert resp.status_code == 422


def test_webhook_status_tracked_on_job(client: TestClient, httpserver: HTTPServer, monkeypatch):
    monkeypatch.setattr("infraprobe.api.scan._validate_webhook_url", lambda url: url)

    httpserver.expect_request("/webhook", method="POST").respond_with_data("OK", status=200)
    webhook_url = httpserver.url_for("/webhook")

    resp = client.post(
        "/v1/scan",
        json={"targets": ["example.com"], "checks": ["headers"], "webhook_url": webhook_url},
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    _poll_until_done(client, job_id)
    time.sleep(2)

    # Poll again — webhook_status should be set
    resp = client.get(f"/v1/scan/{job_id}")
    job = resp.json()
    assert job["webhook_status"] == "delivered"
    assert job["webhook_delivered_at"] is not None


def test_no_webhook_when_url_not_provided(client: TestClient):
    resp = client.post(
        "/v1/scan",
        json={"targets": ["example.com"], "checks": ["headers"]},
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    job = _poll_until_done(client, job_id)
    assert job["webhook_status"] is None
    assert job["webhook_delivered_at"] is None


def test_webhook_secret_not_in_job_response(client: TestClient, httpserver: HTTPServer, monkeypatch):
    monkeypatch.setattr("infraprobe.api.scan._validate_webhook_url", lambda url: url)

    httpserver.expect_request("/webhook", method="POST").respond_with_data("OK", status=200)
    webhook_url = httpserver.url_for("/webhook")

    resp = client.post(
        "/v1/scan",
        json={
            "targets": ["example.com"],
            "checks": ["headers"],
            "webhook_url": webhook_url,
            "webhook_secret": "super-secret",
        },
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    job = _poll_until_done(client, job_id)
    # The secret should never appear in the job response
    assert "webhook_secret" not in job.get("request", {})
