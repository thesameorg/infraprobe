def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_ready(client):
    """Readiness probe should return 200 when cleanup task is running."""
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"


def test_metrics_endpoint(client):
    """Prometheus metrics endpoint should return 200 with text content."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    # Should contain at least one of our custom metrics
    assert "infraprobe_" in response.text


def test_target_too_long(client):
    """Target string exceeding max_length should return 422."""
    long_target = "a" * 2049
    resp = client.post("/v1/check/headers", json={"target": long_target})
    assert resp.status_code == 422
