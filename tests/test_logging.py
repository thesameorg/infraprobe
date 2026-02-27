"""Tests for structured JSON logging."""

import json
import logging

from infraprobe.logging import JSONFormatter, request_ctx


def test_json_formatter_output():
    """JSONFormatter should produce valid JSON with Cloud Logging fields."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="infraprobe.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="test message",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    entry = json.loads(output)

    assert entry["severity"] == "INFO"
    assert entry["logger"] == "infraprobe.test"
    assert entry["message"] == "test message"
    assert "timestamp" in entry
    assert entry["timestamp"].endswith("Z")


def test_json_formatter_with_extra():
    """Extra fields from logger.info(..., extra={...}) should appear in JSON."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="infraprobe.scanner",
        level=logging.WARNING,
        pathname="test.py",
        lineno=1,
        msg="check timeout",
        args=(),
        exc_info=None,
    )
    record.check = "headers"
    record.target = "example.com"
    record.duration_ms = 10500

    output = formatter.format(record)
    entry = json.loads(output)

    assert entry["severity"] == "WARNING"
    assert entry["check"] == "headers"
    assert entry["target"] == "example.com"
    assert entry["duration_ms"] == 10500


def test_json_formatter_merges_request_ctx():
    """JSONFormatter should merge request_ctx ContextVar into the JSON output."""
    formatter = JSONFormatter()
    token = request_ctx.set({"request_id": "abc12345", "method": "POST", "path": "/v1/scan", "client_ip": "1.2.3.4"})
    try:
        record = logging.LogRecord(
            name="infraprobe.scanner",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="check done",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        entry = json.loads(output)

        assert entry["request_id"] == "abc12345"
        assert entry["method"] == "POST"
        assert entry["path"] == "/v1/scan"
        assert entry["client_ip"] == "1.2.3.4"
    finally:
        request_ctx.reset(token)


def test_json_formatter_exception():
    """Exceptions should be captured in an 'exception' field."""
    formatter = JSONFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord(
            name="infraprobe.test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="check error",
            args=(),
            exc_info=sys.exc_info(),
        )

    output = formatter.format(record)
    entry = json.loads(output)

    assert entry["severity"] == "ERROR"
    assert "exception" in entry
    assert "ValueError: boom" in entry["exception"]


def test_health_not_logged(client, caplog):
    """Health endpoint should not produce log lines."""
    with caplog.at_level(logging.DEBUG):
        client.get("/health")

    messages = [r.message for r in caplog.records]
    assert "request completed" not in messages


def test_scan_bundle_logs(client, caplog):
    """Bundle scan should log scan started, finished per check, target done, scan done."""
    with caplog.at_level(logging.INFO, logger="infraprobe"):
        resp = client.post("/v1/scan", json={"target": "example.com"})
        assert resp.status_code == 200

    messages = [r.message for r in caplog.records]
    assert any("scan started:" in m for m in messages)
    assert sum("finished on" in m for m in messages) == 5  # headers, ssl, dns, web, whois
    assert any("target done:" in m for m in messages)
    assert any("scan done:" in m for m in messages)

    scan_started = next(r for r in caplog.records if "scan started:" in r.message)
    assert scan_started.targets == ["example.com"]
    assert set(scan_started.checks) == {"headers", "ssl", "dns", "web", "whois"}


def test_log_level_respects_config():
    """setup_logging should set the root logger level from settings."""
    root = logging.getLogger()
    # Default config is "info"
    assert root.level <= logging.INFO
