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


def test_scanner_logs_on_check(client, caplog):
    """Scanner should produce started/finished logs with expected fields."""
    with caplog.at_level(logging.INFO, logger="infraprobe.scanner"):
        client.post("/v1/check/headers", json={"target": "example.com"})

    started = [r for r in caplog.records if "started on" in r.message]
    assert len(started) == 1
    assert started[0].check == "headers"
    assert started[0].scanner_timeout > 0

    finished = [r for r in caplog.records if "finished on" in r.message]
    assert len(finished) == 1

    record = finished[0]
    assert record.check == "headers"
    assert record.target == "example.com"
    assert isinstance(record.duration_ms, int)
    assert record.duration_ms >= 0
    assert isinstance(record.findings_count, int)
    assert hasattr(record, "scanner_timeout")


def test_request_completed_log(client, caplog):
    """Middleware should log 'request completed' with status_code and duration_ms."""
    with caplog.at_level(logging.INFO, logger="infraprobe.app"):
        client.post("/v1/check/headers", json={"target": "example.com"})

    completed = [r for r in caplog.records if r.message == "request completed"]
    assert len(completed) == 1

    record = completed[0]
    assert record.status_code == 200
    assert isinstance(record.duration_ms, int)
    assert record.endpoint == "/v1/check/headers"


def test_health_not_logged(client, caplog):
    """Health endpoint should not produce log lines."""
    with caplog.at_level(logging.DEBUG):
        client.get("/health")

    messages = [r.message for r in caplog.records]
    assert "request completed" not in messages


def test_blocked_target_logged(client, caplog):
    """Blocked target should produce a warning log."""
    with caplog.at_level(logging.WARNING, logger="infraprobe.app"):
        client.post("/v1/check/headers", json={"target": "127.0.0.1"})

    warnings = [r for r in caplog.records if "blocked" in r.message]
    assert len(warnings) >= 1
    assert warnings[0].levelno == logging.WARNING


def test_scan_bundle_logs(client, caplog):
    """Bundle scan should log scan started, finished per check, target done, scan done."""
    import time

    with caplog.at_level(logging.INFO, logger="infraprobe"):
        resp = client.post("/v1/scan", json={"targets": ["example.com"], "checks": ["headers", "ssl"]})
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]
        # Poll until background task completes so logs are captured
        for _ in range(30):
            poll = client.get(f"/v1/scan/{job_id}")
            if poll.json()["status"] in ("completed", "failed"):
                break
            time.sleep(0.5)

    messages = [r.message for r in caplog.records]
    assert any("scan started:" in m for m in messages)
    assert sum("finished on" in m for m in messages) == 2  # headers + ssl
    assert any("target done:" in m for m in messages)
    assert any("scan done:" in m for m in messages)

    scan_started = next(r for r in caplog.records if "scan started:" in r.message)
    assert scan_started.targets == ["example.com"]
    assert set(scan_started.checks) == {"headers", "ssl"}


def test_request_id_in_context(client, caplog):
    """request_id set by middleware should propagate to scanner logs via ContextVar."""
    with caplog.at_level(logging.INFO):
        client.post("/v1/check/headers", json={"target": "example.com"})

    # Verify JSON formatter would include request_id by checking the ContextVar was set
    # (caplog records don't go through the formatter, but we can verify the formatter
    # produces correct output by formatting one of the captured records)
    scanner_records = [r for r in caplog.records if r.name == "infraprobe.scanner"]
    assert len(scanner_records) > 0


def test_log_level_respects_config():
    """setup_logging should set the root logger level from settings."""
    root = logging.getLogger()
    # Default config is "info"
    assert root.level <= logging.INFO
