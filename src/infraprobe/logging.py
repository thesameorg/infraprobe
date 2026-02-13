"""Structured JSON logging for Cloud Logging compatibility.

Every log record is emitted as a single JSON line to stdout.  Cloud Run
auto-ingests these into Cloud Logging where every field becomes queryable.
Downloaded logs can be analyzed with ``jq`` or pandas.

Usage::

    from infraprobe.logging import setup_logging, request_ctx

    setup_logging()                       # call once at startup
    request_ctx.set({"request_id": …})    # set per-request fields
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

# Request-scoped context: automatically inherited by asyncio.gather children.
request_ctx: ContextVar[dict] = ContextVar("request_ctx")

# Python log level → Cloud Logging severity
_SEVERITY_MAP = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARNING",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "CRITICAL",
}


class JSONFormatter(logging.Formatter):
    """Format every log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        import json

        now = datetime.now(UTC)
        entry: dict = {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
            "severity": _SEVERITY_MAP.get(record.levelno, "DEFAULT"),
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Merge request-scoped context (request_id, method, path, client_ip)
        ctx = request_ctx.get({})
        entry.update(ctx)

        # Merge extra fields passed via logger.info("…", extra={…})
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in (
                "name",
                "msg",
                "args",
                "created",
                "relativeCreated",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "levelno",
                "levelname",
                "pathname",
                "filename",
                "module",
                "thread",
                "threadName",
                "process",
                "processName",
                "msecs",
                "message",
                "taskName",
            ):
                continue
            if key not in entry:
                entry[key] = value

        if record.exc_info and record.exc_info[1] is not None:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, default=str)


def setup_logging() -> None:
    """Configure root logger with JSON formatter on stdout."""
    from infraprobe.config import settings

    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Remove any existing handlers (e.g. from basicConfig)
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)

    # Quiet noisy third-party loggers
    for name in ("httpx", "httpcore", "uvicorn.access", "sslyze", "wappalyzer", "hpack"):
        logging.getLogger(name).setLevel(logging.WARNING)
