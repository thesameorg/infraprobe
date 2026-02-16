"""Prometheus metrics for InfraProbe."""

from prometheus_client import Counter, Gauge, Histogram

REQUEST_COUNT = Counter(
    "infraprobe_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

REQUEST_DURATION = Histogram(
    "infraprobe_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
)

SCANNER_DURATION = Histogram(
    "infraprobe_scanner_duration_seconds",
    "Scanner execution duration in seconds",
    ["check"],
)

ACTIVE_SCANS = Gauge(
    "infraprobe_active_scans",
    "Number of currently running scan targets",
)
