import hmac
import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import generate_latest
from starlette.middleware.base import BaseHTTPMiddleware

from infraprobe import __version__
from infraprobe.api.scan import drain_background_tasks, register_scanner, reset_shutdown_flag
from infraprobe.api.scan import router as scan_router
from infraprobe.blocklist import BlockedTargetError, CapacityExceededError, InvalidTargetError
from infraprobe.config import settings
from infraprobe.logging import request_ctx, setup_logging
from infraprobe.metrics import REQUEST_COUNT, REQUEST_DURATION
from infraprobe.models import CheckType
from infraprobe.scanners import blacklist, cve, ports, tech, web, whois_scanner
from infraprobe.scanners import dns as dns_scanner
from infraprobe.scanners import headers_drheader as headers
from infraprobe.scanners import ssl as ssl_scanner
from infraprobe.scanners.deep import dns as dns_deep
from infraprobe.scanners.deep import ssl as ssl_deep_scanner
from infraprobe.storage import MemoryJobStore, create_job_store

setup_logging()

logger = logging.getLogger("infraprobe.app")

# Paths excluded from logging and auth middleware
_SKIP_PATHS = frozenset({"/health", "/health/ready", "/metrics"})


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    if settings.job_store_backend == "firestore":
        store = create_job_store(
            backend="firestore",
            project=settings.firestore_project,
            database=settings.firestore_database,
            ttl_seconds=settings.job_ttl_seconds,
        )
        app.state.job_store = store
        reset_shutdown_flag()
        yield
        await drain_background_tasks(timeout=25)
    else:
        store = MemoryJobStore(
            ttl_seconds=settings.job_ttl_seconds,
            cleanup_interval=settings.job_cleanup_interval,
        )
        app.state.job_store = store
        store.start_cleanup_loop()
        reset_shutdown_flag()
        yield
        await drain_background_tasks(timeout=25)
        store.stop_cleanup_loop()


app = FastAPI(
    title="InfraProbe",
    version=__version__,
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Scans", "description": "Bundle scan endpoints — always async. Submit scan, poll for results."},
        {"name": "Checks", "description": "Individual check endpoints — fast checks inline, slow checks async."},
        {"name": "Internal", "description": "Health probes and observability."},
    ],
)


# ---------------------------------------------------------------------------
# Request logging middleware (raw ASGI — no BaseHTTPMiddleware overhead)
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware:
    """Log every request with duration, status, and a unique request_id.

    Implemented as raw ASGI middleware to avoid the overhead and quirks of
    Starlette's BaseHTTPMiddleware.  Sets ``request_ctx`` so all downstream
    loggers (including scanner code running under asyncio.gather) inherit
    request-scoped fields automatically.

    Also records Prometheus request metrics (count + duration histogram).
    """

    def __init__(self, app):  # type: ignore[no-untyped-def]
        self.app = app

    async def __call__(self, scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")

        # Skip infrastructure endpoints to avoid noise from Cloud Run probes
        if path in _SKIP_PATHS:
            return await self.app(scope, receive, send)

        request_id = uuid.uuid4().hex[:8]
        method = scope.get("method", "")
        client = scope.get("client")
        client_ip = client[0] if client else ""

        ctx = {
            "request_id": request_id,
            "method": method,
            "path": path,
            "client_ip": client_ip,
        }
        token = request_ctx.set(ctx)

        status_code = 500  # default in case send never fires
        start = time.monotonic()

        async def send_wrapper(message):  # type: ignore[no-untyped-def]
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_s = time.monotonic() - start
            duration_ms = int(duration_s * 1000)
            logger.info(
                "request completed",
                extra={"status_code": status_code, "duration_ms": duration_ms, "endpoint": path},
            )
            REQUEST_COUNT.labels(method=method, path=path, status=status_code).inc()
            REQUEST_DURATION.labels(method=method, path=path).observe(duration_s)
            request_ctx.reset(token)


app.add_middleware(RequestLoggingMiddleware)


if settings.rapidapi_proxy_secret and not settings.dev_bypass_auth:

    class _RapidAPIAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):  # type: ignore[override]
            if request.url.path in _SKIP_PATHS:
                return await call_next(request)
            secret = request.headers.get("x-rapidapi-proxy-secret") or ""
            if not hmac.compare_digest(secret, settings.rapidapi_proxy_secret):
                logger.warning("rapidapi auth rejected", extra={"path": request.url.path})
                return JSONResponse(status_code=403, content={"error": "forbidden", "detail": "Forbidden"})
            return await call_next(request)

    app.add_middleware(_RapidAPIAuthMiddleware)
elif settings.dev_bypass_auth:
    logger.warning("DEV_BYPASS_AUTH is enabled — authentication disabled")


@app.exception_handler(BlockedTargetError)
async def _blocked_target_handler(_request: Request, exc: BlockedTargetError) -> JSONResponse:
    logger.warning("blocked target", extra={"error": str(exc)})
    return JSONResponse(status_code=400, content={"error": "blocked_target", "detail": str(exc)})


@app.exception_handler(CapacityExceededError)
async def _capacity_exceeded_handler(_request: Request, exc: CapacityExceededError) -> JSONResponse:
    logger.warning("capacity exceeded", extra={"error": str(exc)})
    return JSONResponse(status_code=429, content={"error": "too_many_requests", "detail": str(exc)})


@app.exception_handler(InvalidTargetError)
async def _invalid_target_handler(_request: Request, exc: InvalidTargetError) -> JSONResponse:
    logger.warning("invalid target", extra={"error": str(exc)})
    return JSONResponse(status_code=422, content={"error": "invalid_target", "detail": str(exc)})


@app.exception_handler(Exception)
async def _unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled exception: %s: %s", type(exc).__name__, exc)
    return JSONResponse(status_code=500, content={"error": "internal_error", "detail": "Internal server error"})


# Light scanners (fast, default)
register_scanner(CheckType.HEADERS, headers.scan)
register_scanner(CheckType.SSL, ssl_scanner.scan)
register_scanner(CheckType.DNS, dns_scanner.scan)
register_scanner(CheckType.TECH, tech.scan)
register_scanner(CheckType.BLACKLIST, blacklist.scan)
register_scanner(CheckType.WEB, web.scan)
register_scanner(CheckType.WHOIS, whois_scanner.scan)

# Deep scanners (slower, more thorough)
register_scanner(CheckType.SSL_DEEP, ssl_deep_scanner.scan)
register_scanner(CheckType.DNS_DEEP, dns_deep.scan)
register_scanner(CheckType.BLACKLIST_DEEP, blacklist.scan_deep)
register_scanner(CheckType.PORTS, ports.scan)
register_scanner(CheckType.PORTS_DEEP, ports.scan_deep)
register_scanner(CheckType.CVE, cve.scan)

# Register routes with /v1 prefix
app.include_router(scan_router, prefix="/v1")


@app.get("/health", tags=["Internal"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready", tags=["Internal"])
async def health_ready(request: Request) -> JSONResponse:
    """Readiness probe — checks that the job store is available."""
    store = request.app.state.job_store
    if isinstance(store, MemoryJobStore):
        task = store._cleanup_task
        if task is None or task.done():
            return JSONResponse(status_code=503, content={"status": "not ready", "reason": "cleanup task not running"})
    return JSONResponse(status_code=200, content={"status": "ready"})


@app.get("/metrics", tags=["Internal"])
async def metrics() -> PlainTextResponse:
    """Prometheus metrics endpoint."""
    return PlainTextResponse(generate_latest(), media_type="text/plain; version=0.0.4; charset=utf-8")
