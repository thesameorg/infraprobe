import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from infraprobe import __version__
from infraprobe.api.scan import register_scanner
from infraprobe.api.scan import router as scan_router
from infraprobe.blocklist import BlockedTargetError, InvalidTargetError
from infraprobe.config import settings
from infraprobe.logging import request_ctx, setup_logging
from infraprobe.models import CheckType
from infraprobe.scanners import blacklist, cve, ports, tech, web
from infraprobe.scanners import dns as dns_scanner
from infraprobe.scanners import headers_drheader as headers
from infraprobe.scanners import ssl as ssl_scanner
from infraprobe.scanners.deep import dns as dns_deep
from infraprobe.scanners.deep import ssl as ssl_deep_scanner
from infraprobe.scanners.deep import tech as tech_deep
from infraprobe.storage import MemoryJobStore

setup_logging()

logger = logging.getLogger("infraprobe.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    store = MemoryJobStore(
        ttl_seconds=settings.job_ttl_seconds,
        cleanup_interval=settings.job_cleanup_interval,
    )
    app.state.job_store = store
    store.start_cleanup_loop()
    yield
    store.stop_cleanup_loop()


app = FastAPI(title="InfraProbe", version=__version__, lifespan=lifespan)


# ---------------------------------------------------------------------------
# Request logging middleware (raw ASGI — no BaseHTTPMiddleware overhead)
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware:
    """Log every request with duration, status, and a unique request_id.

    Implemented as raw ASGI middleware to avoid the overhead and quirks of
    Starlette's BaseHTTPMiddleware.  Sets ``request_ctx`` so all downstream
    loggers (including scanner code running under asyncio.gather) inherit
    request-scoped fields automatically.
    """

    def __init__(self, app):  # type: ignore[no-untyped-def]
        self.app = app

    async def __call__(self, scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")

        # Skip health endpoint to avoid noise from Cloud Run probes
        if path == "/health":
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
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.info(
                "request completed",
                extra={"status_code": status_code, "duration_ms": duration_ms, "endpoint": path},
            )
            request_ctx.reset(token)


app.add_middleware(RequestLoggingMiddleware)


if settings.rapidapi_proxy_secret:

    class _RapidAPIAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):  # type: ignore[override]
            if request.url.path == "/health":
                return await call_next(request)
            secret = request.headers.get("x-rapidapi-proxy-secret")
            if secret != settings.rapidapi_proxy_secret:
                logger.warning("rapidapi auth rejected", extra={"path": request.url.path})
                return JSONResponse(status_code=403, content={"detail": "Forbidden"})
            return await call_next(request)

    app.add_middleware(_RapidAPIAuthMiddleware)


@app.exception_handler(BlockedTargetError)
async def _blocked_target_handler(_request: Request, exc: BlockedTargetError) -> JSONResponse:
    logger.warning("blocked target", extra={"error": str(exc)})
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(InvalidTargetError)
async def _invalid_target_handler(_request: Request, exc: InvalidTargetError) -> JSONResponse:
    logger.warning("invalid target", extra={"error": str(exc)})
    return JSONResponse(status_code=422, content={"detail": str(exc)})


# Light scanners (fast, default)
register_scanner(CheckType.HEADERS, headers.scan)
register_scanner(CheckType.SSL, ssl_scanner.scan)
register_scanner(CheckType.DNS, dns_scanner.scan)
register_scanner(CheckType.TECH, tech.scan)
register_scanner(CheckType.BLACKLIST, blacklist.scan)
register_scanner(CheckType.WEB, web.scan)

# Deep scanners (slower, more thorough)
register_scanner(CheckType.SSL_DEEP, ssl_deep_scanner.scan)
register_scanner(CheckType.DNS_DEEP, dns_deep.scan)
register_scanner(CheckType.TECH_DEEP, tech_deep.scan)
register_scanner(CheckType.BLACKLIST_DEEP, blacklist.scan_deep)
register_scanner(CheckType.PORTS, ports.scan)
register_scanner(CheckType.PORTS_DEEP, ports.scan_deep)
register_scanner(CheckType.CVE, cve.scan)

# Register routes with /v1 prefix
app.include_router(scan_router, prefix="/v1")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
