from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from infraprobe.api.scan import register_scanner
from infraprobe.api.scan import router as scan_router
from infraprobe.blocklist import BlockedTargetError, InvalidTargetError
from infraprobe.config import settings
from infraprobe.models import CheckType
from infraprobe.scanners import blacklist, tech, web
from infraprobe.scanners import dns as dns_scanner
from infraprobe.scanners import headers_drheader as headers
from infraprobe.scanners import ssl as ssl_scanner
from infraprobe.scanners.deep import dns as dns_deep
from infraprobe.scanners.deep import ssl as ssl_deep_scanner
from infraprobe.scanners.deep import tech as tech_deep

app = FastAPI(title="InfraProbe", version="0.2.0")


if settings.rapidapi_proxy_secret:

    class _RapidAPIAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):  # type: ignore[override]
            if request.url.path == "/health":
                return await call_next(request)
            secret = request.headers.get("x-rapidapi-proxy-secret")
            if secret != settings.rapidapi_proxy_secret:
                return JSONResponse(status_code=403, content={"detail": "Forbidden"})
            return await call_next(request)

    app.add_middleware(_RapidAPIAuthMiddleware)


@app.exception_handler(BlockedTargetError)
async def _blocked_target_handler(_request: Request, exc: BlockedTargetError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(InvalidTargetError)
async def _invalid_target_handler(_request: Request, exc: InvalidTargetError) -> JSONResponse:
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

# Register routes with /v1 prefix
app.include_router(scan_router, prefix="/v1")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
