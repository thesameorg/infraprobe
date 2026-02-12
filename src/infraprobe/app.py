from fastapi import FastAPI

from infraprobe.api.scan import register_scanner
from infraprobe.api.scan import router as scan_router
from infraprobe.models import CheckType
from infraprobe.scanners import blacklist, dns_deep, headers, tech, tech_deep
from infraprobe.scanners import dns as dns_scanner
from infraprobe.scanners import ssl as ssl_scanner
from infraprobe.scanners import ssl_deep as ssl_deep_scanner

app = FastAPI(title="InfraProbe", version="0.2.0")

# Light scanners (fast, default)
register_scanner(CheckType.HEADERS, headers.scan)
register_scanner(CheckType.SSL, ssl_scanner.scan)
register_scanner(CheckType.DNS, dns_scanner.scan)
register_scanner(CheckType.TECH, tech.scan)
register_scanner(CheckType.BLACKLIST, blacklist.scan)

# Deep scanners (slower, more thorough)
register_scanner(CheckType.SSL_DEEP, ssl_deep_scanner.scan)
register_scanner(CheckType.DNS_DEEP, dns_deep.scan)
register_scanner(CheckType.TECH_DEEP, tech_deep.scan)

# Register routes with /v1 prefix
app.include_router(scan_router, prefix="/v1")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
