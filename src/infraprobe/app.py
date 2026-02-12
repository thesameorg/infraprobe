from fastapi import FastAPI

from infraprobe.api.scan import register_scanner
from infraprobe.api.scan import router as scan_router
from infraprobe.models import CheckType
from infraprobe.scanners import headers

app = FastAPI(title="InfraProbe", version="0.1.0")

# Register scanners
register_scanner(CheckType.HEADERS, headers.scan)

# Register routes
app.include_router(scan_router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
