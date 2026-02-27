import asyncio
import json
import logging
import time
from collections.abc import Callable, Coroutine
from fastapi import APIRouter
from fastapi.responses import Response

from infraprobe.blocklist import validate_target
from infraprobe.config import scan_semaphore, settings
from infraprobe.formatters.csv import scan_response_to_csv
from infraprobe.formatters.sarif import scan_response_to_sarif
from infraprobe.metrics import ACTIVE_SCANS, SCANNER_DURATION
from infraprobe.models import (
    DOMAIN_CHECKS,
    IP_CHECKS,
    AuthConfig,
    CheckResult,
    CheckType,
    OutputFormat,
    ScanResponse,
    SingleCheckRequest,
    TargetResult,
)
from infraprobe.target import ScanContext, parse_target

router = APIRouter()
logger = logging.getLogger("infraprobe.scanner")


# ---------------------------------------------------------------------------
# Scanner registry
# ---------------------------------------------------------------------------

type ScanFn = Callable[[str, float, AuthConfig | None], Coroutine[None, None, CheckResult]]

_SCANNERS: dict[CheckType, ScanFn] = {}


def register_scanner(check_type: CheckType, fn: ScanFn) -> None:
    _SCANNERS[check_type] = fn


# Small buffer for asyncio scheduling overhead
_SCHEDULING_BUFFER = 0.5


async def _run_scanner(
    check_type: CheckType, target: str, timeout: float, auth: AuthConfig | None = None
) -> CheckResult:
    fn = _SCANNERS.get(check_type)
    if fn is None:
        return CheckResult(check=check_type, error=f"Scanner {check_type} not registered")

    start = time.monotonic()
    logger.info(
        "%s started on %s (timeout=%.1fs)",
        check_type,
        target,
        timeout,
        extra={"check": check_type, "target": target, "scanner_timeout": timeout},
    )
    timeout_ms = int(timeout * 1000)
    try:
        result = await asyncio.wait_for(fn(target, timeout, auth), timeout=timeout + _SCHEDULING_BUFFER)
        duration_s = time.monotonic() - start
        duration_ms = int(duration_s * 1000)
        result.duration_ms = duration_ms
        result.timeout_ms = timeout_ms
        SCANNER_DURATION.labels(check=check_type).observe(duration_s)
        logger.info(
            "%s finished on %s in %dms — %d findings%s",
            check_type,
            target,
            duration_ms,
            len(result.findings),
            f", error: {result.error}" if result.error else "",
            extra={
                "check": check_type,
                "target": target,
                "duration_ms": duration_ms,
                "scanner_timeout": timeout,
                "findings_count": len(result.findings),
                "error": result.error,
            },
        )
        return result
    except TimeoutError:
        duration_s = time.monotonic() - start
        duration_ms = int(duration_s * 1000)
        SCANNER_DURATION.labels(check=check_type).observe(duration_s)
        logger.warning(
            "%s TIMEOUT on %s after %dms (budget was %.1fs)",
            check_type,
            target,
            duration_ms,
            timeout,
            extra={"check": check_type, "target": target, "duration_ms": duration_ms, "scanner_timeout": timeout},
        )
        return CheckResult(
            check=check_type,
            error=f"Scanner {check_type} timed out after {timeout}s",
            duration_ms=duration_ms,
            timeout_ms=timeout_ms,
        )
    except Exception as exc:
        duration_s = time.monotonic() - start
        duration_ms = int(duration_s * 1000)
        SCANNER_DURATION.labels(check=check_type).observe(duration_s)
        logger.error(
            "%s ERROR on %s after %dms (budget was %.1fs): %s: %s",
            check_type,
            target,
            duration_ms,
            timeout,
            type(exc).__name__,
            exc,
            exc_info=True,
            extra={
                "check": check_type,
                "target": target,
                "duration_ms": duration_ms,
                "scanner_timeout": timeout,
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
        )
        return CheckResult(check=check_type, error=f"Scanner {check_type} failed: {exc}")


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


async def _scan_target(ctx: ScanContext, checks: list[CheckType], auth: AuthConfig | None = None) -> TargetResult:
    async with scan_semaphore():
        ACTIVE_SCANS.inc()
        start = time.monotonic()
        target_str = str(ctx)

        try:
            tasks = [_run_scanner(ct, target_str, settings.scanner_timeout, auth) for ct in checks]
            results: list[CheckResult] = await asyncio.gather(*tasks)

            results_map: dict[str, CheckResult] = {}
            for r in results:
                results_map[r.check] = r

            duration_ms = int((time.monotonic() - start) * 1000)

            return TargetResult(
                target=target_str,
                results=results_map,
                duration_ms=duration_ms,
            )
        finally:
            ACTIVE_SCANS.dec()


_SARIF_MEDIA_TYPE = "application/sarif+json"
_CSV_MEDIA_TYPE = "text/csv"


def _format_scan_response(result: ScanResponse, fmt: OutputFormat) -> ScanResponse | Response:
    if fmt == OutputFormat.SARIF:
        return Response(content=json.dumps(scan_response_to_sarif(result)), media_type=_SARIF_MEDIA_TYPE)
    if fmt == OutputFormat.CSV:
        return Response(content=scan_response_to_csv(result), media_type=_CSV_MEDIA_TYPE)
    return result


async def _run_scan_with_contexts(
    contexts: list[ScanContext],
    checks: list[CheckType],
    auth: AuthConfig | None = None,
) -> ScanResponse:
    """Orchestrate scan given already-validated ScanContext objects (no re-resolution)."""
    check_names = [str(c) for c in checks]
    logger.info(
        "scan started: %d target(s) × %d checks [%s]",
        len(contexts),
        len(checks),
        ", ".join(check_names),
        extra={
            "targets": [str(ctx) for ctx in contexts],
            "checks": check_names,
            "resolved_ips": {str(ctx): list(ctx.resolved_ips) for ctx in contexts},
        },
    )
    start = time.monotonic()
    target_results = await asyncio.gather(*[_scan_target(ctx, checks, auth) for ctx in contexts])
    for tr in target_results:
        logger.info(
            "target done: %s in %dms",
            tr.target,
            tr.duration_ms,
            extra={"target": tr.target, "duration_ms": tr.duration_ms},
        )
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "scan done: %d target(s) in %dms",
        len(contexts),
        duration_ms,
        extra={"targets_count": len(contexts), "duration_ms": duration_ms},
    )
    return ScanResponse(results=list(target_results))


# ---------------------------------------------------------------------------
# POST /v1/scan — always sync (200), fixed check bundle
# ---------------------------------------------------------------------------


@router.post(
    "/scan",
    response_model=None,
    tags=["Scan"],
    summary="Run security scan",
    description=(
        "Run a security scan against a single target. "
        "Returns **200** with inline results. "
        "Domains get headers/ssl/dns/web/whois; IPs get headers/ssl/web. "
        "Set `format` in the request body to `sarif` or `csv` for alternative output formats."
    ),
)
async def scan(request: SingleCheckRequest) -> ScanResponse | Response:
    # Resolve fixed checks based on target type
    is_ip = parse_target(request.target).is_ip
    checks = list(IP_CHECKS) if is_ip else list(DOMAIN_CHECKS)

    # Validate target + run checks
    ctx = await validate_target(request.target)
    result = await _run_scan_with_contexts([ctx], checks, request.auth)

    return _format_scan_response(result, request.format)
