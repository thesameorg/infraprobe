import asyncio
import json
import logging
import time
import uuid
from collections.abc import Callable, Coroutine
from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response

from infraprobe.blocklist import BlockedTargetError, InvalidTargetError, validate_domain, validate_ip, validate_target
from infraprobe.config import settings
from infraprobe.formatters.csv import scan_response_to_csv, target_result_to_csv
from infraprobe.formatters.sarif import scan_response_to_sarif, target_result_to_sarif
from infraprobe.metrics import ACTIVE_SCANS, SCANNER_DURATION
from infraprobe.models import (
    DNS_ONLY_CHECKS,
    CheckResult,
    CheckType,
    DomainScanRequest,
    IpScanRequest,
    Job,
    JobCreate,
    JobStatus,
    OutputFormat,
    ScanRequest,
    ScanResponse,
    SingleCheckRequest,
    TargetResult,
)
from infraprobe.storage.base import JobStore
from infraprobe.target import ScanContext
from infraprobe.webhook import _validate_webhook_url, maybe_deliver_webhook

router = APIRouter()
logger = logging.getLogger("infraprobe.scanner")

FormatParam = Annotated[OutputFormat, Query(alias="format")]

# Scanner registry: maps check type → scan function
# Each scanner is async def scan(target, timeout) -> CheckResult
type ScanFn = Callable[[str, float], Coroutine[None, None, CheckResult]]

_SCANNERS: dict[CheckType, ScanFn] = {}


def register_scanner(check_type: CheckType, fn: ScanFn) -> None:
    _SCANNERS[check_type] = fn


# Small buffer for asyncio scheduling overhead; scanners should respect their
# own timeout budget internally — this only covers task-switch latency.
_SCHEDULING_BUFFER = 0.5


async def _run_scanner(check_type: CheckType, target: str, timeout: float) -> CheckResult:
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
    try:
        result = await asyncio.wait_for(fn(target, timeout), timeout=timeout + _SCHEDULING_BUFFER)
        duration_s = time.monotonic() - start
        duration_ms = int(duration_s * 1000)
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
        return CheckResult(check=check_type, error=f"Scanner {check_type} timed out after {timeout}s")
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


_DEEP_CHECKS = frozenset({"ssl_deep", "tech_deep", "dns_deep", "blacklist_deep", "ports_deep", "cve"})


async def _scan_target(ctx: ScanContext, checks: list[CheckType]) -> TargetResult:
    ACTIVE_SCANS.inc()
    start = time.monotonic()
    target_str = str(ctx)

    try:
        tasks = [
            _run_scanner(
                ct,
                target_str,
                settings.deep_scanner_timeout if ct in _DEEP_CHECKS else settings.scanner_timeout,
            )
            for ct in checks
        ]
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


def _format_target_result(result: TargetResult, fmt: OutputFormat) -> TargetResult | Response:
    if fmt == OutputFormat.SARIF:
        return Response(content=json.dumps(target_result_to_sarif(result)), media_type=_SARIF_MEDIA_TYPE)
    if fmt == OutputFormat.CSV:
        return Response(content=target_result_to_csv(result), media_type=_CSV_MEDIA_TYPE)
    return result


# ---------------------------------------------------------------------------
# Existing endpoints (backward-compatible)
# ---------------------------------------------------------------------------


async def _run_scan_with_validator(
    targets: list[str],
    checks: list[CheckType],
    validator: Callable[[str], ScanContext],
) -> ScanResponse:
    """Shared orchestration for all scan endpoints (generic, domain, IP)."""
    contexts = [validator(raw) for raw in targets]
    check_names = [str(c) for c in checks]
    logger.info(
        "scan started: %d target(s) × %d checks [%s]",
        len(targets),
        len(checks),
        ", ".join(check_names),
        extra={
            "targets": targets,
            "checks": check_names,
            "resolved_ips": {str(ctx): list(ctx.resolved_ips) for ctx in contexts},
        },
    )
    start = time.monotonic()
    target_results = await asyncio.gather(*[_scan_target(ctx, checks) for ctx in contexts])
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
        len(targets),
        duration_ms,
        extra={"targets_count": len(targets), "duration_ms": duration_ms},
    )
    return ScanResponse(results=list(target_results))


async def _run_full_scan(request: ScanRequest) -> ScanResponse:
    return await _run_scan_with_validator(request.targets, request.checks, validate_target)


@router.post("/scan")
async def scan(
    request: ScanRequest,
    fmt: FormatParam = OutputFormat.JSON,
) -> ScanResponse:
    result = await _run_full_scan(request)
    return _format_scan_response(result, fmt)


async def _run_single_check(
    check_type: CheckType,
    target: str,
    validator: Callable[[str], ScanContext],
) -> TargetResult:
    """Shared orchestration for all single-check endpoints (generic, domain, IP)."""
    ctx = validator(target)
    timeout = settings.deep_scanner_timeout if check_type in _DEEP_CHECKS else settings.scanner_timeout
    logger.info(
        "check request: %s on %s (timeout=%.1fs, ips=%s)",
        check_type,
        target,
        timeout,
        list(ctx.resolved_ips),
        extra={
            "target": target,
            "check": str(check_type),
            "scanner_timeout": timeout,
            "resolved_ips": list(ctx.resolved_ips),
        },
    )
    start = time.monotonic()
    result = await _scan_target(ctx, [check_type])
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "check request done: %s on %s in %dms",
        check_type,
        target,
        duration_ms,
        extra={
            "target": target,
            "check": str(check_type),
            "duration_ms": duration_ms,
        },
    )
    return result


async def _single_check(check_type: CheckType, request: SingleCheckRequest) -> TargetResult:
    return await _run_single_check(check_type, request.target, validate_target)


def _make_check_handler(ct: CheckType):
    async def handler(
        request: SingleCheckRequest,
        fmt: FormatParam = OutputFormat.JSON,
    ) -> TargetResult:
        result = await _single_check(ct, request)
        return _format_target_result(result, fmt)

    handler.__name__ = f"check_{ct.value}"
    return handler


# Register a dedicated route per check type so each appears as its own endpoint in OpenAPI.
# Deep checks live under /check_deep/{name} (e.g. /check_deep/ssl), light checks under /check/{name}.
for _ct in CheckType:
    _handler = _make_check_handler(_ct)
    if _ct.value.endswith("_deep"):
        _slug = _ct.value.removesuffix("_deep")
        router.add_api_route(f"/check_deep/{_slug}", _handler, methods=["POST"], response_model=TargetResult)
    else:
        router.add_api_route(f"/check/{_ct.value}", _handler, methods=["POST"], response_model=TargetResult)


# ---------------------------------------------------------------------------
# Domain-specific endpoints
# ---------------------------------------------------------------------------


@router.post("/scan_domain")
async def scan_domain(
    request: DomainScanRequest,
    fmt: FormatParam = OutputFormat.JSON,
) -> ScanResponse:
    result = await _run_scan_with_validator(request.targets, request.checks, validate_domain)
    return _format_scan_response(result, fmt)


@router.post("/check_domain/{check_type}")
async def check_domain(
    check_type: CheckType,
    request: SingleCheckRequest,
    fmt: FormatParam = OutputFormat.JSON,
) -> TargetResult:
    result = await _run_single_check(check_type, request.target, validate_domain)
    return _format_target_result(result, fmt)


# ---------------------------------------------------------------------------
# IP-specific endpoints
# ---------------------------------------------------------------------------


@router.post("/scan_ip")
async def scan_ip(
    request: IpScanRequest,
    fmt: FormatParam = OutputFormat.JSON,
) -> ScanResponse:
    invalid = set(request.checks) & DNS_ONLY_CHECKS
    if invalid:
        raise InvalidTargetError(f"DNS checks not applicable to IP targets: {', '.join(sorted(invalid))}")
    result = await _run_scan_with_validator(request.targets, request.checks, validate_ip)
    return _format_scan_response(result, fmt)


@router.post("/check_ip/{check_type}")
async def check_ip(
    check_type: CheckType,
    request: SingleCheckRequest,
    fmt: FormatParam = OutputFormat.JSON,
) -> TargetResult:
    if check_type in DNS_ONLY_CHECKS:
        raise InvalidTargetError(f"Check type {check_type} not applicable to IP targets")
    result = await _run_single_check(check_type, request.target, validate_ip)
    return _format_target_result(result, fmt)


# ---------------------------------------------------------------------------
# Async / polling endpoints
# ---------------------------------------------------------------------------

# Prevent GC of fire-and-forget tasks
_background_tasks: set[asyncio.Task] = set()
_shutting_down = False


def reset_shutdown_flag() -> None:
    """Reset the shutdown flag (called at lifespan startup)."""
    global _shutting_down  # noqa: PLW0603
    _shutting_down = False


async def drain_background_tasks(timeout: float = 25) -> None:
    """Wait for in-flight background scan tasks to finish (graceful shutdown)."""
    global _shutting_down  # noqa: PLW0603
    _shutting_down = True
    if not _background_tasks:
        return
    logger.info("draining %d background tasks (timeout=%.0fs)", len(_background_tasks), timeout)
    done, pending = await asyncio.wait(_background_tasks, timeout=timeout)
    if pending:
        logger.warning("cancelling %d background tasks after drain timeout", len(pending))
        for task in pending:
            task.cancel()


async def _run_scan_job(
    store: JobStore,
    job_id: str,
    request: ScanRequest,
    webhook_url: str | None = None,
    webhook_secret: str | None = None,
) -> None:
    try:
        await store.update_status(job_id, JobStatus.RUNNING)
        result = await _run_full_scan(request)
        await store.complete(job_id, result)
    except Exception as exc:
        logger.error(
            "async scan job %s failed: %s: %s",
            job_id,
            type(exc).__name__,
            exc,
            exc_info=True,
            extra={"job_id": job_id, "error": str(exc), "error_type": type(exc).__name__},
        )
        await store.fail(job_id, str(exc))

    if webhook_url:
        job = await store.get(job_id)
        if job:
            await maybe_deliver_webhook(
                job,
                webhook_url,
                webhook_secret,
                store=store,
                timeout=settings.webhook_timeout,
                max_retries=settings.webhook_max_retries,
            )


@router.post("/scan/async", status_code=202, response_model=JobCreate)
async def scan_async(request: ScanRequest, req: Request) -> JobCreate | JSONResponse:
    if _shutting_down:
        return JSONResponse(status_code=503, content={"error": "shutting_down", "detail": "Server is shutting down"})

    # Validate targets eagerly so 400/422 errors are returned synchronously
    for raw in request.targets:
        validate_target(raw)

    # Validate webhook URL (SSRF protection)
    webhook_url = request.webhook_url
    webhook_secret = request.webhook_secret
    if webhook_url:
        try:
            _validate_webhook_url(webhook_url)
        except BlockedTargetError as exc:
            raise InvalidTargetError(str(exc)) from exc
        except ValueError as exc:
            raise InvalidTargetError(str(exc)) from exc

    store: JobStore = req.app.state.job_store
    job_id = uuid.uuid4().hex
    job = await store.create(job_id, request)

    task = asyncio.create_task(_run_scan_job(store, job_id, request, webhook_url, webhook_secret))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    return JobCreate(job_id=job.job_id, status=job.status, created_at=job.created_at)


@router.get("/scan/{job_id}", response_model=Job)
async def get_scan_job(job_id: str, req: Request) -> Job | JSONResponse:
    store: JobStore = req.app.state.job_store
    job = await store.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"error": "not_found", "detail": "Job not found"})
    return job


@router.get("/scan/{job_id}/report", response_model=None)
async def get_scan_report(
    job_id: str,
    req: Request,
    fmt: FormatParam = OutputFormat.JSON,
):
    store: JobStore = req.app.state.job_store
    job = await store.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"error": "not_found", "detail": "Job not found"})
    if job.status != JobStatus.COMPLETED or job.result is None:
        return JSONResponse(
            status_code=409, content={"error": "job_not_ready", "detail": f"Job is {job.status}", "job_id": job_id}
        )
    return _format_scan_response(job.result, fmt)
