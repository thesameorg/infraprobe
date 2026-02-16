import asyncio
import json
import logging
import time
import uuid
from collections.abc import Callable, Coroutine
from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response

from infraprobe.blocklist import InvalidTargetError, validate_domain, validate_ip, validate_target
from infraprobe.config import settings
from infraprobe.formatters.sarif import scan_response_to_sarif, target_result_to_sarif
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
from infraprobe.scoring import calculate_score
from infraprobe.storage.base import JobStore
from infraprobe.target import ScanContext

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
    try:
        result = await asyncio.wait_for(fn(target, timeout), timeout=timeout + _SCHEDULING_BUFFER)
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "check done",
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
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.warning(
            "check timeout",
            extra={"check": check_type, "target": target, "duration_ms": duration_ms, "scanner_timeout": timeout},
        )
        return CheckResult(check=check_type, error=f"Scanner {check_type} timed out after {timeout}s")
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.error(
            "check error",
            extra={
                "check": check_type,
                "target": target,
                "duration_ms": duration_ms,
                "scanner_timeout": timeout,
                "error": str(exc),
            },
        )
        return CheckResult(check=check_type, error=f"Scanner {check_type} failed: {exc}")


_DEEP_CHECKS = frozenset({"ssl_deep", "tech_deep", "dns_deep", "blacklist_deep"})


async def _scan_target(ctx: ScanContext, checks: list[CheckType]) -> TargetResult:
    start = time.monotonic()
    target_str = str(ctx)

    tasks = [
        _run_scanner(
            ct,
            target_str,
            settings.deep_scanner_timeout if ct in _DEEP_CHECKS else settings.scanner_timeout,
        )
        for ct in checks
    ]
    results: list[CheckResult] = await asyncio.gather(*tasks)

    all_findings = []
    results_map: dict[str, CheckResult] = {}
    for r in results:
        results_map[r.check] = r
        all_findings.extend(r.findings)

    score, summary = calculate_score(all_findings)
    duration_ms = int((time.monotonic() - start) * 1000)

    return TargetResult(
        target=target_str,
        score=score,
        summary=summary,
        results=results_map,
        duration_ms=duration_ms,
    )


_SARIF_MEDIA_TYPE = "application/sarif+json"


def _format_scan_response(result: ScanResponse, fmt: OutputFormat) -> ScanResponse | Response:
    if fmt == OutputFormat.SARIF:
        return Response(content=json.dumps(scan_response_to_sarif(result)), media_type=_SARIF_MEDIA_TYPE)
    return result


def _format_target_result(result: TargetResult, fmt: OutputFormat) -> TargetResult | Response:
    if fmt == OutputFormat.SARIF:
        return Response(content=json.dumps(target_result_to_sarif(result)), media_type=_SARIF_MEDIA_TYPE)
    return result


# ---------------------------------------------------------------------------
# Existing endpoints (backward-compatible)
# ---------------------------------------------------------------------------


async def _run_full_scan(request: ScanRequest) -> ScanResponse:
    contexts = [validate_target(raw) for raw in request.targets]
    logger.info(
        "scan started",
        extra={
            "targets": request.targets,
            "checks": [str(c) for c in request.checks],
            "resolved_ips": {str(ctx): list(ctx.resolved_ips) for ctx in contexts},
        },
    )
    start = time.monotonic()
    target_results = await asyncio.gather(*[_scan_target(ctx, request.checks) for ctx in contexts])
    for tr in target_results:
        logger.info("target done", extra={"target": tr.target, "score": tr.score, "duration_ms": tr.duration_ms})
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info("scan done", extra={"targets_count": len(request.targets), "duration_ms": duration_ms})
    return ScanResponse(results=list(target_results))


@router.post("/scan")
async def scan(
    request: ScanRequest,
    fmt: FormatParam = OutputFormat.JSON,
) -> ScanResponse:
    result = await _run_full_scan(request)
    return _format_scan_response(result, fmt)


async def _single_check(check_type: CheckType, request: SingleCheckRequest) -> TargetResult:
    ctx = validate_target(request.target)
    logger.info(
        "check started",
        extra={
            "target": request.target,
            "check": str(check_type),
            "resolved_ips": list(ctx.resolved_ips),
        },
    )
    start = time.monotonic()
    result = await _scan_target(ctx, [check_type])
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "check request done",
        extra={"target": request.target, "check": str(check_type), "score": result.score, "duration_ms": duration_ms},
    )
    return result


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
    if _ct in _DEEP_CHECKS:
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
    contexts = [validate_domain(raw) for raw in request.targets]
    logger.info(
        "scan started",
        extra={
            "targets": request.targets,
            "checks": [str(c) for c in request.checks],
            "resolved_ips": {str(ctx): list(ctx.resolved_ips) for ctx in contexts},
        },
    )
    start = time.monotonic()
    target_results = await asyncio.gather(*[_scan_target(ctx, request.checks) for ctx in contexts])
    for tr in target_results:
        logger.info("target done", extra={"target": tr.target, "score": tr.score, "duration_ms": tr.duration_ms})
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info("scan done", extra={"targets_count": len(request.targets), "duration_ms": duration_ms})
    return _format_scan_response(ScanResponse(results=list(target_results)), fmt)


@router.post("/check_domain/{check_type}")
async def check_domain(
    check_type: CheckType,
    request: SingleCheckRequest,
    fmt: FormatParam = OutputFormat.JSON,
) -> TargetResult:
    ctx = validate_domain(request.target)
    logger.info(
        "check started",
        extra={"target": request.target, "check": str(check_type), "resolved_ips": list(ctx.resolved_ips)},
    )
    start = time.monotonic()
    result = await _scan_target(ctx, [check_type])
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "check request done",
        extra={"target": request.target, "check": str(check_type), "score": result.score, "duration_ms": duration_ms},
    )
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
    contexts = [validate_ip(raw) for raw in request.targets]
    logger.info(
        "scan started",
        extra={
            "targets": request.targets,
            "checks": [str(c) for c in request.checks],
            "resolved_ips": {str(ctx): list(ctx.resolved_ips) for ctx in contexts},
        },
    )
    start = time.monotonic()
    target_results = await asyncio.gather(*[_scan_target(ctx, request.checks) for ctx in contexts])
    for tr in target_results:
        logger.info("target done", extra={"target": tr.target, "score": tr.score, "duration_ms": tr.duration_ms})
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info("scan done", extra={"targets_count": len(request.targets), "duration_ms": duration_ms})
    return _format_scan_response(ScanResponse(results=list(target_results)), fmt)


@router.post("/check_ip/{check_type}")
async def check_ip(
    check_type: CheckType,
    request: SingleCheckRequest,
    fmt: FormatParam = OutputFormat.JSON,
) -> TargetResult:
    if check_type in DNS_ONLY_CHECKS:
        raise InvalidTargetError(f"Check type {check_type} not applicable to IP targets")
    ctx = validate_ip(request.target)
    logger.info(
        "check started",
        extra={"target": request.target, "check": str(check_type), "resolved_ips": list(ctx.resolved_ips)},
    )
    start = time.monotonic()
    result = await _scan_target(ctx, [check_type])
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "check request done",
        extra={"target": request.target, "check": str(check_type), "score": result.score, "duration_ms": duration_ms},
    )
    return _format_target_result(result, fmt)


# ---------------------------------------------------------------------------
# Async / polling endpoints
# ---------------------------------------------------------------------------

# Prevent GC of fire-and-forget tasks
_background_tasks: set[asyncio.Task] = set()


async def _run_scan_job(store: JobStore, job_id: str, request: ScanRequest) -> None:
    try:
        await store.update_status(job_id, JobStatus.RUNNING)
        result = await _run_full_scan(request)
        await store.complete(job_id, result)
    except Exception as exc:
        logger.error("async scan job failed", extra={"job_id": job_id, "error": str(exc)})
        await store.fail(job_id, str(exc))


@router.post("/scan/async", status_code=202, response_model=JobCreate)
async def scan_async(request: ScanRequest, req: Request) -> JobCreate:
    # Validate targets eagerly so 400/422 errors are returned synchronously
    for raw in request.targets:
        validate_target(raw)

    store: JobStore = req.app.state.job_store
    job_id = uuid.uuid4().hex
    job = await store.create(job_id, request)

    task = asyncio.create_task(_run_scan_job(store, job_id, request))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    return JobCreate(job_id=job.job_id, status=job.status, created_at=job.created_at)


@router.get("/scan/{job_id}", response_model=Job)
async def get_scan_job(job_id: str, req: Request) -> Job | JSONResponse:
    store: JobStore = req.app.state.job_store
    job = await store.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"detail": "Job not found"})
    return job
