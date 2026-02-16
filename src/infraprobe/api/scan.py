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


_DEEP_CHECKS = frozenset({"ssl_deep", "tech_deep", "dns_deep", "blacklist_deep", "ports_deep", "cve"})


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
    logger.info(
        "scan started",
        extra={
            "targets": targets,
            "checks": [str(c) for c in checks],
            "resolved_ips": {str(ctx): list(ctx.resolved_ips) for ctx in contexts},
        },
    )
    start = time.monotonic()
    target_results = await asyncio.gather(*[_scan_target(ctx, checks) for ctx in contexts])
    for tr in target_results:
        logger.info("target done", extra={"target": tr.target, "score": tr.score, "duration_ms": tr.duration_ms})
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info("scan done", extra={"targets_count": len(targets), "duration_ms": duration_ms})
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
    logger.info(
        "check started",
        extra={
            "target": target,
            "check": str(check_type),
            "resolved_ips": list(ctx.resolved_ips),
        },
    )
    start = time.monotonic()
    result = await _scan_target(ctx, [check_type])
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "check request done",
        extra={"target": target, "check": str(check_type), "score": result.score, "duration_ms": duration_ms},
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
        logger.error("async scan job failed", extra={"job_id": job_id, "error": str(exc)})
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
async def scan_async(request: ScanRequest, req: Request) -> JobCreate:
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
        return JSONResponse(status_code=404, content={"detail": "Job not found"})
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
        return JSONResponse(status_code=404, content={"detail": "Job not found"})
    if job.status != JobStatus.COMPLETED or job.result is None:
        return JSONResponse(status_code=409, content={"detail": f"Job is {job.status}", "job_id": job_id})
    return _format_scan_response(job.result, fmt)
