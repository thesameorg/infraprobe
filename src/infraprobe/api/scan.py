import asyncio
import json
import logging
import time
import uuid
from collections.abc import Callable, Coroutine
from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response

from infraprobe.blocklist import (
    BlockedTargetError,
    InvalidTargetError,
    validate_target,
)
from infraprobe.config import scan_semaphore, settings
from infraprobe.formatters.csv import scan_response_to_csv, target_result_to_csv
from infraprobe.formatters.sarif import scan_response_to_sarif, target_result_to_sarif
from infraprobe.metrics import ACTIVE_SCANS, SCANNER_DURATION
from infraprobe.models import (
    DNS_ONLY_CHECKS,
    DOMAIN_CHECKS,
    IP_CHECKS,
    AuthConfig,
    CheckResult,
    CheckType,
    Job,
    JobCreate,
    JobStatus,
    OutputFormat,
    ScanRequest,
    ScanResponse,
    Severity,
    SingleCheckRequest,
    TargetResult,
)
from infraprobe.storage.base import JobStore
from infraprobe.target import ScanContext, parse_target
from infraprobe.webhook import _validate_webhook_url, maybe_deliver_webhook

router = APIRouter()
logger = logging.getLogger("infraprobe.scanner")

FormatParam = Annotated[OutputFormat, Query(alias="format")]
FailOnParam = Annotated[str | None, Query(alias="fail_on")]

# Severity ordering for fail_on threshold comparison
_SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _check_fail_on(result: ScanResponse | TargetResult, fail_on: str | None) -> JSONResponse | None:
    """If fail_on is set and findings at or above threshold exist, return 422 response."""
    if not fail_on:
        return None

    thresholds = {s.strip().lower() for s in fail_on.split(",")}
    valid_severities = set(_SEVERITY_RANK.keys())
    invalid = thresholds - valid_severities
    if invalid:
        return JSONResponse(
            status_code=422,
            content={"error": "invalid_parameter", "detail": f"Invalid fail_on severity: {', '.join(sorted(invalid))}"},
        )

    max_rank = max(_SEVERITY_RANK[s] for s in thresholds)

    # Collect all findings
    if isinstance(result, ScanResponse):
        all_findings = [f for tr in result.results for cr in tr.results.values() for f in cr.findings]
    else:
        all_findings = [f for cr in result.results.values() for f in cr.findings]

    exceeding = [f for f in all_findings if _SEVERITY_RANK.get(f.severity, 5) <= max_rank]
    if exceeding:
        return JSONResponse(
            status_code=422,
            content={
                "error": "threshold_exceeded",
                "detail": f"Found {len(exceeding)} finding(s) at or above threshold",
                "result": result.model_dump(mode="json"),
            },
        )


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
    try:
        result = await asyncio.wait_for(fn(target, timeout, auth), timeout=timeout + _SCHEDULING_BUFFER)
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


_DEEP_CHECKS = frozenset({"ssl_deep", "dns_deep", "blacklist_deep", "ports_deep", "cve"})

# Slow checks return 202 from /check/{type} (nmap-based, long-running)
_SLOW_CHECKS = frozenset({CheckType.PORTS, CheckType.PORTS_DEEP, CheckType.CVE})


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


async def _scan_target(ctx: ScanContext, checks: list[CheckType], auth: AuthConfig | None = None) -> TargetResult:
    async with scan_semaphore():
        ACTIVE_SCANS.inc()
        start = time.monotonic()
        target_str = str(ctx)

        try:
            tasks = [
                _run_scanner(
                    ct,
                    target_str,
                    settings.deep_scanner_timeout if ct in _DEEP_CHECKS else settings.scanner_timeout,
                    auth,
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


def _resolve_checks(targets: list[str], checks: list[CheckType] | None) -> list[CheckType]:
    """Resolve checks list: auto-detect from target types if None, validate if explicit."""
    if checks is not None:
        # Validate: reject DNS-only checks on IP targets
        ip_targets = [t for t in targets if parse_target(t).is_ip]
        if ip_targets:
            dns_only = set(checks) & DNS_ONLY_CHECKS
            if dns_only:
                raise InvalidTargetError(
                    f"DNS checks ({', '.join(sorted(str(c) for c in dns_only))}) "
                    f"not applicable to IP targets: {', '.join(ip_targets)}"
                )
        return checks

    # Auto-detect based on target types
    has_ip = any(parse_target(t).is_ip for t in targets)
    if has_ip:
        return list(IP_CHECKS)
    return list(DOMAIN_CHECKS)


async def _run_scan_with_validator(
    targets: list[str],
    checks: list[CheckType],
    auth: AuthConfig | None = None,
) -> ScanResponse:
    """Shared orchestration: validate targets, run checks in parallel."""
    contexts = [validate_target(raw) for raw in targets]
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
        len(targets),
        duration_ms,
        extra={"targets_count": len(targets), "duration_ms": duration_ms},
    )
    return ScanResponse(results=list(target_results))


async def _run_full_scan(request: ScanRequest) -> ScanResponse:
    return await _run_scan_with_validator(request.targets, request.checks, request.auth)


# ---------------------------------------------------------------------------
# Background task management
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# POST /v1/scan — always async (202)
# ---------------------------------------------------------------------------


@router.post("/scan", status_code=202, response_model=JobCreate, tags=["Scans"])
async def scan(request: ScanRequest, req: Request) -> JobCreate | JSONResponse:
    if _shutting_down:
        return JSONResponse(status_code=503, content={"error": "shutting_down", "detail": "Server is shutting down"})

    # Validate targets eagerly so 400/422 errors are returned synchronously
    for raw in request.targets:
        validate_target(raw)

    # Resolve checks (auto-detect if None)
    resolved_checks = _resolve_checks(request.targets, request.checks)
    request = request.model_copy(update={"checks": resolved_checks})

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


# ---------------------------------------------------------------------------
# GET /v1/scan/{job_id} — poll + results in one (replaces /scan/{job_id}/report)
# ---------------------------------------------------------------------------


@router.get("/scan/{job_id}", response_model=None, tags=["Scans"])
async def get_scan_job(
    job_id: str,
    req: Request,
    fmt: FormatParam = OutputFormat.JSON,
    fail_on: FailOnParam = None,
) -> Job | JSONResponse | Response:
    store: JobStore = req.app.state.job_store
    job = await store.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"error": "not_found", "detail": "Job not found"})

    # Apply fail_on and format to completed results
    if job.status == JobStatus.COMPLETED and job.result is not None:
        fail_response = _check_fail_on(job.result, fail_on)
        if fail_response:
            return fail_response
        if fmt != OutputFormat.JSON:
            return _format_scan_response(job.result, fmt)

    return job


# ---------------------------------------------------------------------------
# POST /v1/check/{type} — fast checks inline (200), slow checks async (202)
# ---------------------------------------------------------------------------


async def _run_single_check(
    check_type: CheckType,
    target: str,
    auth: AuthConfig | None = None,
) -> TargetResult:
    """Run a single check against a target (inline)."""
    ctx = validate_target(target)
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
    result = await _scan_target(ctx, [check_type], auth)
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


def _make_check_handler(ct: CheckType):
    """Create an inline check handler (200) for fast checks."""

    async def handler(
        request: SingleCheckRequest,
        fmt: FormatParam = OutputFormat.JSON,
        fail_on: FailOnParam = None,
    ) -> TargetResult | JSONResponse | Response:
        # Reject DNS-only checks on IP targets
        if ct in DNS_ONLY_CHECKS and parse_target(request.target).is_ip:
            raise InvalidTargetError(f"Check type {ct} not applicable to IP targets")

        result = await _run_single_check(ct, request.target, request.auth)

        fail_response = _check_fail_on(result, fail_on)
        if fail_response:
            return fail_response

        return _format_target_result(result, fmt)

    handler.__name__ = f"check_{ct.value}"
    return handler


def _make_slow_check_handler(ct: CheckType):
    """Create an async check handler (202) for slow (nmap-based) checks."""

    async def handler(request: SingleCheckRequest, req: Request) -> JSONResponse:
        if _shutting_down:
            return JSONResponse(
                status_code=503, content={"error": "shutting_down", "detail": "Server is shutting down"}
            )

        # Validate target eagerly
        validate_target(request.target)

        # Reject DNS-only checks on IP targets
        if ct in DNS_ONLY_CHECKS and parse_target(request.target).is_ip:
            raise InvalidTargetError(f"Check type {ct} not applicable to IP targets")

        # Create a ScanRequest wrapping the single check
        scan_req = ScanRequest(targets=[request.target], checks=[ct], auth=request.auth)

        store: JobStore = req.app.state.job_store
        job_id = uuid.uuid4().hex
        job = await store.create(job_id, scan_req)

        task = asyncio.create_task(_run_scan_job(store, job_id, scan_req))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)

        return JSONResponse(
            status_code=202,
            content=JobCreate(job_id=job.job_id, status=job.status, created_at=job.created_at).model_dump(mode="json"),
        )

    handler.__name__ = f"check_{ct.value}"
    return handler


# Register a dedicated route per check type under /check/{type}
for _ct in CheckType:
    if _ct in _SLOW_CHECKS:
        _handler = _make_slow_check_handler(_ct)
        router.add_api_route(f"/check/{_ct.value}", _handler, methods=["POST"], tags=["Checks"])
    else:
        _handler = _make_check_handler(_ct)
        router.add_api_route(
            f"/check/{_ct.value}", _handler, methods=["POST"], response_model=TargetResult, tags=["Checks"]
        )
