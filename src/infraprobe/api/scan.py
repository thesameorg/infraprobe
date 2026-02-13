import asyncio
import time
from collections.abc import Callable, Coroutine

from fastapi import APIRouter

from infraprobe.blocklist import validate_target
from infraprobe.config import settings
from infraprobe.models import CheckResult, CheckType, ScanRequest, ScanResponse, SingleCheckRequest, TargetResult
from infraprobe.scoring import calculate_score

router = APIRouter()

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
    try:
        return await asyncio.wait_for(fn(target, timeout), timeout=timeout + _SCHEDULING_BUFFER)
    except TimeoutError:
        return CheckResult(check=check_type, error=f"Scanner {check_type} timed out after {timeout}s")
    except Exception as exc:
        return CheckResult(check=check_type, error=f"Scanner {check_type} failed: {exc}")


_DEEP_CHECKS = frozenset({"ssl_deep", "tech_deep", "dns_deep"})


async def _scan_target(target: str, checks: list[CheckType]) -> TargetResult:
    start = time.monotonic()

    tasks = [
        _run_scanner(
            ct,
            target,
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
        target=target,
        score=score,
        summary=summary,
        results=results_map,
        duration_ms=duration_ms,
    )


@router.post("/scan")
async def scan(request: ScanRequest) -> ScanResponse:
    validated = [validate_target(raw) for raw in request.targets]
    target_results = await asyncio.gather(*[_scan_target(t, request.checks) for t in validated])
    return ScanResponse(results=list(target_results))


async def _single_check(check_type: CheckType, request: SingleCheckRequest) -> TargetResult:
    target = validate_target(request.target)
    return await _scan_target(target, [check_type])


def _make_check_handler(ct: CheckType):
    async def handler(request: SingleCheckRequest) -> TargetResult:
        return await _single_check(ct, request)

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
