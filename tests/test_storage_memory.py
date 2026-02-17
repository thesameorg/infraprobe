"""Tests for MemoryJobStore — verifies the JobStore contract without external deps."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from infraprobe.models import (
    CheckResult,
    CheckType,
    Finding,
    JobStatus,
    ScanRequest,
    ScanResponse,
    Severity,
    TargetResult,
)
from infraprobe.storage.memory import MemoryJobStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
def store() -> MemoryJobStore:
    return MemoryJobStore(ttl_seconds=3600, cleanup_interval=300)


def _scan_request() -> ScanRequest:
    return ScanRequest(targets=["example.com"], checks=[CheckType.HEADERS])


def _scan_response() -> ScanResponse:
    finding = Finding(severity=Severity.HIGH, title="Missing HSTS", description="No HSTS header")
    cr = CheckResult(check=CheckType.HEADERS, findings=[finding])
    tr = TargetResult(target="example.com", results={"headers": cr}, duration_ms=100)
    return ScanResponse(results=[tr])


async def test_create_and_get(store: MemoryJobStore):
    job = await store.create("job-1", _scan_request())
    assert job.job_id == "job-1"
    assert job.status == JobStatus.PENDING

    retrieved = await store.get("job-1")
    assert retrieved is not None
    assert retrieved.job_id == "job-1"


async def test_get_nonexistent(store: MemoryJobStore):
    assert await store.get("nope") is None


async def test_update_status(store: MemoryJobStore):
    await store.create("job-2", _scan_request())
    await store.update_status("job-2", JobStatus.RUNNING)
    job = await store.get("job-2")
    assert job.status == JobStatus.RUNNING


async def test_complete(store: MemoryJobStore):
    await store.create("job-3", _scan_request())
    await store.complete("job-3", _scan_response())
    job = await store.get("job-3")
    assert job.status == JobStatus.COMPLETED
    assert job.result is not None
    assert job.result.results[0].target == "example.com"
    assert job.result.summary.high == 1


async def test_fail(store: MemoryJobStore):
    await store.create("job-4", _scan_request())
    await store.fail("job-4", "boom")
    job = await store.get("job-4")
    assert job.status == JobStatus.FAILED
    assert job.error == "boom"


async def test_update_webhook_status(store: MemoryJobStore):
    await store.create("job-5", _scan_request())
    now = datetime.now(UTC)
    await store.update_webhook_status("job-5", "delivered", now)
    job = await store.get("job-5")
    assert job.webhook_status == "delivered"
    assert job.webhook_delivered_at == now


async def test_ttl_expiration(store: MemoryJobStore):
    """Expired jobs should not be returned."""
    store._ttl_seconds = 0  # Expire immediately
    await store.create("expired", _scan_request())
    # updated_at is set to now; with TTL=0, it's already expired
    job = await store.get("expired")
    assert job is None


async def test_full_lifecycle(store: MemoryJobStore):
    await store.create("lc-1", _scan_request())
    await store.update_status("lc-1", JobStatus.RUNNING)
    await store.complete("lc-1", _scan_response())
    job = await store.get("lc-1")
    assert job.status == JobStatus.COMPLETED
    assert job.result.summary.total == 1


async def test_multiple_jobs_independent(store: MemoryJobStore):
    await store.create("a", _scan_request())
    await store.create("b", _scan_request())
    await store.update_status("a", JobStatus.RUNNING)
    await store.fail("b", "timeout")

    assert (await store.get("a")).status == JobStatus.RUNNING
    assert (await store.get("b")).status == JobStatus.FAILED
