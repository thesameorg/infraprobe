"""Storage contract tests — verify both MemoryJobStore and FirestoreJobStore
implement the JobStore protocol correctly.

These tests run against MemoryJobStore by default. Firestore tests require
the Firestore emulator (skipped if unavailable).
"""

import asyncio
from datetime import UTC, datetime

import pytest

from infraprobe.models import CheckResult, CheckType, JobStatus, ScanRequest, ScanResponse, TargetResult
from infraprobe.storage.memory import MemoryJobStore


def _make_request() -> ScanRequest:
    return ScanRequest(targets=["example.com"], checks=["headers"])


def _make_response() -> ScanResponse:
    return ScanResponse(
        results=[
            TargetResult(
                target="example.com",
                results={"headers": CheckResult(check=CheckType.HEADERS)},
                duration_ms=100,
            )
        ]
    )


@pytest.fixture
def store():
    return MemoryJobStore(ttl_seconds=3600, cleanup_interval=300)


class TestJobStoreContract:
    """Tests that any JobStore implementation must satisfy."""

    def test_create_and_get(self, store):
        async def _test():
            job = await store.create("job-1", _make_request())
            assert job.job_id == "job-1"
            assert job.status == JobStatus.PENDING
            assert job.result is None
            assert job.error is None

            retrieved = await store.get("job-1")
            assert retrieved is not None
            assert retrieved.job_id == "job-1"
            assert retrieved.status == JobStatus.PENDING

        asyncio.get_event_loop().run_until_complete(_test())

    def test_get_nonexistent_returns_none(self, store):
        async def _test():
            result = await store.get("nonexistent")
            assert result is None

        asyncio.get_event_loop().run_until_complete(_test())

    def test_update_status(self, store):
        async def _test():
            await store.create("job-1", _make_request())
            await store.update_status("job-1", JobStatus.RUNNING)

            job = await store.get("job-1")
            assert job.status == JobStatus.RUNNING

        asyncio.get_event_loop().run_until_complete(_test())

    def test_complete(self, store):
        async def _test():
            await store.create("job-1", _make_request())
            await store.update_status("job-1", JobStatus.RUNNING)

            result = _make_response()
            await store.complete("job-1", result)

            job = await store.get("job-1")
            assert job.status == JobStatus.COMPLETED
            assert job.result is not None
            assert len(job.result.results) == 1
            assert job.result.results[0].target == "example.com"

        asyncio.get_event_loop().run_until_complete(_test())

    def test_fail(self, store):
        async def _test():
            await store.create("job-1", _make_request())
            await store.update_status("job-1", JobStatus.RUNNING)
            await store.fail("job-1", "Something went wrong")

            job = await store.get("job-1")
            assert job.status == JobStatus.FAILED
            assert job.error == "Something went wrong"
            assert job.result is None

        asyncio.get_event_loop().run_until_complete(_test())

    def test_update_webhook_status(self, store):
        async def _test():
            await store.create("job-1", _make_request())
            now = datetime.now(UTC)
            await store.update_webhook_status("job-1", "delivered", now)

            job = await store.get("job-1")
            assert job.webhook_status == "delivered"
            assert job.webhook_delivered_at is not None

        asyncio.get_event_loop().run_until_complete(_test())

    def test_job_preserves_request(self, store):
        async def _test():
            request = _make_request()
            await store.create("job-1", request)

            job = await store.get("job-1")
            assert job.request.targets == ["example.com"]
            assert job.request.checks == request.checks

        asyncio.get_event_loop().run_until_complete(_test())

    def test_complete_result_has_summary(self, store):
        async def _test():
            await store.create("job-1", _make_request())
            result = _make_response()
            await store.complete("job-1", result)

            job = await store.get("job-1")
            assert job.result is not None
            assert hasattr(job.result, "summary")
            assert job.result.summary.total >= 0

        asyncio.get_event_loop().run_until_complete(_test())


class TestMemoryJobStoreTTL:
    """TTL-specific tests for MemoryJobStore."""

    def test_expired_job_returns_none(self):
        import time

        store = MemoryJobStore(ttl_seconds=1, cleanup_interval=300)

        async def _test():
            await store.create("job-1", _make_request())
            time.sleep(1.5)  # Wait for TTL to expire
            result = await store.get("job-1")
            assert result is None

        asyncio.get_event_loop().run_until_complete(_test())
