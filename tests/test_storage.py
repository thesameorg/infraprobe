import asyncio

import pytest

from infraprobe.models import CheckType, JobStatus, ScanRequest, ScanResponse
from infraprobe.storage.memory import MemoryJobStore


@pytest.fixture
def store():
    return MemoryJobStore(ttl_seconds=2, cleanup_interval=1)


@pytest.fixture
def scan_request():
    return ScanRequest(targets=["example.com"], checks=[CheckType.HEADERS])


async def test_create_and_get(store: MemoryJobStore, scan_request: ScanRequest):
    job = await store.create("job-1", scan_request)
    assert job.job_id == "job-1"
    assert job.status == JobStatus.PENDING
    assert job.request == scan_request
    assert job.result is None
    assert job.error is None

    fetched = await store.get("job-1")
    assert fetched is not None
    assert fetched.job_id == "job-1"


async def test_get_nonexistent(store: MemoryJobStore):
    assert await store.get("nope") is None


async def test_update_status(store: MemoryJobStore, scan_request: ScanRequest):
    await store.create("job-1", scan_request)
    await store.update_status("job-1", JobStatus.RUNNING)
    job = await store.get("job-1")
    assert job is not None
    assert job.status == JobStatus.RUNNING


async def test_complete(store: MemoryJobStore, scan_request: ScanRequest):
    await store.create("job-1", scan_request)
    result = ScanResponse(results=[])
    await store.complete("job-1", result)
    job = await store.get("job-1")
    assert job is not None
    assert job.status == JobStatus.COMPLETED
    assert job.result == result


async def test_fail(store: MemoryJobStore, scan_request: ScanRequest):
    await store.create("job-1", scan_request)
    await store.fail("job-1", "something broke")
    job = await store.get("job-1")
    assert job is not None
    assert job.status == JobStatus.FAILED
    assert job.error == "something broke"


async def test_ttl_expiration(store: MemoryJobStore, scan_request: ScanRequest):
    await store.create("job-1", scan_request)
    # Wait for TTL (2s) to expire
    await asyncio.sleep(2.5)
    assert await store.get("job-1") is None


async def test_cleanup_loop(scan_request: ScanRequest):
    store = MemoryJobStore(ttl_seconds=1, cleanup_interval=1)
    await store.create("job-1", scan_request)
    await store.create("job-2", scan_request)

    store.start_cleanup_loop()
    try:
        # Wait long enough for TTL to expire and cleanup to run
        await asyncio.sleep(2.5)
        # Jobs should be cleaned up from internal dict
        assert "job-1" not in store._jobs
        assert "job-2" not in store._jobs
    finally:
        store.stop_cleanup_loop()
