"""Tests for FirestoreJobStore against the Firestore emulator.

Requires:
  1. google-cloud-firestore installed: uv sync --extra firestore
  2. Firestore emulator running: gcloud emulators firestore start --host-port=localhost:8686
  3. Env var: FIRESTORE_EMULATOR_HOST=localhost:8686

Tests skip automatically if either requirement is missing.
"""

from __future__ import annotations

import os
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

# Skip entire module if google-cloud-firestore not installed
try:
    import google.cloud.firestore_v1  # noqa: F401

    HAS_FIRESTORE = True
except ImportError:
    HAS_FIRESTORE = False

pytestmark = [
    pytest.mark.skipif(not HAS_FIRESTORE, reason="google-cloud-firestore not installed (uv sync --extra firestore)"),
    pytest.mark.skipif(
        not os.environ.get("FIRESTORE_EMULATOR_HOST"),
        reason="FIRESTORE_EMULATOR_HOST not set (start emulator: gcloud emulators firestore start)",
    ),
]


@pytest.fixture
async def store():
    """Create a FirestoreJobStore connected to the emulator, clean up after."""
    from infraprobe.storage.firestore import FirestoreJobStore

    s = FirestoreJobStore(project="test-project", database="(default)", ttl_seconds=3600)
    yield s
    # Clean up all documents in the collection
    async for doc in s._collection.stream():
        await doc.reference.delete()


def _scan_request(checks=None):
    return ScanRequest(targets=["example.com"], checks=checks or [CheckType.HEADERS])


def _scan_response():
    finding = Finding(severity=Severity.HIGH, title="Missing HSTS", description="No HSTS header")
    cr = CheckResult(check=CheckType.HEADERS, findings=[finding])
    tr = TargetResult(target="example.com", results={"headers": cr}, duration_ms=100)
    return ScanResponse(results=[tr])


class TestFirestoreJobStoreCRUD:
    async def test_create_and_get(self, store):
        job = await store.create("job-1", _scan_request())
        assert job.job_id == "job-1"
        assert job.status == JobStatus.PENDING
        assert job.request.targets == ["example.com"]

        fetched = await store.get("job-1")
        assert fetched is not None
        assert fetched.job_id == "job-1"
        assert fetched.status == JobStatus.PENDING
        assert fetched.request.targets == ["example.com"]

    async def test_get_nonexistent_returns_none(self, store):
        result = await store.get("nonexistent")
        assert result is None

    async def test_update_status(self, store):
        await store.create("job-2", _scan_request())
        await store.update_status("job-2", JobStatus.RUNNING)

        job = await store.get("job-2")
        assert job.status == JobStatus.RUNNING
        assert job.updated_at > job.created_at

    async def test_complete(self, store):
        await store.create("job-3", _scan_request())
        result = _scan_response()
        await store.complete("job-3", result)

        job = await store.get("job-3")
        assert job.status == JobStatus.COMPLETED
        assert job.result is not None
        assert len(job.result.results) == 1
        assert job.result.results[0].target == "example.com"
        assert "headers" in job.result.results[0].results
        assert len(job.result.results[0].results["headers"].findings) == 1
        assert job.result.results[0].results["headers"].findings[0].title == "Missing HSTS"

    async def test_fail(self, store):
        await store.create("job-4", _scan_request())
        await store.fail("job-4", "Connection refused")

        job = await store.get("job-4")
        assert job.status == JobStatus.FAILED
        assert job.error == "Connection refused"

    async def test_update_webhook_status(self, store):
        await store.create("job-5", _scan_request())
        now = datetime.now(UTC)
        await store.update_webhook_status("job-5", "delivered", now)

        job = await store.get("job-5")
        assert job.webhook_status == "delivered"
        assert job.webhook_delivered_at is not None


class TestFirestoreJobStoreLifecycle:
    async def test_full_lifecycle(self, store):
        """Simulate the full job lifecycle: create → running → completed."""
        req = _scan_request([CheckType.HEADERS, CheckType.SSL])
        job = await store.create("lifecycle-1", req)
        assert job.status == JobStatus.PENDING

        await store.update_status("lifecycle-1", JobStatus.RUNNING)
        job = await store.get("lifecycle-1")
        assert job.status == JobStatus.RUNNING

        await store.complete("lifecycle-1", _scan_response())
        job = await store.get("lifecycle-1")
        assert job.status == JobStatus.COMPLETED
        assert job.result is not None
        assert job.result.summary.total > 0

    async def test_failed_lifecycle(self, store):
        """Simulate a failed scan: create → running → failed."""
        await store.create("lifecycle-2", _scan_request())
        await store.update_status("lifecycle-2", JobStatus.RUNNING)
        await store.fail("lifecycle-2", "Scanner crashed")

        job = await store.get("lifecycle-2")
        assert job.status == JobStatus.FAILED
        assert job.error == "Scanner crashed"
        assert job.result is None

    async def test_multiple_jobs_independent(self, store):
        """Multiple jobs don't interfere with each other."""
        await store.create("multi-1", _scan_request())
        await store.create("multi-2", _scan_request())

        await store.complete("multi-1", _scan_response())
        await store.fail("multi-2", "timeout")

        job1 = await store.get("multi-1")
        job2 = await store.get("multi-2")
        assert job1.status == JobStatus.COMPLETED
        assert job2.status == JobStatus.FAILED


class TestFirestoreJobStoreSerialization:
    async def test_scan_response_roundtrip(self, store):
        """ScanResponse survives serialization to/from Firestore."""
        finding = Finding(
            severity=Severity.CRITICAL,
            title="Expired cert",
            description="Certificate expired 30 days ago",
            details={"days_expired": 30, "issuer": "Let's Encrypt"},
        )
        cr = CheckResult(check=CheckType.SSL, findings=[finding], raw={"host": "example.com", "port": 443})
        tr = TargetResult(target="example.com", results={"ssl": cr}, duration_ms=250)
        result = ScanResponse(results=[tr])

        await store.create("serial-1", _scan_request([CheckType.SSL]))
        await store.complete("serial-1", result)

        job = await store.get("serial-1")
        assert job.result.results[0].results["ssl"].findings[0].severity == Severity.CRITICAL
        assert job.result.results[0].results["ssl"].findings[0].details["days_expired"] == 30
        assert job.result.results[0].results["ssl"].raw["port"] == 443
        assert job.result.summary.critical == 1
        assert job.result.summary.total == 1

    async def test_empty_result_roundtrip(self, store):
        """A scan with no findings roundtrips correctly."""
        cr = CheckResult(check=CheckType.HEADERS, findings=[])
        tr = TargetResult(target="example.com", results={"headers": cr}, duration_ms=50)
        result = ScanResponse(results=[tr])

        await store.create("serial-2", _scan_request())
        await store.complete("serial-2", result)

        job = await store.get("serial-2")
        assert job.result.results[0].results["headers"].findings == []
        assert job.result.summary.total == 0

    async def test_error_check_result_roundtrip(self, store):
        """A check result with an error but no findings roundtrips correctly."""
        cr = CheckResult(check=CheckType.SSL, error="Connection refused")
        tr = TargetResult(target="example.com", results={"ssl": cr}, duration_ms=10)
        result = ScanResponse(results=[tr])

        await store.create("serial-3", _scan_request([CheckType.SSL]))
        await store.complete("serial-3", result)

        job = await store.get("serial-3")
        assert job.result.results[0].results["ssl"].error == "Connection refused"
        assert job.result.results[0].results["ssl"].findings == []
