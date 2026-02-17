"""Firestore-backed job store for persistent scan jobs.

Survives Cloud Run scale-to-zero. Uses Firestore's built-in TTL policy
for automatic document expiration (no cleanup loop needed).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from infraprobe.models import Job, JobStatus, ScanRequest, ScanResponse

logger = logging.getLogger("infraprobe.storage.firestore")

_COLLECTION = "infraprobe_jobs"


class FirestoreJobStore:
    """JobStore implementation using Google Cloud Firestore.

    Expects ``google-cloud-firestore`` to be installed.  Documents are stored
    in the ``infraprobe_jobs`` collection with the ``job_id`` as document ID.

    TTL expiration is handled server-side via a Firestore TTL policy on the
    ``expire_at`` field — no background cleanup loop required.
    """

    def __init__(
        self,
        project: str | None = None,
        database: str | None = None,
        ttl_seconds: int = 3600,
    ) -> None:
        from google.cloud.firestore_v1 import AsyncClient

        self._db = AsyncClient(project=project, database=database)
        self._collection = self._db.collection(_COLLECTION)
        self._ttl_seconds = ttl_seconds
        logger.info(
            "Firestore job store initialized",
            extra={"project": project, "database": database, "collection": _COLLECTION},
        )

    def _job_to_doc(self, job: Job) -> dict[str, Any]:
        """Serialize a Job to a Firestore-compatible dict."""
        from datetime import timedelta

        doc = job.model_dump(mode="json")
        # Add TTL expiration field for Firestore TTL policy
        doc["expire_at"] = job.updated_at + timedelta(seconds=self._ttl_seconds)
        return doc

    def _doc_to_job(self, doc: dict[str, Any]) -> Job:
        """Deserialize a Firestore document to a Job."""
        doc.pop("expire_at", None)
        return Job.model_validate(doc)

    async def create(self, job_id: str, request: ScanRequest) -> Job:
        now = datetime.now(UTC)
        job = Job(
            job_id=job_id,
            status=JobStatus.PENDING,
            created_at=now,
            updated_at=now,
            request=request,
        )
        await self._collection.document(job_id).set(self._job_to_doc(job))
        return job

    async def get(self, job_id: str) -> Job | None:
        doc = await self._collection.document(job_id).get()
        if not doc.exists:
            return None
        return self._doc_to_job(doc.to_dict())

    async def update_status(self, job_id: str, status: JobStatus) -> None:
        now = datetime.now(UTC)
        from datetime import timedelta

        await self._collection.document(job_id).update(
            {
                "status": status.value,
                "updated_at": now.isoformat(),
                "expire_at": (now + timedelta(seconds=self._ttl_seconds)).isoformat(),
            }
        )

    async def complete(self, job_id: str, result: ScanResponse) -> None:
        now = datetime.now(UTC)
        from datetime import timedelta

        await self._collection.document(job_id).update(
            {
                "status": JobStatus.COMPLETED.value,
                "result": result.model_dump(mode="json"),
                "updated_at": now.isoformat(),
                "expire_at": (now + timedelta(seconds=self._ttl_seconds)).isoformat(),
            }
        )

    async def fail(self, job_id: str, error: str) -> None:
        now = datetime.now(UTC)
        from datetime import timedelta

        await self._collection.document(job_id).update(
            {
                "status": JobStatus.FAILED.value,
                "error": error,
                "updated_at": now.isoformat(),
                "expire_at": (now + timedelta(seconds=self._ttl_seconds)).isoformat(),
            }
        )

    async def update_webhook_status(self, job_id: str, status: str, delivered_at: datetime | None) -> None:
        now = datetime.now(UTC)
        from datetime import timedelta

        await self._collection.document(job_id).update(
            {
                "webhook_status": status,
                "webhook_delivered_at": delivered_at.isoformat() if delivered_at else None,
                "updated_at": now.isoformat(),
                "expire_at": (now + timedelta(seconds=self._ttl_seconds)).isoformat(),
            }
        )
