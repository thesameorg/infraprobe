import asyncio
import logging
from datetime import UTC, datetime

from infraprobe.models import Job, JobStatus, ScanRequest, ScanResponse

logger = logging.getLogger("infraprobe.storage")


class MemoryJobStore:
    def __init__(self, ttl_seconds: int = 3600, cleanup_interval: int = 300) -> None:
        self._jobs: dict[str, Job] = {}
        self._ttl_seconds = ttl_seconds
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def create(self, job_id: str, request: ScanRequest) -> Job:
        now = datetime.now(UTC)
        job = Job(
            job_id=job_id,
            status=JobStatus.PENDING,
            created_at=now,
            updated_at=now,
            request=request,
        )
        async with self._lock:
            self._jobs[job_id] = job
        return job

    async def get(self, job_id: str) -> Job | None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if self._is_expired(job):
                del self._jobs[job_id]
                return None
            return job

    async def update_status(self, job_id: str, status: JobStatus) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = status
            job.updated_at = datetime.now(UTC)

    async def complete(self, job_id: str, result: ScanResponse) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = JobStatus.COMPLETED
            job.result = result
            job.updated_at = datetime.now(UTC)

    async def fail(self, job_id: str, error: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = JobStatus.FAILED
            job.error = error
            job.updated_at = datetime.now(UTC)

    async def update_webhook_status(self, job_id: str, status: str, delivered_at: datetime | None) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.webhook_status = status
            job.webhook_delivered_at = delivered_at
            job.updated_at = datetime.now(UTC)

    def _is_expired(self, job: Job) -> bool:
        age = (datetime.now(UTC) - job.updated_at).total_seconds()
        return age > self._ttl_seconds

    def start_cleanup_loop(self) -> asyncio.Task:
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        return self._cleanup_task

    def stop_cleanup_loop(self) -> None:
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            self._cleanup_task = None

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(self._cleanup_interval)
            try:
                async with self._lock:
                    expired = [jid for jid, job in self._jobs.items() if self._is_expired(job)]
                    for jid in expired:
                        del self._jobs[jid]
                if expired:
                    logger.info("cleaned up expired jobs", extra={"count": len(expired)})
            except Exception:
                logger.exception("error in job cleanup loop")
