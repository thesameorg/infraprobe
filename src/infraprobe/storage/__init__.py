from infraprobe.storage.base import JobStore
from infraprobe.storage.memory import MemoryJobStore

__all__ = ["JobStore", "MemoryJobStore"]


def create_job_store(backend: str = "memory", **kwargs) -> MemoryJobStore:
    """Factory for creating job stores based on backend config.

    Returns MemoryJobStore for 'memory' backend.
    For 'firestore', imports FirestoreJobStore lazily to avoid requiring
    google-cloud-firestore in development.
    """
    if backend == "firestore":
        from infraprobe.storage.firestore import FirestoreJobStore

        return FirestoreJobStore(**kwargs)  # type: ignore[return-value]
    return MemoryJobStore(**kwargs)
