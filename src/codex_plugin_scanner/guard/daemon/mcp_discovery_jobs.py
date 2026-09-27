"""Small in-memory pool for explicitly requested, Guard-owned MCP probes."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from uuid import uuid4


class DiscoveryJobError(ValueError):
    pass


@dataclass
class _Job:
    job_id: str
    cli_id: str
    started: float
    cancel: threading.Event = field(default_factory=threading.Event)
    state: str = "running"
    code: str | None = None
    finished: float | None = None
    thread: threading.Thread | None = None

    def public(self) -> dict[str, object]:
        return {"job_id": self.job_id, "cli_id": self.cli_id, "state": self.state, "error": self.code}


class McpDiscoveryJobs:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, _Job] = {}
        self._closed = False

    def start(
        self, cli_id: str, run: Callable[[threading.Event], None], *, reuse_seconds: float = 0,
    ) -> dict[str, object]:
        with self._lock:
            if self._closed:
                raise DiscoveryJobError("discovery_unavailable")
            now = time.monotonic()
            self._jobs = {
                key: job for key, job in self._jobs.items() if job.finished is None or now - job.finished < 600
            }
            for job in reversed(tuple(self._jobs.values())):
                if job.cli_id != cli_id:
                    continue
                if job.state in {"running", "cancelling"}:
                    return job.public()
                if job.state == "failed" and job.finished is not None and now - job.finished < 10:
                    raise DiscoveryJobError("discovery_retry_backoff")
                if job.state == "complete" and job.finished is not None and now - job.finished < reuse_seconds:
                    return job.public()
                break
            if sum(job.finished is None for job in self._jobs.values()) >= 2:
                raise DiscoveryJobError("discovery_busy")
            while len(self._jobs) >= 16:
                oldest = next((key for key, job in self._jobs.items() if job.finished is not None), None)
                if oldest is None:
                    raise DiscoveryJobError("discovery_busy")
                del self._jobs[oldest]
            job = _Job(uuid4().hex, cli_id, now)
            self._jobs[job.job_id] = job
            job.thread = threading.Thread(
                target=self._run, args=(job, run), name="hol-guard-mcp-discovery", daemon=True,
            )
            try:
                job.thread.start()
            except RuntimeError:
                del self._jobs[job.job_id]
                raise DiscoveryJobError("discovery_unavailable") from None
            return job.public()

    def read(self, job_id: str, *, cancel: bool = False) -> dict[str, object]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise DiscoveryJobError("discovery_job_unavailable")
            if cancel and job.finished is None:
                job.cancel.set()
                job.state = "cancelling"
            return job.public()

    def _run(self, job: _Job, run: Callable[[threading.Event], None]) -> None:
        code = None
        try:
            if not job.cancel.is_set():
                run(job.cancel)
        except Exception as error:
            # Never expose a launch command, environment, provider result, or
            # exception text to polling clients. API codes are a narrow enum.
            candidate = getattr(error, "code", None)
            code = (
                candidate if candidate in {"mcp_refresh_unavailable", "catalog_revision_conflict"}
                else "discovery_failed"
            )
        finally:
            with self._lock:
                job.finished = time.monotonic()
                job.state = "cancelled" if job.cancel.is_set() else "failed" if code else "complete"
                job.code = None if job.cancel.is_set() else code

    def close(self) -> bool:
        with self._lock:
            self._closed = True
            jobs = tuple(self._jobs.values())
            for job in jobs:
                job.cancel.set()
        deadline = time.monotonic() + 3
        for job in jobs:
            if job.thread is not None:
                job.thread.join(max(0, deadline - time.monotonic()))
        return all(job.thread is None or not job.thread.is_alive() for job in jobs)
