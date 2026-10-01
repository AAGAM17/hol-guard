"""Keep coverage failures tied to both jobs that create the shard matrix."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.ci import wait_for_pytest_shards as barrier
from tests.test_ci_wait_for_pytest_shards import _RUN_ID, _job, _jobs, _run

ROOT = Path(__file__).resolve().parents[1]


def test_barrier_tracks_every_coverage_prerequisite() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    assert set(barrier._PREREQUISITE_LABELS) == set(jobs["coverage"]["needs"])


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "timed_out"])
@pytest.mark.parametrize("prerequisite", ["coverage-plan", "native-command-evaluators"])
@pytest.mark.parametrize("placeholder_position", ["none", "before", "after", "previous-page"])
def test_failed_prerequisite_stops_without_waiting_for_an_unexpanded_matrix(
    conclusion: str, prerequisite: str, placeholder_position: str
) -> None:
    failed = dict(_job(1000), name=prerequisite, conclusion=conclusion)
    placeholder = dict(_job(1001), name="coverage (3.12, ${{ matrix.shard-index }})", conclusion="skipped")
    jobs = [failed]
    if placeholder_position == "before":
        jobs = [placeholder, failed]
    elif placeholder_position == "after":
        jobs = [failed, placeholder]
    elif placeholder_position == "previous-page":
        jobs = [placeholder, *[dict(_job(2000 + i), name=f"other-{i}") for i in range(99)], failed]
    calls: list[str] = []

    def fetch(path: str, _timeout: float) -> object:
        calls.append(path)
        page = int(path.rsplit("=", 1)[1])
        return {"total_count": len(jobs), "jobs": jobs[(page - 1) * 100 : page * 100]}

    label = "Python coverage-plan" if prerequisite == "coverage-plan" else "Native command evaluators"
    with pytest.raises(barrier.ShardWaitError, match=f"^{label} completed with {conclusion}$"):
        barrier.wait_for_shards(
            "owner/repo",
            _RUN_ID,
            2,
            fetch_json=fetch,
            clock=lambda: 0.0,
            sleep=lambda _delay: pytest.fail("A failed prerequisite must not be polled again"),
            log=lambda _message: None,
        )
    assert len(calls) == (2 if placeholder_position == "previous-page" else 1)


@pytest.mark.parametrize("status", ["queued", "in_progress"])
def test_pending_native_build_waits_for_complete_successful_coverage(status: str) -> None:
    pending = dict(_job(1000), name="native-command-evaluators", status=status, conclusion=None)
    complete = dict(pending, status="completed", conclusion="success")
    calls, logs = _run([[pending], [complete, *_jobs()]])
    assert len(calls) == 3
    assert logs[-1].startswith("All 128 Python coverage shards succeeded")


def test_successful_native_build_cannot_replace_a_missing_shard() -> None:
    native = dict(_job(1000), name="native-command-evaluators")
    with pytest.raises(barrier.ShardWaitError, match="Timed out"):
        _run([[native, *_jobs()[:-1]]], timeout_seconds=10)


def test_unrelated_failed_job_does_not_supply_or_invalidate_coverage() -> None:
    other = dict(_job(1000), name="unrelated-job", conclusion="failure")
    _, logs = _run([[other, *_jobs()]])
    assert logs[-1].startswith("All 128 Python coverage shards succeeded")


def test_duplicate_native_build_is_rejected() -> None:
    native = dict(_job(1000), name="native-command-evaluators")
    duplicate = dict(native, id=9999)
    with pytest.raises(barrier.ShardWaitError, match="duplicate native-command-evaluators jobs"):
        _run([[native, duplicate, *_jobs()]])


@pytest.mark.parametrize("field,value", [("run_id", _RUN_ID + 1), ("run_attempt", 1)])
def test_native_build_from_another_execution_is_rejected(field: str, value: int) -> None:
    native = dict(_job(1000), name="native-command-evaluators", **{field: value})
    with pytest.raises(barrier.ShardWaitError, match="another (run|attempt)"):
        _run([[native, *_jobs()]])
