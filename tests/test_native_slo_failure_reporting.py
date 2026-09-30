from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest

from scripts import bench_guard_native_installed_slo as benchmark
from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_contract import (
    MAX_COLD_P95_MS,
    MAX_INSTALLED_ADAPTER_P95_MS,
    MAX_INSTALLED_ADAPTER_P99_MS,
    MAX_READINESS_P95_MS,
)
from scripts.native_slo_reporting import (
    SloMeasurements,
    SloProgress,
    incomplete_slo_result,
    slo_gates,
    slo_result,
    summarize_measurements,
)
from scripts.native_slo_session import AdapterSession


class _FixtureObject:
    def __init__(self, **fields: object) -> None:
        for name, value in fields.items():
            setattr(self, name, value)


def _progress(*, include_capacity: bool = True) -> SloProgress:
    progress = SloProgress()
    progress.configure(
        (("codex", "PreToolUse"), ("cursor", "PostToolUse")),
        warm_iterations=2,
        cold_iterations=2,
        recovery_iterations=2,
        readiness_samples=2,
        include_capacity=include_capacity,
    )
    progress.runtime_summary = {"mode": "auto", "package_origin": "installed"}
    return progress


@pytest.mark.parametrize("failing_stage", ("proof_environment", "runtime_provenance"))
def test_preflight_failure_preserves_unknown_plan_and_environment(
    failing_stage: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress = SloProgress()
    error = TimeoutError("preflight transport")

    monkeypatch.setattr(benchmark, "_clear_proof_overrides", lambda: None)
    if failing_stage == "proof_environment":
        monkeypatch.setattr(benchmark, "_clear_proof_overrides", lambda: (_ for _ in ()).throw(error))
    else:
        monkeypatch.setattr(benchmark, "_runtime_summary", lambda _runtime: (_ for _ in ()).throw(error))

    with pytest.raises(TimeoutError, match="preflight transport"):
        benchmark.run_slo(
            tmp_path / "runtime",
            warm_iterations=1,
            cold_iterations=1,
            recovery_iterations=1,
            readiness_samples=1,
            include_capacity=False,
            progress=progress,
        )

    report = incomplete_slo_result(progress, include_capacity=False)
    assert report["failure"]["stage"] == failing_stage
    assert report["failure"]["category"] == "transport_timeout"
    assert report["runtime"]["host_os"]
    assert report["runtime"]["python_version"]
    assert report["corpus"]["routes"] is None
    assert report["corpus"]["harnesses"] is None
    assert report["corpus"]["planned"] is None
    assert report["corpus"]["missing"] is None
    assert report["corpus"]["denominators"]["warm"]["planned"] is None
    assert report["corpus"]["denominators"][failing_stage] == {
        "planned": 1,
        "submitted": 1,
        "started": 1,
        "attempted": 1,
        "completed": 0,
        "failed": 1,
        "cancelled": 0,
        "missing": 0,
        "skipped": False,
    }
    assert all(value is False for value in report["gates"].values())


def test_incomplete_report_preserves_scope_thresholds_and_missing_denominators() -> None:
    progress = _progress()
    progress.activate("warm", harness="codex", event="PreToolUse", size_class="1k")
    progress.submit("warm")
    progress.attempt("warm")
    progress.fail_request("warm")
    progress.record_failure(
        TimeoutError("/fixture/request"),
        stage="warm",
        labels={"harness": "codex", "event": "PreToolUse", "size_class": "1k"},
    )

    report = incomplete_slo_result(progress, include_capacity=True)

    assert report["schema"] == "hol-guard.native-installed-slo.v1"
    assert report["scope"] == "installed_adapter_to_decision"
    assert report["status"] == "failed"
    assert report["evaluation"] == "incomplete"
    assert report["complete"] is False
    assert report["passed"] is False
    assert report["failure"] == {
        "stage": "warm",
        "category": "transport_timeout",
        "harness": "codex",
        "event": "PreToolUse",
        "size_class": "1k",
    }
    assert report["thresholds"] == {
        "installed_adapter_p95_ms": MAX_INSTALLED_ADAPTER_P95_MS,
        "installed_adapter_concurrent_p99_ms": MAX_INSTALLED_ADAPTER_P99_MS,
        "direct_cold_p95_ms": MAX_COLD_P95_MS,
        "readiness_p95_ms": MAX_READINESS_P95_MS,
    }
    assert all(value is False for value in cast(dict[str, bool], report["gates"]).values())
    warm = cast(dict[str, object], cast(dict[str, object], report["corpus"])["denominators"])["warm"]
    assert warm == {
        "planned": 4,
        "submitted": 1,
        "started": 1,
        "attempted": 1,
        "completed": 0,
        "failed": 1,
        "cancelled": 0,
        "missing": 3,
        "skipped": False,
    }
    corpus = cast(dict[str, object], report["corpus"])
    assert corpus["planned"] == 87
    assert corpus["submitted"] == 1
    assert corpus["started"] == 1
    assert corpus["attempted"] == 1
    assert corpus["completed"] == 0
    assert corpus["failed"] == 1
    assert corpus["cancelled"] == 0
    assert corpus["missing"] == 86
    assert cast(dict[str, object], cast(dict[str, object], report["concurrency"])["sixteen"])["denominators"] == {
        "planned": 16,
        "submitted": 0,
        "started": 0,
        "attempted": 0,
        "completed": 0,
        "failed": 0,
        "cancelled": 0,
        "missing": 16,
        "skipped": False,
    }
    encoded = json.dumps(report)
    assert "/fixture/request" not in encoded
    assert "fixture/request" not in encoded


def test_warm_failure_records_the_measured_route_without_aliasing_precondition() -> None:
    progress = _progress()
    calls = 0

    class Session:
        def observe(self, harness: str, event: str, size_class: str, _payload: object = None) -> Observation:
            nonlocal calls
            calls += 1
            if calls == 4:
                raise RuntimeError("adapter request failed") from TimeoutError("transport detail")
            return Observation(harness, event, size_class, 1.0, "native_resident", True)

    with pytest.raises(RuntimeError, match="adapter request failed"):
        benchmark._run_warm(cast(AdapterSession, Session()), tuple(progress.routes), 2, progress=progress)

    stages = progress.stage_snapshot()
    assert stages["warm_precondition"]["completed"] == 2
    assert stages["warm"]["attempted"] == 2
    assert stages["warm"]["completed"] == 1
    assert stages["warm"]["failed"] == 1
    assert stages["warm"]["missing"] == 2
    assert progress.snapshot_failure()["category"] == "transport_timeout"
    assert progress.snapshot_failure()["harness"] == "cursor"


def test_cold_failure_counts_failed_one_shot_without_emitting_response_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    progress = _progress()
    session = _FixtureObject(
        workspace=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
        stop_resident=lambda: True,
    )
    monkeypatch.setattr(
        benchmark.subprocess,
        "run",
        lambda *_args, **_kwargs: _FixtureObject(returncode=1, stdout=b"fixture response body"),
    )

    with pytest.raises(RuntimeError, match="cold native one-shot failed"):
        benchmark._run_cold(tmp_path / "runtime", cast(AdapterSession, session), 2, progress=progress)

    stage = progress.stage_snapshot()["cold"]
    assert stage["attempted"] == 1
    assert stage["completed"] == 0
    assert stage["failed"] == 1
    assert stage["missing"] == 1
    report = incomplete_slo_result(progress, include_capacity=True)
    assert "fixture response body" not in json.dumps(report)


def test_recovery_timeout_keeps_precondition_and_measured_denominators_separate() -> None:
    progress = _progress()
    calls = 0

    def observe(*_args: object, **_kwargs: object) -> Observation:
        nonlocal calls
        calls += 1
        if calls == 1:
            return Observation("claude-code", "PostToolUse", "1k", 1.0, "native_resident", True)
        raise RuntimeError("adapter request failed") from TimeoutError("fixture transport detail")

    session = _FixtureObject(observe=observe, stop_resident=lambda **_kwargs: True)
    with pytest.raises(RuntimeError, match="adapter request failed"):
        benchmark._run_recovery(cast(AdapterSession, session), 2, progress=progress)

    stages = progress.stage_snapshot()
    assert stages["recovery_precondition"]["completed"] == 1
    assert stages["recovery"]["attempted"] == 1
    assert stages["recovery"]["completed"] == 0
    assert stages["recovery"]["failed"] == 1
    assert stages["recovery"]["missing"] == 1
    assert progress.snapshot_failure()["stage"] == "recovery"
    assert progress.snapshot_failure()["category"] == "transport_timeout"


@pytest.mark.parametrize("failure_mode", ("session_start", "first_sample", "warm", "cold_start"))
def test_pre_readiness_and_startup_failures_are_counted_at_bounded_stages(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress = _progress()
    session_count = 0

    class SessionContext:
        def __init__(self, *, fail_enter: bool, fail_sample: bool) -> None:
            self.fail_enter = fail_enter
            self.fail_sample = fail_sample

        def __enter__(self) -> SessionContext:
            if self.fail_enter:
                raise TimeoutError("readiness startup transport")
            return self

        def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> bool:
            return False

        @property
        def readiness_ms(self) -> float:
            if self.fail_sample:
                raise TimeoutError("readiness sample transport")
            return 1.0

    def session_factory(_runtime: Path) -> SessionContext:
        nonlocal session_count
        session_count += 1
        return SessionContext(
            fail_enter=(
                (session_count == 2 and failure_mode == "session_start")
                or (session_count == 1 and failure_mode == "cold_start")
            ),
            fail_sample=session_count == 2 and failure_mode == "first_sample",
        )

    def run_warm(*_args: object, **_kwargs: object) -> list[Observation]:
        if failure_mode == "warm":
            raise TimeoutError("warm transport")
        return []

    monkeypatch.setattr(benchmark, "AdapterSession", session_factory)
    monkeypatch.setattr(benchmark, "_run_cold", lambda *_args, **_kwargs: [1.0])
    monkeypatch.setattr(benchmark, "_run_warm", run_warm)
    monkeypatch.setattr(benchmark, "_run_sizes", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(benchmark, "_run_recovery", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(benchmark, "_run_serialized_warmup", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        benchmark,
        "measure_capacity",
        lambda *_args, **_kwargs: _FixtureObject(
            concurrent_16=[],
            concurrent_64=[],
            errors_16=0,
            errors_64=0,
            rss_baseline=1,
            rss_peak=1,
        ),
    )
    monkeypatch.setattr(benchmark, "process_rss_bytes", lambda: 1)

    with pytest.raises(TimeoutError, match="transport"):
        benchmark._measure_slo(
            tmp_path / "runtime",
            tuple(progress.routes),
            warm_iterations=1,
            cold_iterations=1,
            recovery_iterations=1,
            readiness_samples=2,
            include_capacity=False,
            progress=progress,
        )

    stages = progress.stage_snapshot()
    if failure_mode == "cold_start":
        assert stages["cold_start"] == {
            "planned": 1,
            "submitted": 1,
            "started": 1,
            "attempted": 1,
            "completed": 0,
            "failed": 1,
            "cancelled": 0,
            "missing": 0,
            "skipped": False,
        }
        assert stages["readiness_start"]["attempted"] == 0
        expected_failure = {"stage": "cold_start", "category": "transport_timeout", "size_class": "1k"}
    elif failure_mode == "session_start":
        assert stages["readiness_start"] == {
            "planned": 1,
            "submitted": 1,
            "started": 1,
            "attempted": 1,
            "completed": 0,
            "failed": 1,
            "cancelled": 0,
            "missing": 0,
            "skipped": False,
        }
        assert stages["readiness"]["attempted"] == 0
        expected_failure = {"stage": "readiness_start", "category": "transport_timeout", "wave": "0"}
    elif failure_mode == "warm":
        assert stages["cold_start"]["completed"] == 1
        assert stages["readiness_start"]["completed"] == 1
        assert stages["readiness"]["attempted"] == 0
        expected_failure = {"stage": "warm", "category": "transport_timeout"}
    else:
        assert stages["readiness_start"]["completed"] == 1
        assert stages["readiness"] == {
            "planned": 2,
            "submitted": 1,
            "started": 1,
            "attempted": 1,
            "completed": 0,
            "failed": 1,
            "cancelled": 0,
            "missing": 1,
            "skipped": False,
        }
        expected_failure = {"stage": "readiness", "category": "transport_timeout", "wave": "0"}
    assert progress.snapshot_failure() == expected_failure


def test_capacity_timeout_is_incomplete_and_missing_requests_are_not_fail_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress = _progress()
    started = threading.Event()
    release = threading.Event()

    class Session:
        def observe(self, *_args: object) -> Observation:
            started.set()
            release.wait(timeout=2)
            return Observation("codex", "PreToolUse", "1k", 1.0, "native_resident", True)

    def observer(harness: str, event: str, size_class: str, stage: str) -> Observation:
        return benchmark._observe_with_progress(
            progress,
            cast(AdapterSession, session),
            harness,
            event,
            size_class,
            stage,
            fatal=False,
            record_submission=False,
        )

    session = Session()
    monkeypatch.setattr(capacity, "_CONCURRENT_WAVE_TIMEOUT_SECONDS", 0.01)
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        with pytest.raises(RuntimeError, match="concurrent capacity wave timed out") as raised:
            capacity._run_concurrent(
                cast(AdapterSession, session),
                (("codex", "PreToolUse"),),
                16,
                executor,
                observer=observer,
                stage="concurrent_16",
                on_submitted=progress.submit,
                on_cancelled=progress.cancel,
            )
        assert started.wait(timeout=1)
        progress.record_failure(raised.value, stage="concurrent_16", labels={"wave": "16"})
        stage = progress.stage_snapshot()["concurrent_16"]
        assert stage["submitted"] == 16
        assert stage["started"] == 1
        assert stage["attempted"] == 1
        assert stage["completed"] == 0
        assert stage["failed"] == 0
        assert stage["cancelled"] == 15
        assert stage["missing"] == 1
        assert progress.snapshot_failure()["category"] == "capacity_wave_timeout"
        assert progress.snapshot_failure()["stage"] == "concurrent_16"
    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_capacity_timeout_defers_finished_observations_but_keeps_running_work_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress = _progress()
    first_started = threading.Event()
    second_started = threading.Event()
    release = threading.Event()
    call_lock = threading.Lock()
    calls = 0

    class Session:
        def observe(self, *_args: object) -> Observation:
            nonlocal calls
            with call_lock:
                call_number = calls
                calls += 1
            if call_number == 0:
                first_started.set()
                return Observation("codex", "PreToolUse", "1k", 1.0, "native_resident", True)
            second_started.set()
            release.wait(timeout=2)
            return Observation("codex", "PreToolUse", "1k", 1.0, "native_resident", True)

    def observer(harness: str, event: str, size_class: str, stage: str) -> Observation:
        return benchmark._observe_with_progress(
            progress,
            cast(AdapterSession, session),
            harness,
            event,
            size_class,
            stage,
            fatal=False,
            record_submission=False,
            complete=False,
        )

    deferred: list[Observation] = []

    def record_deferred(observations: list[Observation]) -> None:
        deferred.extend(observations)
        progress.complete("capacity_prewarm", len(observations))

    session = Session()
    monkeypatch.setattr(capacity, "_CONCURRENT_WAVE_TIMEOUT_SECONDS", 0.05)
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        with pytest.raises(RuntimeError, match="concurrent capacity wave timed out"):
            capacity._run_concurrent(
                cast(AdapterSession, session),
                (("codex", "PreToolUse"),),
                3,
                executor,
                observer=observer,
                stage="capacity_prewarm",
                on_submitted=progress.submit,
                on_cancelled=progress.cancel,
                on_transport_observations=record_deferred,
            )
        assert first_started.is_set()
        assert second_started.is_set()
        assert len(deferred) == 1
        stage = progress.stage_snapshot()["capacity_prewarm"]
        assert stage["submitted"] == 3
        assert stage["started"] == 2
        assert stage["attempted"] == 2
        assert stage["completed"] == 1
        assert stage["cancelled"] == 1
        assert stage["missing"] == 14
    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_capacity_transport_failure_is_not_collapsed_into_completed_error_count() -> None:
    progress = _progress()

    class Session:
        def observe(self, *_args: object) -> Observation:
            raise RuntimeError("adapter request failed") from TimeoutError("fixture transport")

    session = Session()

    def observer(harness: str, event: str, size_class: str, stage: str) -> Observation:
        return benchmark._observe_with_progress(
            progress,
            cast(AdapterSession, session),
            harness,
            event,
            size_class,
            stage,
            fatal=False,
        )

    with ThreadPoolExecutor(max_workers=1) as executor, pytest.raises(
        RuntimeError, match="adapter request failed"
    ) as raised:
        capacity._run_concurrent(
            cast(AdapterSession, session),
            (("codex", "PreToolUse"),),
            1,
            executor,
            observer=observer,
            stage="concurrent_16",
        )

    progress.record_failure(raised.value, stage="concurrent_16", labels={"wave": "16"})
    stage = progress.stage_snapshot()["concurrent_16"]
    assert stage["attempted"] == 1
    assert stage["completed"] == 0
    assert stage["failed"] == 1
    assert stage["missing"] == 15
    assert progress.snapshot_failure()["category"] == "transport_timeout"


def test_capacity_prewarm_transport_preserves_returned_observation_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress = _progress()
    monkeypatch.setattr(capacity, "_STEADY_STATE_CONCURRENCY", 3)
    monkeypatch.setattr(capacity, "_prime_load_executor", lambda *_args: 3)

    class Session:
        def observe(self, harness: str, *_args: object) -> Observation:
            if harness == "transport":
                raise TimeoutError("adapter transport timed out")
            if harness == "semantic":
                return Observation("semantic", "PreToolUse", "1k", 1.0, "native_fail_safe", False)
            return Observation("resident", "PreToolUse", "1k", 1.0, "native_resident", True)

    session = Session()

    def observer(harness: str, event: str, size_class: str, stage: str) -> Observation:
        return benchmark._observe_with_progress(
            progress,
            cast(AdapterSession, session),
            harness,
            event,
            size_class,
            stage,
            fatal=False,
            record_submission=False,
            complete=False,
        )

    deferred_complete: list[tuple[str, int]] = []
    deferred_failure: list[tuple[str, int]] = []

    def complete(stage: str, count: int) -> None:
        deferred_complete.append((stage, count))
        progress.complete(stage, count)

    def fail(stage: str, count: int) -> None:
        deferred_failure.append((stage, count))
        progress.fail_request(stage, count)

    with pytest.raises(TimeoutError, match="adapter transport timed out"):
        capacity._prewarm_capacity_workers(
            cast(AdapterSession, session),
            (("resident", "PreToolUse"), ("transport", "PreToolUse"), ("semantic", "PreToolUse")),
            ready_workers=2,
            observer=observer,
            on_submitted=progress.submit,
            on_deferred_complete=complete,
            on_deferred_failure=fail,
        )

    stage = progress.stage_snapshot()["capacity_prewarm"]
    assert deferred_complete == [("capacity_prewarm", 1)]
    assert deferred_failure == [("capacity_prewarm", 1)]
    assert stage["submitted"] == 3
    assert stage["attempted"] == 3
    assert stage["completed"] == 1
    assert stage["failed"] == 2
    assert stage["missing"] == 13


def test_recovery_semantic_failure_is_failed_not_completed() -> None:
    progress = _progress()
    calls = 0

    def observe(*_args: object, **_kwargs: object) -> Observation:
        nonlocal calls
        calls += 1
        if calls == 1:
            return Observation("claude-code", "PostToolUse", "1k", 1.0, "native_resident", True)
        return Observation("claude-code", "PostToolUse", "1k", 1.0, "native_fail_safe", False)

    session = _FixtureObject(observe=observe, stop_resident=lambda **_kwargs: True)
    with pytest.raises(RuntimeError, match="recovery sample 0 failed"):
        benchmark._run_recovery(cast(AdapterSession, session), 1, progress=progress)

    stage = progress.stage_snapshot()["recovery"]
    assert stage["submitted"] == 1
    assert stage["started"] == 1
    assert stage["attempted"] == 1
    assert stage["completed"] == 0
    assert stage["failed"] == 1
    assert stage["missing"] == 1
    assert progress.snapshot_failure()["stage"] == "recovery"


def test_recovery_precondition_semantic_failure_is_failed_not_completed() -> None:
    progress = _progress()
    session = _FixtureObject(
        observe=lambda *_args, **_kwargs: Observation(
            "claude-code", "PostToolUse", "1k", 1.0, "native_fail_safe", False
        ),
        stop_resident=lambda **_kwargs: True,
    )

    with pytest.raises(RuntimeError, match="was not resident before stop"):
        benchmark._run_recovery(cast(AdapterSession, session), 1, progress=progress)

    stage = progress.stage_snapshot()["recovery_precondition"]
    assert stage["submitted"] == 1
    assert stage["started"] == 1
    assert stage["attempted"] == 1
    assert stage["completed"] == 0
    assert stage["failed"] == 1
    assert stage["missing"] == 1
    assert progress.snapshot_failure()["stage"] == "recovery_precondition"


def test_installed_corpus_failure_is_aggregate_with_routes_unattempted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    progress = SloProgress()
    monkeypatch.setattr(benchmark, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(benchmark, "_runtime_summary", lambda _runtime: {"package_origin": "installed"})
    monkeypatch.setattr(benchmark, "_installed_corpus", lambda *_args: (_ for _ in ()).throw(TimeoutError("transport")))

    with pytest.raises(TimeoutError, match="transport"):
        benchmark.run_slo(
            tmp_path / "runtime",
            warm_iterations=1,
            cold_iterations=1,
            recovery_iterations=1,
            readiness_samples=1,
            include_capacity=False,
            progress=progress,
        )

    stages = progress.stage_snapshot()
    assert stages["installed_corpus"] == {
        "planned": 1,
        "submitted": 1,
        "started": 1,
        "attempted": 1,
        "completed": 0,
        "failed": 1,
        "cancelled": 0,
        "missing": 0,
        "skipped": False,
    }
    assert stages["installed_corpus_routes"]["attempted"] == 0
    assert stages["installed_corpus_routes"]["missing"] == len(progress.routes)
    assert progress.snapshot_failure()["stage"] == "installed_corpus"


def test_failure_labels_use_allowlisted_unknown_category() -> None:
    progress = _progress()
    progress.record_failure(
        RuntimeError("bounded"),
        stage="arbitrary_stage",
        labels={
            "harness": "untrusted-harness",
            "event": "OtherEvent",
            "size_class": "not-a-size",
            "wave": "arbitrary-wave",
        },
    )

    assert progress.snapshot_failure() == {
        "stage": "unknown",
        "category": "benchmark_internal_failure",
        "harness": "unknown",
        "event": "unknown",
        "size_class": "unknown",
        "wave": "unknown",
    }


def test_cli_writes_bounded_failure_artifact_and_returns_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"runtime")
    output = tmp_path / "slo.json"

    def fail(_runtime: Path, **kwargs: object) -> dict[str, object]:
        progress = cast(SloProgress, kwargs["progress"])
        progress.configure(
            (("codex", "PreToolUse"),),
            warm_iterations=1,
            cold_iterations=1,
            recovery_iterations=1,
            readiness_samples=1,
            include_capacity=False,
        )
        raise RuntimeError("adapter request failed /fixture/request") from TimeoutError("fixture transport")

    monkeypatch.setattr(benchmark, "run_slo", fail)
    monkeypatch.setattr(
        sys,
        "argv",
        ["bench_guard_native_installed_slo.py", "--runtime", str(runtime), "--json", str(output)],
    )

    assert benchmark.main() == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["scope"] == "installed_adapter_to_decision"
    assert report["status"] == "failed"
    assert report["evaluation"] == "incomplete"
    assert report["passed"] is False
    assert all(value is False for value in report["gates"].values())
    assert report["failure"]["category"] == "transport_timeout"
    encoded = output.read_text(encoding="utf-8")
    assert str(runtime) not in encoded
    assert "adapter request failed" not in encoded
    assert "fixture transport" not in encoded
    assert "fixture/request" not in encoded
    assert "Traceback" in capsys.readouterr().err


def test_successful_result_contract_retains_existing_scope_thresholds_and_gate_names() -> None:
    observation = Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)
    measurements = SloMeasurements(
        warm=[observation],
        sizes=[
            Observation("codex", "PostToolUse", "250k", 1.0, "native_resident", True),
            Observation("codex", "PostToolUse", "1m", 1.0, "native_resident", True),
            Observation("codex", "PostToolUse", "5m", 1.0, "native_resident", True),
        ],
        recovery=[1.0],
        cold=[1.0],
        concurrent_16=[observation],
        concurrent_64=[observation],
        errors_16=0,
        errors_64=0,
        readiness=[1.0],
        rss_baseline=1,
        rss_peak=1,
    )
    summary = summarize_measurements(measurements)
    corpus = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}
    gates = slo_gates(measurements, summary, corpus, 1, include_capacity=True)
    result = slo_result(
        {"mode": "auto", "package_origin": "installed"},
        (("codex", "PostToolUse"),),
        corpus,
        measurements,
        summary,
        gates,
    )

    assert result["schema"] == "hol-guard.native-installed-slo.v1"
    assert result["scope"] == "installed_adapter_to_decision"
    assert "status" not in result
    assert "complete" not in result
    assert result["thresholds"] == {
        "installed_adapter_p95_ms": MAX_INSTALLED_ADAPTER_P95_MS,
        "installed_adapter_concurrent_p99_ms": MAX_INSTALLED_ADAPTER_P99_MS,
        "direct_cold_p95_ms": MAX_COLD_P95_MS,
        "readiness_p95_ms": MAX_READINESS_P95_MS,
    }
    assert set(cast(dict[str, bool], result["gates"])) == {
        "resident_share",
        "safe_corpus",
        "warm_latency",
        "250k_latency",
        "1m_latency",
        "5m_latency",
        "cold_latency",
        "readiness",
        "concurrency",
        "rss",
        "python_fallback",
        "recovery_latency",
        "concurrency_64_bounded",
        "installed_corpus",
    }


def test_runtime_summary_reports_bounded_environment_and_pinned_artifact_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from scripts import bench_guard_native_installed_slo_runtime as runtime_checks

    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    identity = _FixtureObject(path=runtime, size=runtime.stat().st_size, sha256="a" * 64)
    capabilities = _FixtureObject(
        target="aarch64-apple-darwin",
        runtime_version="3.13.1",
        protocol_version=1,
        build_sha="b" * 40,
        rule_digest="c" * 64,
    )
    status = _FixtureObject(
        mode="auto",
        available=True,
        compatible=True,
        reason="native_ready",
        identity=identity,
        capabilities=capabilities,
        platform_tag="macosx_11_0_arm64",
    )
    monkeypatch.setattr(runtime_checks, "native_mode", lambda: "auto")
    monkeypatch.setattr(runtime_checks, "native_runtime_status", lambda: status)
    monkeypatch.setattr(runtime_checks, "hook_fast_path_enabled", lambda: True)
    monkeypatch.setattr(
        runtime_checks.codex_plugin_scanner,
        "__file__",
        "/fixture/site-packages/codex_plugin_scanner/__init__.py",
    )

    summary = runtime_checks._runtime_summary(runtime)

    assert summary["package_origin"] == "installed"
    assert summary["runtime_sha256"] == "a" * 64
    assert summary["runtime_size_bytes"] == 7
    assert summary["build_sha"] == "b" * 40
    assert summary["rule_digest"] == "c" * 64
    assert summary["target"] == "aarch64-apple-darwin"
    assert summary["platform_tag"] == "macosx_11_0_arm64"
    assert summary["host_os"]
    assert summary["host_machine"]
    assert summary["python_implementation"]
    assert summary["python_version"]
    assert "/" not in json.dumps(summary)
