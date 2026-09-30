#!/usr/bin/env python3
"""Measure installed adapter-to-decision native runtime SLOs.

Synthetic requests cross the daemon adapter boundary; output is aggregate-only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

_PROBE_SPEC = importlib.util.spec_from_file_location(
    "hol_guard_installed_default_probe",
    _REPO_ROOT / "ci/native_runtime/probe_native_default_auto.py",
)
if _PROBE_SPEC is None or _PROBE_SPEC.loader is None:
    raise RuntimeError("native_installed_slo_failed: installed hook probe could not be loaded")
_PROBE_MODULE = importlib.util.module_from_spec(_PROBE_SPEC)
_PROBE_SPEC.loader.exec_module(_PROBE_MODULE)
_installed_hook_corpus = _PROBE_MODULE._installed_hook_corpus
from scripts.bench_guard_native_installed_slo_runtime import (  # noqa: E402
    _clear_proof_overrides,
    _readiness_samples,
    _require,
    _runtime_summary,
    runtime_environment_summary,
)
from scripts.native_slo_adapter import (  # noqa: E402
    Observation,
    payload,
    process_rss_bytes,
    route_matrix,
    source_payloads,
)
from scripts.native_slo_baseline import (  # noqa: E402, F401
    steady_state_rss_baseline as _steady_state_rss_baseline,
)
from scripts.native_slo_capacity import (  # noqa: E402, F401
    _stabilize_ready_hook_workers,
    measure_capacity,
)
from scripts.native_slo_contract import SAFE_ROUTE_NAMES, SIZE_CLASSES  # noqa: E402
from scripts.native_slo_reporting import (  # noqa: E402
    SloMeasurements,
    SloProgress,
    incomplete_slo_result,
    safe_failure_rate,
    slo_gates,
    slo_result,
    summarize_measurements,
)
from scripts.native_slo_session import AdapterSession, stop_native_resident  # noqa: E402

_DEFAULT_WARM_ITERATIONS = 2
_DEFAULT_COLD_ITERATIONS = 3
_DEFAULT_RECOVERY_ITERATIONS = 3
_MAX_READINESS_SAMPLES = 8
_INSTALLED_WHEEL_OWNERSHIP_CONTRACT = "installed_wheel_ownership_contract"

# Keep historical private imports available to contract tests and downstream tooling.
_safe_failure_rate = safe_failure_rate


def _prepare_progress(
    progress: SloProgress,
    *,
    warm_iterations: int,
    cold_iterations: int,
    recovery_iterations: int,
    readiness_samples: int,
    include_capacity: bool,
) -> None:
    """Plan invocation work before proof, runtime, or route preflight runs."""

    progress.configure(
        (),
        warm_iterations=warm_iterations,
        cold_iterations=cold_iterations,
        recovery_iterations=recovery_iterations,
        readiness_samples=readiness_samples,
        include_capacity=include_capacity,
        route_count=None,
    )
    progress.runtime_summary = runtime_environment_summary()


def _run_preflight(progress: SloProgress, stage: str, action: Callable[[], object]) -> object:
    progress.activate(stage)
    progress.submit(stage)
    progress.attempt(stage)
    try:
        result = action()
    except Exception as error:
        progress.fail_request(stage)
        progress.record_failure(error, stage=stage)
        raise
    else:
        progress.complete(stage)
        return result


def _observe_with_progress(
    progress: SloProgress,
    session: AdapterSession,
    harness: str,
    event: str,
    size_class: str,
    stage: str,
    request_payload: Mapping[str, object] | None = None,
    *,
    fatal: bool = True,
    record_attempt: bool = True,
    record_submission: bool = True,
    complete: bool = True,
) -> Observation:
    """Observe one request while retaining only bounded failure metadata."""

    progress.activate(stage, harness=harness, event=event, size_class=size_class)
    if record_attempt:
        if record_submission:
            progress.submit(stage)
        progress.attempt(stage)
    try:
        observation = session.observe(harness, event, size_class, request_payload)
    except Exception as error:
        progress.fail_request(stage)
        if fatal:
            progress.record_failure(
                error,
                stage=stage,
                labels={"harness": harness, "event": event, "size_class": size_class},
            )
        raise
    if complete:
        progress.complete(stage)
    return observation


def _installed_corpus(runtime: Path, expected_routes: int) -> dict[str, int]:
    """Exercise the canonical all-harness installed ingress corpus."""

    with tempfile.TemporaryDirectory(prefix="hol-guard-installed-corpus-") as temporary:
        root = Path(temporary)
        report: Mapping[str, object] | None = None
        try:
            candidate = _installed_hook_corpus(root)
            if isinstance(candidate, Mapping):
                report = candidate
        finally:
            stop_native_resident(runtime, root / "hook-home")
        if report is None:
            raise RuntimeError("native_installed_slo_failed: installed all-harness corpus returned no aggregate")
        values_by_name: dict[str, object] = {}
        for name in (
            "route_count",
            "native_resident_decisions",
            "native_oneshot_decisions",
            "fail_safe_decisions",
            "python_semantic_decisions",
        ):
            if name not in report:
                raise RuntimeError(f"native_installed_slo_failed: installed corpus omitted {name}")
            values_by_name[name] = report[name]
        route_count = values_by_name["route_count"]
        resident = values_by_name["native_resident_decisions"]
        oneshot = values_by_name["native_oneshot_decisions"]
        fail_safe = values_by_name["fail_safe_decisions"]
        python_semantic = values_by_name["python_semantic_decisions"]
        values = (route_count, resident, oneshot, fail_safe, python_semantic)
        if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values):
            raise RuntimeError("native_installed_slo_failed: installed corpus aggregate was invalid")
        route_count = cast(int, route_count)
        resident = cast(int, resident)
        oneshot = cast(int, oneshot)
        fail_safe = cast(int, fail_safe)
        python_semantic = cast(int, python_semantic)
        _require(route_count == expected_routes, "installed corpus did not cover every declared route")
        _require(resident == expected_routes, "installed corpus did not stay resident")
        _require(oneshot == 0 and fail_safe == 0 and python_semantic == 0, "installed corpus left the native route")
        return {
            "routes": route_count,
            "resident": resident,
            "oneshot": oneshot,
            "fail_safe": fail_safe,
            "python_semantic": python_semantic,
            "python_semantic_decisions": python_semantic,
        }


def _run_warm(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    iterations: int,
    *,
    progress: SloProgress | None = None,
) -> list[Observation]:
    for harness, event in routes:
        if progress is None:
            session.observe(harness, event, "1k")
        else:
            _observe_with_progress(progress, session, harness, event, "1k", "warm_precondition")
    observations: list[Observation] = []
    for _ in range(iterations):
        for harness, event in routes:
            if progress is None:
                observations.append(session.observe(harness, event, "1k"))
            else:
                observations.append(_observe_with_progress(progress, session, harness, event, "1k", "warm"))
    return observations


def _run_sizes(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    *,
    progress: SloProgress | None = None,
) -> list[Observation]:
    post_routes = tuple((harness, event) for harness, event in routes if event == "PostToolUse")
    selected = post_routes or (routes[0],)
    large_payloads = source_payloads(session.workspace)
    observations: list[Observation] = []
    for size_class in SIZE_CLASSES[1:]:
        request_payload = large_payloads[size_class]
        for harness, event in selected:
            if progress is None:
                observations.append(session.observe(harness, event, size_class, request_payload))
            else:
                observations.append(
                    _observe_with_progress(
                        progress,
                        session,
                        harness,
                        event,
                        size_class,
                        f"size_{size_class}",
                        request_payload,
                    )
                )
    return observations


def _wire_request(workspace: Path, guard_home: Path, request_id: str) -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": payload("PostToolUse", "1k"),
            "guard_remaining_ms": 1_000,
            "cwd": str(workspace),
            "home_dir": str(workspace),
            "guard_home": str(guard_home),
            "source_ref_external_allowed": False,
            "observe_mode": False,
            "deadline_budget_ms": 5_000,
        },
        separators=(",", ":"),
    )


def _run_cold(
    runtime: Path,
    session: AdapterSession,
    iterations: int,
    *,
    progress: SloProgress | None = None,
) -> list[float]:
    values: list[float] = []
    environment = {
        "HOME": str(session.workspace),
        "TMPDIR": tempfile.gettempdir(),
        **{key: value for key in ("LANG", "LC_ALL") if (value := os.environ.get(key))},
    }
    request = _wire_request(session.workspace, session.guard_home, "native-slo-cold")
    for index in range(iterations):
        if progress is not None:
            progress.activate("cold", size_class="1k", wave=str(index))
            progress.submit("cold")
            progress.attempt("cold")
        try:
            _require(session.stop_resident(), "cold native resident stop was not contained")
            started = time.perf_counter()
            completed = subprocess.run(
                (str(runtime), "hook", "--stdin"),
                input=request.encode("utf-8"),
                cwd=runtime.parent,
                env=environment,
                capture_output=True,
                check=False,
                timeout=5,
            )
            elapsed_ms = (time.perf_counter() - started) * 1_000.0
            _require(completed.returncode == 0, "cold native one-shot failed")
            try:
                response = json.loads(completed.stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise RuntimeError("cold native one-shot returned invalid JSON") from error
            _require(isinstance(response, Mapping) and response.get("decision") == "allow", "cold decision was unsafe")
            values.append(elapsed_ms)
        except Exception as error:
            if progress is not None:
                progress.fail_request("cold")
                progress.record_failure(error, stage="cold", labels={"size_class": "1k", "wave": str(index)})
            raise
        else:
            if progress is not None:
                progress.complete("cold")
    return values


def _run_recovery(
    session: AdapterSession,
    iterations: int,
    *,
    progress: SloProgress | None = None,
) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        labels = {"harness": "claude-code", "event": "PostToolUse", "size_class": "1k", "wave": str(index)}
        deferred_precondition = False
        deferred_observation = False
        try:
            if progress is None:
                warm = session.observe("claude-code", "PostToolUse", "1k")
            else:
                warm = _observe_with_progress(
                    progress,
                    session,
                    "claude-code",
                    "PostToolUse",
                    "1k",
                    "recovery_precondition",
                    complete=False,
                )
                deferred_precondition = True
            _require(
                warm.allowed and warm.route == "native_resident",
                f"recovery sample {index} was not resident before stop",
            )
            if deferred_precondition and progress is not None:
                progress.complete("recovery_precondition")
                deferred_precondition = False
            if progress is not None:
                progress.activate("recovery", **labels)
            _require(
                # A resident restart leaves the installed adapter's persistent
                # Rust client alive. That stream re-discovers/authenticates the
                # new generation on the next request; destroying it here would
                # add a separate client cold start to the resident recovery SLO.
                session.stop_resident(preserve_clients=True),
                f"resident stop failed during recovery sample {index}",
            )
            started = time.perf_counter()
            if progress is None:
                observation = session.observe("claude-code", "PostToolUse", "1k")
            else:
                observation = _observe_with_progress(
                    progress,
                    session,
                    "claude-code",
                    "PostToolUse",
                    "1k",
                    "recovery",
                    complete=False,
                )
                deferred_observation = True
            elapsed_ms = (time.perf_counter() - started) * 1_000.0
            print(
                json.dumps(
                    {
                        "schema": "hol-guard.native-recovery-sample.v1",
                        "sample": index,
                        "adapter_ms": round(observation.latency_ms, 3),
                        "elapsed_ms": round(elapsed_ms, 3),
                        "route": observation.route,
                        "allowed": observation.allowed,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
            _require(observation.allowed and observation.route == "native_resident", f"recovery sample {index} failed")
            if progress is not None:
                progress.complete("recovery")
            values.append(elapsed_ms)
        except Exception as error:
            if progress is not None:
                if deferred_precondition:
                    progress.fail_request("recovery_precondition")
                if deferred_observation:
                    progress.fail_request("recovery")
                progress.record_failure(error, stage=progress.active_stage or "recovery", labels=labels)
            raise
    return values


def _run_serialized_warmup(
    session: AdapterSession,
    harness: str,
    event: str,
    *,
    progress: SloProgress | None = None,
) -> None:
    observed = False
    if progress is None:
        observation = session.observe(harness, event, "1k")
    else:
        observation = _observe_with_progress(
            progress,
            session,
            harness,
            event,
            "1k",
            "serialized_warmup",
            complete=False,
        )
        observed = True
    passed = observation.allowed and observation.route == "native_resident"
    if not passed:
        from codex_plugin_scanner.guard.native_approval_errors import NATIVE_COMMAND_CONTROL_ERROR_CODES

        publisher = session.daemon._server.hook_worker.policy_snapshot_publisher
        error = publisher.last_error
        reasons = NATIVE_COMMAND_CONTROL_ERROR_CODES | {
            "native_policy_snapshot_resident_changed",
            "native_policy_snapshot_expired",
            "native_policy_snapshot_runtime_unavailable",
            "native_policy_snapshot_publish_failed",
            "native_policy_snapshot_native_disabled",
            "native_policy_snapshot_protocol_unsupported",
        }
        binding = publisher.current_snapshot_binding()
        generation = binding.get("generation") if isinstance(binding, dict) else None
        print(
            json.dumps(
                {
                    "schema": "hol-guard.native-serialized-warmup-failure.v1",
                    "route": observation.route if observation.route in SAFE_ROUTE_NAMES else "unknown",
                    "allowed": observation.allowed,
                    "adapter_ms": round(observation.latency_ms, 3),
                    "publisher_error": error if error in reasons else None,
                    "publisher_ready": binding is not None,
                    "policy_generation": generation if type(generation) is int and 0 <= generation < 2**64 else None,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
    try:
        _require(passed, "serialized resident pool warmup did not stay on the allowed native route")
    except Exception as error:
        if progress is not None:
            if observed:
                progress.fail_request("serialized_warmup")
            progress.record_failure(error, stage="serialized_warmup", labels={"harness": harness, "event": event})
        raise
    else:
        if progress is not None:
            progress.complete("serialized_warmup")


def _measure_slo(
    runtime: Path,
    routes: tuple[tuple[str, str], ...],
    *,
    warm_iterations: int,
    cold_iterations: int,
    recovery_iterations: int,
    readiness_samples: int,
    include_capacity: bool,
    progress: SloProgress | None = None,
) -> SloMeasurements:
    # Cold probes stop the session's resident before each one-shot call. Keep
    # them separate so this lifecycle exercise does not consume the bounded
    # restart budget used by warmup and recovery.
    cold_start_pending = False
    if progress is not None:
        progress.activate("cold_start", size_class="1k")
        progress.submit("cold_start")
        progress.attempt("cold_start")
        cold_start_pending = True
    try:
        with AdapterSession(runtime) as cold_session:
            if progress is not None:
                progress.complete("cold_start")
                cold_start_pending = False
            cold = _run_cold(runtime, cold_session, cold_iterations, progress=progress)
    except Exception as error:
        if progress is not None and cold_start_pending:
            progress.fail_request("cold_start")
            progress.record_failure(error, stage="cold_start", labels={"size_class": "1k"})
        raise

    readiness_start_pending = False
    if progress is not None:
        progress.activate("readiness_start", wave="0")
        progress.submit("readiness_start")
        progress.attempt("readiness_start")
        readiness_start_pending = True
    readiness_first_sample_pending = False
    try:
        with AdapterSession(runtime) as session:
            if progress is not None:
                progress.complete("readiness_start")
                readiness_start_pending = False
                progress.activate("warm")
            warm = _run_warm(session, routes, warm_iterations, progress=progress)
            sizes = _run_sizes(session, routes, progress=progress)
            recovery = _run_recovery(session, recovery_iterations, progress=progress)
            warmup_harness, warmup_event = routes[0]
            _run_serialized_warmup(session, warmup_harness, warmup_event, progress=progress)
            if progress is not None:
                progress.activate("capacity_stabilization")

            def observe_capacity(harness: str, event: str, size_class: str, stage: str) -> Observation:
                if progress is None:
                    return session.observe(harness, event, size_class)
                return _observe_with_progress(
                    progress,
                    session,
                    harness,
                    event,
                    size_class,
                    stage,
                    fatal=False,
                    record_submission=False,
                    complete=stage != "capacity_prewarm",
                )

            def progress_submitted(stage: str, count: int) -> None:
                if progress is not None:
                    progress.submit(stage, count)

            def progress_cancelled(stage: str, count: int) -> None:
                if progress is not None:
                    progress.cancel(stage, count)

            def progress_deferred_complete(stage: str, count: int) -> None:
                if progress is not None:
                    progress.complete(stage, count)

            def progress_deferred_failure(stage: str, count: int) -> None:
                if progress is not None:
                    progress.fail_request(stage, count)

            capacity = measure_capacity(
                session,
                routes,
                include_capacity=include_capacity,
                observer=observe_capacity if progress is not None else None,
                on_submitted=progress_submitted if progress is not None else None,
                on_cancelled=progress_cancelled if progress is not None else None,
                on_deferred_complete=progress_deferred_complete if progress is not None else None,
                on_deferred_failure=progress_deferred_failure if progress is not None else None,
            )
            if progress is not None:
                progress.activate("readiness", wave="0")
                progress.submit("readiness")
                progress.attempt("readiness")
                readiness_first_sample_pending = True
            readiness = [session.readiness_ms]
            readiness_first_sample_pending = False
            if progress is not None:
                progress.complete("readiness")
    except Exception as error:
        if progress is not None:
            if readiness_start_pending:
                progress.fail_request("readiness_start")
                progress.record_failure(error, stage="readiness_start", labels={"wave": "0"})
            elif progress.active_stage == "readiness" and readiness_first_sample_pending:
                progress.fail_request("readiness")
                progress.record_failure(error, stage="readiness", labels={"wave": "0"})
            elif progress.failure is None:
                # Phase helpers normally account for their own request. Keep
                # an early phase-level exception attributable when it occurs
                # before a helper can establish request accounting.
                progress.record_failure(error, stage=progress.active_stage)
        raise
    if readiness_samples > 1:
        if progress is not None:
            progress.activate("readiness")
        try:
            readiness.extend(
                _readiness_samples(
                    runtime,
                    readiness_samples - 1,
                    progress_submit=(progress.submit if progress is not None else None),
                    progress_attempt=(progress.attempt if progress is not None else None),
                    progress_complete=(progress.complete if progress is not None else None),
                )
            )
        except Exception as error:
            if progress is not None:
                progress.fail_request("readiness")
                progress.record_failure(error, stage="readiness")
            raise
    rss_peak = max(capacity.rss_peak, process_rss_bytes())
    return SloMeasurements(
        warm=warm,
        sizes=sizes,
        recovery=recovery,
        cold=cold,
        concurrent_16=capacity.concurrent_16,
        concurrent_64=capacity.concurrent_64,
        errors_16=capacity.errors_16,
        errors_64=capacity.errors_64,
        readiness=readiness,
        rss_baseline=capacity.rss_baseline,
        rss_peak=rss_peak,
    )


def run_slo(
    runtime: Path,
    *,
    warm_iterations: int,
    cold_iterations: int,
    recovery_iterations: int,
    readiness_samples: int,
    include_capacity: bool,
    progress: SloProgress | None = None,
) -> dict[str, object]:
    progress = progress or SloProgress()
    _prepare_progress(
        progress,
        warm_iterations=warm_iterations,
        cold_iterations=cold_iterations,
        recovery_iterations=recovery_iterations,
        readiness_samples=readiness_samples,
        include_capacity=include_capacity,
    )
    _run_preflight(progress, "proof_environment", _clear_proof_overrides)
    runtime_summary = cast(
        dict[str, object],
        _run_preflight(progress, "runtime_provenance", lambda: _runtime_summary(runtime)),
    )
    progress.runtime_summary = runtime_summary
    routes = cast(tuple[tuple[str, str], ...], _run_preflight(progress, "route_contract", route_matrix))
    progress.configure(
        routes,
        warm_iterations=warm_iterations,
        cold_iterations=cold_iterations,
        recovery_iterations=recovery_iterations,
        readiness_samples=readiness_samples,
        include_capacity=include_capacity,
        route_count=len(routes),
    )
    progress.activate("installed_corpus")
    progress.submit("installed_corpus")
    progress.attempt("installed_corpus")
    try:
        installed_corpus = _installed_corpus(runtime, len(routes))
    except Exception as error:
        progress.fail_request("installed_corpus")
        progress.record_failure(error, stage="installed_corpus")
        raise
    progress.complete("installed_corpus")
    progress.submit("installed_corpus_routes", len(routes))
    progress.attempt("installed_corpus_routes", len(routes))
    progress.complete("installed_corpus_routes", len(routes))
    progress.installed_corpus = installed_corpus
    measurements = _measure_slo(
        runtime,
        routes,
        warm_iterations=warm_iterations,
        cold_iterations=cold_iterations,
        recovery_iterations=recovery_iterations,
        readiness_samples=readiness_samples,
        include_capacity=include_capacity,
        progress=progress,
    )
    summary = summarize_measurements(measurements)
    gates = slo_gates(
        measurements,
        summary,
        installed_corpus,
        len(routes),
        include_capacity=include_capacity,
    )
    return slo_result(
        runtime_summary,
        routes,
        installed_corpus,
        measurements,
        summary,
        gates,
        corpus_origin=_INSTALLED_WHEEL_OWNERSHIP_CONTRACT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--warm-iterations", type=int, default=_DEFAULT_WARM_ITERATIONS)
    parser.add_argument("--cold-iterations", type=int, default=_DEFAULT_COLD_ITERATIONS)
    parser.add_argument("--recovery-iterations", type=int, default=_DEFAULT_RECOVERY_ITERATIONS)
    parser.add_argument("--readiness-samples", type=int, default=3)
    parser.add_argument("--skip-capacity", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.warm_iterations <= 0 or args.cold_iterations <= 0 or args.recovery_iterations <= 0:
        parser.error("iteration counts must be positive")
    if not 1 <= args.readiness_samples <= _MAX_READINESS_SAMPLES:
        parser.error("readiness samples must be between one and eight")
    progress = SloProgress()
    execution_failed = False
    try:
        _prepare_progress(
            progress,
            warm_iterations=args.warm_iterations,
            cold_iterations=args.cold_iterations,
            recovery_iterations=args.recovery_iterations,
            readiness_samples=args.readiness_samples,
            include_capacity=not args.skip_capacity,
        )
        progress.activate("runtime_input")
        progress.submit("runtime_input")
        progress.attempt("runtime_input")
        try:
            runtime = args.runtime.expanduser().resolve(strict=True)
            _require(runtime.is_file() and not args.runtime.is_symlink(), "runtime must be a regular non-symlink file")
        except Exception as error:
            progress.fail_request("runtime_input")
            progress.record_failure(error, stage="runtime_input")
            raise
        else:
            progress.complete("runtime_input")
        result = run_slo(
            runtime,
            warm_iterations=args.warm_iterations,
            cold_iterations=args.cold_iterations,
            recovery_iterations=args.recovery_iterations,
            readiness_samples=args.readiness_samples,
            include_capacity=not args.skip_capacity,
            progress=progress,
        )
    except Exception as error:
        execution_failed = True
        # Any failure that escapes a stage-specific handler has no trustworthy
        # phase or request labels. Keep the fallback explicitly unknown rather
        # than reusing a stale active stage from an earlier phase.
        progress.record_failure(
            error,
            stage="unknown",
            labels={"harness": "unknown", "event": "unknown", "size_class": "unknown", "wave": "unknown"},
        )
        result = incomplete_slo_result(progress, include_capacity=not args.skip_capacity)
        # Preserve the existing detailed operator traceback on stderr while
        # keeping the persisted aggregate free of exception text and paths.
        import traceback

        traceback.print_exc()
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.write_text(rendered + "\n", encoding="utf-8")
    if execution_failed:
        return 1
    return 0 if not args.enforce or result.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
