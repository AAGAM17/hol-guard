"""Aggregate and render installed native-runtime SLO observations."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from threading import RLock

from scripts.native_slo_adapter import Observation
from scripts.native_slo_contract import (
    MAX_COLD_P95_MS,
    MAX_INSTALLED_ADAPTER_P95_MS,
    MAX_INSTALLED_ADAPTER_P99_MS,
    MAX_READINESS_P95_MS,
    SAFE_EVENT_NAMES,
    SAFE_FAILURE_STAGE_NAMES,
    SAFE_FAILURE_WAVE_NAMES,
    SAFE_HARNESS_NAMES,
    SAFE_ROUTE_NAMES,
    SAFE_SIZE_CLASS_NAMES,
    SIZE_CLASSES,
    SLO_SCHEMA,
    all_gates_pass,
    assert_privacy_safe,
    gate_results,
    summarize,
)


@dataclass(frozen=True)
class SloMeasurements:
    warm: list[Observation]
    sizes: list[Observation]
    recovery: list[float]
    cold: list[float]
    concurrent_16: list[Observation]
    concurrent_64: list[Observation]
    errors_16: int
    errors_64: int
    readiness: list[float]
    rss_baseline: int
    rss_peak: int


@dataclass
class SloProgressStage:
    """Bounded counters for one benchmark stage.

    ``planned`` is ``None`` for stages such as RSS plateau sampling whose
    reviewed contract is time-bounded rather than a fixed request count.
    Missing work is derived from completed and failed requests so a timed-out
    concurrent wave cannot be mistaken for a complete wave.
    """

    planned: int | None = None
    submitted: int = 0
    started: int = 0
    attempted: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    skipped: bool = False

    def snapshot(self) -> dict[str, object]:
        missing = (
            None
            if self.planned is None
            else max(0, self.planned - self.completed - self.failed - self.cancelled)
        )
        return {
            "planned": self.planned,
            "submitted": self.submitted,
            "started": self.started,
            "attempted": self.attempted,
            "completed": self.completed,
            "failed": self.failed,
            "cancelled": self.cancelled,
            "missing": missing,
            "skipped": self.skipped,
        }


_OBSERVATION_PROGRESS_STAGES = frozenset(
    {
        "warm",
        "size_250k",
        "size_1m",
        "size_5m",
        "concurrent_16",
        "concurrent_64",
    }
)


def classify_benchmark_error(error: BaseException) -> str:
    """Map an internal failure to a bounded, privacy-safe diagnostic code."""

    chain: list[BaseException] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(chain) < 8:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__

    if any(isinstance(item, TimeoutError) for item in chain):
        return "transport_timeout"
    if any("concurrent capacity wave timed out" in str(item) for item in chain):
        return "capacity_wave_timeout"
    if any("adapter response exceeded bound" in str(item) for item in chain):
        return "response_oversize"
    if any("adapter response was not JSON" in str(item) for item in chain):
        return "response_invalid"
    if any("adapter response was not an object" in str(item) for item in chain):
        return "response_invalid"
    if any(str(item) == "adapter request failed" for item in chain):
        return "response_status"
    if any(
        isinstance(item, OSError)
        or item.__class__.__name__ in {"HTTPException", "TimeoutExpired"}
        for item in chain
    ):
        if any(item.__class__.__name__ == "TimeoutExpired" for item in chain):
            return "transport_timeout"
        return "transport_error"
    if any(isinstance(item, RuntimeError) and str(item).startswith("native_installed_slo_failed") for item in chain):
        return "benchmark_contract"
    return "benchmark_internal_failure"


@dataclass
class SloProgress:
    """Thread-safe, aggregate-only progress for a potentially failed run."""

    stages: dict[str, SloProgressStage] = field(default_factory=dict)
    routes: tuple[tuple[str, str], ...] = ()
    route_count: int | None = None
    runtime_summary: dict[str, object] | None = None
    installed_corpus: dict[str, int] | None = None
    active_stage: str | None = None
    active_labels: dict[str, str] = field(default_factory=dict)
    failure: dict[str, object] | None = None
    _lock: RLock = field(default_factory=RLock, repr=False)

    def configure(
        self,
        routes: tuple[tuple[str, str], ...],
        *,
        warm_iterations: int,
        cold_iterations: int,
        recovery_iterations: int,
        readiness_samples: int,
        include_capacity: bool,
        route_count: int | None = None,
    ) -> None:
        """Install the fixed stage denominators before any work begins."""

        known_route_count = len(routes) if routes else route_count
        post_routes = sum(event == "PostToolUse" for _, event in routes) if known_route_count is not None else 0
        selected_size_routes = (
            None
            if known_route_count is None
            else post_routes or (1 if known_route_count else 0)
        )
        with self._lock:
            self.routes = routes
            self.route_count = known_route_count
            self._plan("proof_environment", 1)
            self._plan("runtime_provenance", 1)
            self._plan("route_contract", 1)
            # The installed corpus helper is one bounded aggregate operation;
            # its route denominator is kept separately so a pre-request
            # failure cannot claim every route was attempted.
            self._plan("installed_corpus", 1)
            self._plan("installed_corpus_routes", known_route_count)
            self._plan("cold_start", 1)
            self._plan("cold", cold_iterations)
            self._plan("warm_precondition", known_route_count)
            self._plan(
                "warm",
                known_route_count * warm_iterations if known_route_count is not None else None,
            )
            for size_class in SIZE_CLASSES[1:]:
                self._plan(f"size_{size_class}", selected_size_routes)
            self._plan("recovery_precondition", recovery_iterations)
            self._plan("recovery", recovery_iterations)
            self._plan("serialized_warmup", 1)
            self._plan("capacity_stabilization", 0)
            self._plan("capacity_prewarm", 16 if include_capacity else 0, skipped=not include_capacity)
            self._plan("concurrent_16", 16 if include_capacity else 0, skipped=not include_capacity)
            # The RSS baseline still runs in skip-capacity mode because the
            # existing runner measures it independently of c16/c64.
            self._plan("rss_baseline", None)
            self._plan("concurrent_64", 64 if include_capacity else 0, skipped=not include_capacity)
            self._plan("readiness_start", 1)
            self._plan("readiness", readiness_samples)

    def _plan(self, name: str, planned: int | None, *, skipped: bool = False) -> None:
        current = self.stages.get(name)
        if current is None:
            self.stages[name] = SloProgressStage(planned=planned, skipped=skipped)
            return
        current.planned = planned
        current.skipped = skipped

    def activate(self, stage: str, **labels: str) -> None:
        with self._lock:
            self.active_stage = stage
            self.active_labels = {key: value for key, value in labels.items() if isinstance(value, str)}

    def attempt(self, stage: str, count: int = 1) -> None:
        with self._lock:
            current = self.stages.setdefault(stage, SloProgressStage())
            current.started += count
            current.attempted += count

    def submit(self, stage: str, count: int = 1) -> None:
        with self._lock:
            self.stages.setdefault(stage, SloProgressStage()).submitted += count

    def complete(self, stage: str, count: int = 1) -> None:
        with self._lock:
            self.stages.setdefault(stage, SloProgressStage()).completed += count

    def fail_request(self, stage: str, count: int = 1) -> None:
        with self._lock:
            self.stages.setdefault(stage, SloProgressStage()).failed += count

    def cancel(self, stage: str, count: int = 1) -> None:
        with self._lock:
            self.stages.setdefault(stage, SloProgressStage()).cancelled += count

    def record_failure(
        self,
        error: BaseException,
        *,
        stage: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> None:
        """Record only the first fatal failure using bounded labels."""

        with self._lock:
            if self.failure is not None:
                return
            selected_stage = stage or self.active_stage or "unknown"
            selected_labels = dict(labels or self.active_labels)
            failure: dict[str, object] = {
                "stage": selected_stage if selected_stage in SAFE_FAILURE_STAGE_NAMES else "unknown",
                "category": classify_benchmark_error(error),
            }
            allowlists = {
                "harness": SAFE_HARNESS_NAMES,
                "event": SAFE_EVENT_NAMES,
                "size_class": SAFE_SIZE_CLASS_NAMES,
                "wave": SAFE_FAILURE_WAVE_NAMES,
            }
            for key, allowed in allowlists.items():
                value = selected_labels.get(key)
                if isinstance(value, str):
                    failure[key] = value if value in allowed else "unknown"
            self.failure = failure

    def stage_snapshot(self) -> dict[str, dict[str, object]]:
        with self._lock:
            return {name: stage.snapshot() for name, stage in sorted(self.stages.items())}

    def completed_observations(self) -> int:
        with self._lock:
            return sum(self.stages.get(name, SloProgressStage()).completed for name in _OBSERVATION_PROGRESS_STAGES)

    def observation_snapshot(self) -> dict[str, int | None]:
        """Return the aggregate counters for the report's observation corpus."""

        with self._lock:
            stages = [self.stages.get(name, SloProgressStage()) for name in _OBSERVATION_PROGRESS_STAGES]
            planned = (
                None
                if any(stage.planned is None for stage in stages)
                else sum(stage.planned or 0 for stage in stages)
            )
            submitted = sum(stage.submitted for stage in stages)
            started = sum(stage.started for stage in stages)
            attempted = sum(stage.attempted for stage in stages)
            completed = sum(stage.completed for stage in stages)
            failed = sum(stage.failed for stage in stages)
            cancelled = sum(stage.cancelled for stage in stages)
            return {
                "planned": planned,
                "submitted": submitted,
                "started": started,
                "attempted": attempted,
                "completed": completed,
                "failed": failed,
                "cancelled": cancelled,
                "missing": (
                    None
                    if planned is None
                    else max(0, planned - completed - failed - cancelled)
                ),
            }

    def completed_error_count(self, stage: str) -> int | None:
        with self._lock:
            current = self.stages.get(stage)
            if current is None or current.planned in (None, 0):
                return None
            if current.cancelled or current.completed + current.failed < current.planned:
                return None
            return current.failed

    def snapshot_failure(self) -> dict[str, object]:
        with self._lock:
            if self.failure is not None:
                return dict(self.failure)
            return {
                "stage": self.active_stage if self.active_stage in SAFE_FAILURE_STAGE_NAMES else "unknown",
                "category": "benchmark_internal_failure",
            }


@dataclass(frozen=True)
class SloSummary:
    all_observations: list[Observation]
    route_counts: Counter[str]
    warm_routes: Counter[str]
    warm_failures: int
    warm_fail_safe: int
    # Policy denials from size and capacity probes are expected evidence, not
    # native fail-safe outcomes. Keep their aggregate separate from the SLO.
    safe_failures: int
    security_denials: int
    safe_failure_rate: float
    safe_failures_by_size: Counter[str]
    security_denials_by_size: Counter[str]
    size_values: dict[str, list[float]]
    warm_values: list[float]
    concurrent_values: list[float]
    size_p95: dict[str, float]
    event_values: dict[str, list[float]]
    rss_growth: float
    concurrent_64_summary: dict[str, float]
    concurrent_16_overloads: int
    concurrent_64_overloads: int


def _require(condition: bool, reason: object) -> None:
    if not condition:
        raise RuntimeError(f"native_installed_slo_failed: {reason}")


def safe_failure_rate(observations: Sequence[Observation]) -> float:
    """Return the native fail-safe rate for the supplied corpus.

    ``allowed`` is a policy result, so a false value is not itself a fail-safe.
    Large source-reference and bounded-capacity probes may be intentionally
    denied. The SLO gate supplies the ordinary warm corpus here; callers can
    retain all policy denials separately for diagnostic evidence.
    """

    return sum(
        observation.route == "native_fail_safe" and not observation.overloaded for observation in observations
    ) / max(1, len(observations))


def _all_observations(measurements: SloMeasurements) -> list[Observation]:
    return measurements.warm + measurements.sizes + measurements.concurrent_16 + measurements.concurrent_64


def _latencies_by_size(observations: Sequence[Observation]) -> dict[str, list[float]]:
    return {
        size_class: [observation.latency_ms for observation in observations if observation.size_class == size_class]
        for size_class in SIZE_CLASSES
    }


def _latencies_by_event(observations: Sequence[Observation]) -> dict[str, list[float]]:
    return {
        event: [observation.latency_ms for observation in observations if observation.event == event]
        for event in ("PreToolUse", "PostToolUse")
    }


def _failure_counts(
    observations: Sequence[Observation],
) -> tuple[int, Counter[str], int, Counter[str]]:
    safe = [
        observation
        for observation in observations
        if observation.route == "native_fail_safe" and not observation.overloaded
    ]
    denials = [
        observation
        for observation in observations
        if not observation.allowed and (observation.route != "native_fail_safe" or observation.overloaded)
    ]
    return (
        len(safe),
        Counter(observation.size_class for observation in safe),
        len(denials),
        Counter(observation.size_class for observation in denials),
    )


def _rss_growth(measurements: SloMeasurements) -> float:
    if not measurements.rss_baseline:
        return 1.0
    return round(max(0, measurements.rss_peak - measurements.rss_baseline) / measurements.rss_baseline, 6)


def summarize_measurements(measurements: SloMeasurements) -> SloSummary:
    all_observations = _all_observations(measurements)
    route_counts = Counter(observation.route for observation in all_observations)
    _require(
        not (set(route_counts) - SAFE_ROUTE_NAMES),
        {"unexpected_routes": sorted(set(route_counts) - SAFE_ROUTE_NAMES)},
    )
    warm_values = [observation.latency_ms for observation in measurements.warm]
    size_values = _latencies_by_size(all_observations)
    event_values = _latencies_by_event(measurements.warm)
    safe_failures, safe_failures_by_size, security_denials, security_denials_by_size = _failure_counts(all_observations)
    return SloSummary(
        all_observations=all_observations,
        route_counts=route_counts,
        warm_routes=Counter(observation.route for observation in measurements.warm),
        warm_failures=sum(not observation.allowed for observation in measurements.warm),
        warm_fail_safe=sum(observation.route == "native_fail_safe" for observation in measurements.warm),
        safe_failures=safe_failures,
        security_denials=security_denials,
        safe_failure_rate=safe_failure_rate(measurements.warm),
        safe_failures_by_size=safe_failures_by_size,
        security_denials_by_size=security_denials_by_size,
        size_values=size_values,
        warm_values=warm_values,
        concurrent_values=[observation.latency_ms for observation in measurements.concurrent_16],
        size_p95={size_class: summarize(values)["p95_ms"] for size_class, values in size_values.items() if values},
        event_values=event_values,
        rss_growth=_rss_growth(measurements),
        concurrent_64_summary=summarize([item.latency_ms for item in measurements.concurrent_64]),
        concurrent_16_overloads=sum(item.overloaded for item in measurements.concurrent_16),
        concurrent_64_overloads=sum(item.overloaded for item in measurements.concurrent_64),
    )


def _concurrent_observations_are_bounded(
    observations: Sequence[Observation],
    *,
    allow_overload: bool,
) -> bool:
    """Require a resident decision or an explicitly bounded overload result."""

    if not observations:
        return False
    if allow_overload:
        return all(observation.overloaded or observation.route == "native_resident" for observation in observations)
    return all(not observation.overloaded and observation.route == "native_resident" for observation in observations)


def slo_gates(
    measurements: SloMeasurements,
    summary: SloSummary,
    installed_corpus: dict[str, int],
    route_count: int,
    *,
    include_capacity: bool,
) -> dict[str, bool]:
    gates = gate_results(
        resident_share=summary.warm_routes["native_resident"] / max(1, len(measurements.warm)),
        safe_fail_rate=summary.safe_failure_rate,
        warm_p95_ms=summarize(summary.warm_values)["p95_ms"],
        size_p95_ms=summary.size_p95,
        cold_p95_ms=summarize(measurements.cold)["p95_ms"],
        readiness_p95_ms=summarize(measurements.readiness)["p95_ms"],
        concurrent_p99_ms=(
            summarize(summary.concurrent_values)["p99_ms"] if summary.concurrent_values else float("inf")
        ),
        rss_growth=summary.rss_growth,
        rss_baseline_bytes=measurements.rss_baseline,
        errors=measurements.errors_16,
        errors_64=measurements.errors_64,
        python_fallback_decisions=summary.route_counts["python_semantic"],
        installed_python_fallback_decisions=installed_corpus["python_semantic_decisions"],
    )
    gates["recovery_latency"] = summarize(measurements.recovery)["p95_ms"] <= MAX_INSTALLED_ADAPTER_P95_MS
    gates["concurrency"] = gates["concurrency"] and _concurrent_observations_are_bounded(
        measurements.concurrent_16,
        allow_overload=False,
    )
    gates["concurrency_64_bounded"] = (
        include_capacity
        and measurements.errors_64 == 0
        and _concurrent_observations_are_bounded(measurements.concurrent_64, allow_overload=True)
    )
    gates["installed_corpus"] = (
        installed_corpus["routes"] == route_count
        and installed_corpus["resident"] == route_count
        and installed_corpus["oneshot"] == 0
        and installed_corpus["fail_safe"] == 0
        and installed_corpus["python_semantic_decisions"] == 0
    )
    if not include_capacity:
        gates["concurrency"] = False
        gates["concurrency_64_bounded"] = False
    return gates


def _thresholds() -> dict[str, float]:
    """Return the reviewed thresholds shared by complete and failed reports."""

    return {
        "installed_adapter_p95_ms": MAX_INSTALLED_ADAPTER_P95_MS,
        "installed_adapter_concurrent_p99_ms": MAX_INSTALLED_ADAPTER_P99_MS,
        "direct_cold_p95_ms": MAX_COLD_P95_MS,
        "readiness_p95_ms": MAX_READINESS_P95_MS,
    }


def slo_result(
    runtime_summary: dict[str, object],
    routes: tuple[tuple[str, str], ...],
    installed_corpus: dict[str, int],
    measurements: SloMeasurements,
    summary: SloSummary,
    gates: dict[str, bool],
    *,
    corpus_origin: str = "installed_wheel_ownership_contract",
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": SLO_SCHEMA,
        "scope": "installed_adapter_to_decision",
        "runtime": runtime_summary,
        "corpus": {
            "harnesses": len({harness for harness, _ in routes}),
            "routes": len(routes),
            "observations": len(summary.all_observations),
            "corpus_origin": corpus_origin,
            "route_corpus": "installed_routes",
            "warm_failures": summary.warm_failures,
            # Keep the historical aliases while exposing an unambiguous name:
            # these are expected policy/capacity denials, not the fail-safe
            # SLO numerator.
            "safe_failures": summary.safe_failures,
            "security_denials": summary.security_denials,
            "safe_failure_rate": round(summary.safe_failure_rate, 6),
            "fail_safe_decisions": summary.warm_fail_safe,
            "fail_safe_rate": round(summary.warm_fail_safe / max(1, len(measurements.warm)), 6),
            "resident_share": round(summary.warm_routes["native_resident"] / max(1, len(measurements.warm)), 6),
            "python_fallback_decisions": summary.warm_routes["python_semantic"],
            "python_semantic_decisions": summary.route_counts["python_semantic"],
            "oneshot_decisions": summary.warm_routes["native_oneshot"],
            "safe_failures_by_size": dict(sorted(summary.safe_failures_by_size.items())),
            "security_denials_by_size": dict(sorted(summary.security_denials_by_size.items())),
            "rss_baseline_bytes": measurements.rss_baseline,
            "rss_peak_bytes": measurements.rss_peak,
            "rss_growth": summary.rss_growth,
            "installed": installed_corpus,
        },
        "routes": dict(sorted(summary.route_counts.items())),
        "python_semantic_decisions": summary.route_counts["python_semantic"],
        "errors_16": measurements.errors_16,
        "errors_64": measurements.errors_64,
        "latency": {
            "warm_all_harnesses": summarize(summary.warm_values),
            "warm_by_event": {event: summarize(values) for event, values in summary.event_values.items() if values},
            "size_classes": {size_class: summarize(values) for size_class, values in summary.size_values.items()},
            "cold_native_oneshot": summarize(measurements.cold),
            "resident_recovery": summarize(measurements.recovery),
            "readiness": summarize(measurements.readiness),
        },
        "thresholds": _thresholds(),
        "concurrency": {
            "sixteen": {
                "latency": summarize(summary.concurrent_values),
                "errors": measurements.errors_16,
                "overloaded": summary.concurrent_16_overloads,
                "deadline_ms": MAX_INSTALLED_ADAPTER_P99_MS,
            },
            "sixty_four": {
                "latency": summary.concurrent_64_summary,
                "errors": measurements.errors_64,
                "overloaded": summary.concurrent_64_overloads,
                "fail_safe": sum(item.route == "native_fail_safe" for item in measurements.concurrent_64),
                "latency_ceiling_ms": None,
                "bounded": gates.get("concurrency_64_bounded", False),
            },
        },
        "gates": gates,
        "passed": all_gates_pass(gates),
    }
    return assert_privacy_safe(result)


def incomplete_slo_result(
    progress: SloProgress,
    *,
    include_capacity: bool,
) -> dict[str, object]:
    """Render a bounded failed run without manufacturing missing measurements."""

    gates = gate_results(
        resident_share=0.0,
        safe_fail_rate=1.0,
        warm_p95_ms=float("inf"),
        size_p95_ms={},
        cold_p95_ms=float("inf"),
        readiness_p95_ms=float("inf"),
        concurrent_p99_ms=float("inf"),
        rss_growth=1.0,
        rss_baseline_bytes=0,
        errors=1,
        errors_64=1,
        python_fallback_decisions=1,
        installed_python_fallback_decisions=1,
    )
    gates["recovery_latency"] = False
    gates["concurrency_64_bounded"] = False
    gates["installed_corpus"] = False
    stages = progress.stage_snapshot()
    observations = progress.observation_snapshot()
    installed = progress.installed_corpus
    errors_16 = progress.completed_error_count("concurrent_16")
    errors_64 = progress.completed_error_count("concurrent_64")
    routes = progress.routes
    route_count = progress.route_count
    concurrency: dict[str, object] = {
        "sixteen": {
            "latency": None,
            "errors": errors_16,
            "overloaded": None,
            "deadline_ms": MAX_INSTALLED_ADAPTER_P99_MS,
            "denominators": stages.get("concurrent_16"),
        },
        "sixty_four": {
            "latency": None,
            "errors": errors_64,
            "overloaded": None,
            "fail_safe": None,
            "latency_ceiling_ms": None,
            "bounded": False,
            "denominators": stages.get("concurrent_64"),
        },
    }
    if not include_capacity:
        # Keep skipped capacity distinguishable from an unobserved wave while
        # retaining the current false capacity gates.
        concurrency["skipped"] = True
    result: dict[str, object] = {
        "schema": SLO_SCHEMA,
        "scope": "installed_adapter_to_decision",
        "status": "failed",
        "complete": False,
        "evaluation": "incomplete",
        "runtime": progress.runtime_summary or {},
        "corpus": {
            "harnesses": None if route_count is None else len({harness for harness, _ in routes}),
            "routes": route_count,
            "observations": observations["completed"],
            "planned": observations["planned"],
            "submitted": observations["submitted"],
            "started": observations["started"],
            "attempted": observations["attempted"],
            "completed": observations["completed"],
            "failed": observations["failed"],
            "cancelled": observations["cancelled"],
            "missing": observations["missing"],
            "corpus_origin": "installed_wheel_ownership_contract",
            "route_corpus": "installed_routes",
            "safe_failures": None,
            "security_denials": None,
            "safe_failure_rate": None,
            "fail_safe_decisions": None,
            "fail_safe_rate": None,
            "resident_share": None,
            "python_fallback_decisions": None,
            "python_semantic_decisions": None,
            "oneshot_decisions": None,
            "rss_baseline_bytes": None,
            "rss_peak_bytes": None,
            "rss_growth": None,
            "installed": installed,
            "denominators": stages,
        },
        "failure": progress.snapshot_failure(),
        "errors_16": errors_16,
        "errors_64": errors_64,
        "latency": {
            "warm_all_harnesses": None,
            "warm_by_event": {},
            "size_classes": {},
            "cold_native_oneshot": None,
            "resident_recovery": None,
            "readiness": None,
        },
        "thresholds": _thresholds(),
        "concurrency": concurrency,
        "gates": gates,
        "passed": False,
    }
    return assert_privacy_safe(result)


__all__ = [
    "SloMeasurements",
    "SloProgress",
    "SloProgressStage",
    "SloSummary",
    "classify_benchmark_error",
    "incomplete_slo_result",
    "safe_failure_rate",
    "slo_gates",
    "slo_result",
    "summarize_measurements",
]
