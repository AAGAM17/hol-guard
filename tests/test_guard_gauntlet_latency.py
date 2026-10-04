"""Latency evidence contracts; these tests do not qualify a live agent run."""

from __future__ import annotations

import pytest

from ci.gauntlet.input_evidence import public_observations
from ci.gauntlet.latency import summarize_hook_latency


def test_nearest_rank_and_event_distributions_include_tail_failures():
    rows = [{"elapsed_ms": n, "event": "PreToolUse", "http_status": 200} for n in range(1, 100)]
    rows.append({"elapsed_ms": 15000, "event": "SessionStart", "transport_error": True})
    result = summarize_hook_latency(rows)
    assert result["samples"] == 100
    assert [result[key] for key in ("p50_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms")] == [50, 90, 95, 99, 15000]
    assert result["failed_attempts"] == 1
    assert result["by_event"]["SessionStart"]["p99_ms"] == 15000


@pytest.mark.parametrize("value", [None, True, "2", -1, float("nan"), float("inf")])
def test_invalid_or_missing_timings_are_not_zero(value):
    result = summarize_hook_latency([{"elapsed_ms": value, "http_status": 200}])
    assert result["samples"] == 0
    assert result["missing_samples"] == 1
    assert result["p99_ms"] is None


def test_transport_failure_survives_public_export():
    row = {"transport_error": True, "elapsed_ms": 1000}
    assert public_observations([row], {}) == [row]
    assert summarize_hook_latency([row])["failed_attempts"] == 1


def test_empty_and_single_sample_distributions():
    assert summarize_hook_latency([])["p50_ms"] is None
    result = summarize_hook_latency([{"elapsed_ms": 0, "http_status": 200}])
    assert result["samples"] == 1
    assert result["p99_ms"] == result["max_ms"] == 0
