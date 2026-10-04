"""A main coverage ratchet is never a waiver of security, PR coverage, or evidence."""

from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts.ci import check_sonar_quality as runner
from scripts.ci.sonar_quality_policy import REQUIRED_METRICS, conditions, inherited_coverage_allowed, number


def gate(coverage: str = "61.7") -> dict:
    entries = [
        ("new_reliability_rating", "1", "GT", "1"),
        ("new_security_rating", "1", "GT", "1"),
        ("new_maintainability_rating", "1", "GT", "1"),
        ("new_coverage", coverage, "LT", "80"),
        ("new_duplicated_lines_density", "1.1", "GT", "3"),
        ("new_security_hotspots_reviewed", "100", "LT", "100"),
    ]
    rows = []
    for metric, actual, comparator, threshold in entries:
        failed = number(actual) < number(threshold) if comparator == "LT" else number(actual) > number(threshold)
        rows.append(
            {
                "metricKey": metric,
                "actualValue": actual,
                "comparator": comparator,
                "errorThreshold": threshold,
                "periodIndex": 1,
                "status": "ERROR" if failed else "OK",
            }
        )
    return {
        "status": "ERROR" if any(row["status"] == "ERROR" for row in rows) else "OK",
        "conditions": rows,
        "periods": [{"index": 1, "mode": "previous_version", "date": "2026-09-04T13:19:40+0000"}],
        "ignoredConditions": False,
    }


def row(payload: dict, metric: str) -> dict:
    return next(item for item in payload["conditions"] if item["metricKey"] == metric)


@pytest.mark.parametrize(
    ("current", "baseline", "allowed"),
    [
        ("61.7", "61.7", True),
        ("70", "61.7", True),
        ("61.6", "61.7", False),
        ("61.7", "86.6", False),
        ("79.9", "80", False),
        ("80", "61.7", False),
    ],
)
def test_only_inherited_nonworsening_debt_is_eligible(current, baseline, allowed):
    assert inherited_coverage_allowed(gate(current), gate(baseline)) is allowed


@pytest.mark.parametrize("metric", sorted(REQUIRED_METRICS))
@pytest.mark.parametrize("target", ["current", "baseline"])
def test_every_security_and_quality_failure_stays_blocking(metric: str, target: str) -> None:
    current, baseline = gate(), gate()
    condition = row(current if target == "current" else baseline, metric)
    condition["actualValue"] = "0" if condition["comparator"] == "LT" else "4"
    condition["status"] = "ERROR"
    assert not inherited_coverage_allowed(current, baseline)


@pytest.mark.parametrize(
    "change", ["period", "missing-period", "version-mode", "threshold", "unknown-failure", "ignored"]
)
def test_changed_scope_or_unknown_condition_cannot_be_grandfathered(change: str) -> None:
    current, baseline = gate(), gate()
    if change == "period":
        current["periods"][0]["date"] = "2026-10-04T00:00:00+0000"
    elif change == "missing-period":
        current.pop("periods")
    elif change == "version-mode":
        current["periods"][0]["mode"] = "number_of_days"
    elif change == "threshold":
        row(current, "new_coverage")["errorThreshold"] = "90"
    elif change == "ignored":
        current["ignoredConditions"] = True
    else:
        current["conditions"].append(
            {
                "metricKey": "future_security_metric",
                "status": "ERROR",
                "actualValue": "1",
                "comparator": "GT",
                "errorThreshold": "0",
            }
        )
    assert not inherited_coverage_allowed(current, baseline)


@pytest.mark.parametrize(
    "change", ["missing-security", "duplicate", "unknown-status", "wrong-status", "missing-actual", "nan"]
)
def test_incomplete_or_inconsistent_gate_evidence_is_rejected(change: str) -> None:
    payload = gate()
    if change == "missing-security":
        payload["conditions"].remove(row(payload, "new_security_rating"))
    elif change == "duplicate":
        payload["conditions"].append(copy.deepcopy(payload["conditions"][0]))
    elif change == "unknown-status":
        payload["status"] = "NONE"
    elif change == "wrong-status":
        payload["status"] = "OK"
    elif change == "missing-actual":
        row(payload, "new_coverage").pop("actualValue")
    else:
        row(payload, "new_coverage")["actualValue"] = "NaN"
    with pytest.raises(ValueError):
        conditions(payload)


@pytest.mark.parametrize(
    ("metric", "threshold"),
    [
        ("new_security_rating", "2"),
        ("new_reliability_rating", "2"),
        ("new_maintainability_rating", "2"),
        ("new_security_hotspots_reviewed", "90"),
        ("new_coverage", "60"),
        ("new_duplicated_lines_density", "4"),
    ],
)
def test_weakened_thresholds_are_rejected_even_if_server_reports_green(metric, threshold):
    payload = gate("95")
    row(payload, metric)["errorThreshold"] = threshold
    with pytest.raises(ValueError, match="weakened"):
        conditions(payload)


@pytest.mark.parametrize("value", [None, 80, True, "nan", "Infinity", "-Infinity", "not-a-number", "1" * 65])
def test_invalid_measurements_never_become_a_passing_comparison(value):
    with pytest.raises(ValueError):
        number(value)


@pytest.fixture
def history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    runner.git("init", "-q", "-b", "main")
    runner.git("config", "user.name", "CI regression")
    runner.git("config", "user.email", "ci@example.invalid")
    runner.git("config", "commit.gpgsign", "false")
    runner.git("commit", "--allow-empty", "-qm", "analyzed main")
    before = runner.git("rev-parse", "HEAD")
    runner.git("checkout", "-qb", "unrelated")
    runner.git("commit", "--allow-empty", "-qm", "unrelated analysis")
    unrelated = runner.git("rev-parse", "HEAD")
    runner.git("checkout", "-q", "main")
    runner.git("commit", "--allow-empty", "-qm", "candidate main")
    after = runner.git("rev-parse", "HEAD")
    event = {
        "before": before,
        "after": after,
        "ref": "refs/heads/main",
        "repository": {"full_name": runner.REPOSITORY},
        "forced": False,
        "deleted": False,
    }
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event))
    environment = {
        "GITHUB_SHA": after,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": runner.REPOSITORY,
        "GITHUB_EVENT_PATH": str(event_path),
    }
    analyses = [
        {"key": "candidate", "revision": after, "date": "2026-10-04T15:00:00+0000", "projectVersion": "not provided"},
        {
            "key": "unrelated",
            "revision": unrelated,
            "date": "2026-10-04T14:59:00+0000",
            "projectVersion": "not provided",
        },
        {"key": "before", "revision": before, "date": "2026-10-04T14:00:00+0000", "projectVersion": "not provided"},
    ]
    return environment, event, analyses


def test_real_git_history_ignores_newer_unrelated_analysis(history) -> None:
    environment, event, analyses = history
    ancestors = runner.trusted_main_history(environment, event)
    selected = runner.previous_analysis(analyses, "candidate", environment["GITHUB_SHA"], ancestors)
    assert selected["key"] == "before"
    client = Mock()
    client.gate.side_effect = [gate(), gate()]
    client.main_analyses.return_value = analyses
    report = {"decision": "blocked"}
    assert runner.evaluate(client, "candidate", environment, report)
    assert report["sonar_status"] == "ERROR"
    assert report["decision"] == "inherited-main-coverage-not-worsened"
    assert client.gate.call_args_list[1].args == ("before",)
    runner.evidence(report, environment)
    saved = json.loads(Path("sonar-quality-evidence/quality.json").read_text())
    assert saved["gate"]["status"] == "ERROR" and saved["baseline"]["key"] == "before"


@pytest.mark.parametrize(
    ("event_name", "ref"),
    [
        ("pull_request", "refs/heads/main"),
        ("pull_request_target", "refs/heads/main"),
        ("schedule", "refs/heads/main"),
        ("workflow_dispatch", "refs/heads/main"),
        ("push", "refs/heads/release/3.0"),
    ],
)
def test_pr_release_and_manual_coverage_remain_strict(event_name, ref):
    client = Mock()
    client.gate.return_value = gate()
    assert not runner.evaluate(client, "candidate", {"GITHUB_EVENT_NAME": event_name, "GITHUB_REF": ref}, {})
    client.main_analyses.assert_not_called()


def test_green_pr_without_coverable_lines_passes_without_ancestry_lookup():
    payload = gate("95")
    payload["conditions"].remove(row(payload, "new_coverage"))
    payload["periods"] = []
    client = Mock()
    client.gate.return_value = payload
    assert runner.evaluate(client, "candidate", {"GITHUB_EVENT_NAME": "pull_request"}, {})
    client.main_analyses.assert_not_called()


@pytest.mark.parametrize("change", ["forced", "foreign-repo", "head", "before", "deleted", "checkout"])
def test_main_provenance_is_not_a_caller_controlled_waiver(history, change):
    environment, event, _ = history
    if change == "forced":
        event["forced"] = True
    elif change == "deleted":
        event["deleted"] = True
    elif change == "foreign-repo":
        environment["GITHUB_REPOSITORY"] = "someone/else"
    elif change == "head":
        event["after"] = "a" * 40
    elif change == "before":
        event["before"] = "0" * 40
    else:
        runner.git("checkout", "-q", "unrelated")
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        runner.trusted_main_history(environment, event)


@pytest.mark.parametrize(
    "change", ["version", "current-sha", "missing-ancestor", "future-ancestor", "duplicate-current"]
)
def test_history_or_baseline_ambiguity_fails_closed(history, change):
    environment, event, analyses = history
    if change == "version":
        analyses[0]["projectVersion"] = "3.23.0"
    elif change == "current-sha":
        analyses[0]["revision"] = "a" * 40
    elif change == "missing-ancestor":
        analyses.pop()
    elif change == "future-ancestor":
        analyses[-1]["date"] = "2026-10-05T00:00:00+0000"
    else:
        analyses.append(copy.deepcopy(analyses[0]))
    with pytest.raises(ValueError):
        runner.previous_analysis(
            analyses, "candidate", environment["GITHUB_SHA"], runner.trusted_main_history(environment, event)
        )


def test_evidence_failure_is_nonzero_and_still_writes_a_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SONAR_TOKEN", "test-only-token")
    monkeypatch.setattr(runner, "metadata_task", Mock(side_effect=OSError("metadata unavailable")))
    assert runner.main() == 1
    report = json.loads(Path("sonar-quality-evidence/quality.json").read_text())
    assert report["decision"] == "blocked" and "metadata unavailable" in report["error"]
