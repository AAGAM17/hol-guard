"""Keep security gates strict and ratchet inherited main-branch coverage debt."""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime
from html import escape
from pathlib import Path

from scripts.ci.sonar_quality_client import SonarClient, identifier, metadata_task
from scripts.ci.sonar_quality_policy import conditions, inherited_coverage_allowed

REPOSITORY = "hashgraph-online/hol-guard"


def sha(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None or value == "0" * 40:
        raise ValueError("Expected a complete nonzero commit SHA")
    return value


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], text=True, timeout=15).strip()


def trusted_main_history(environment: dict[str, str], event: dict) -> list[str]:
    """Bind the exception to the actual push and its pre-push first-parent history."""
    if not isinstance(event, dict) or not isinstance(event.get("repository"), dict):
        raise ValueError("Push provenance is not an object")
    if (
        environment.get("GITHUB_EVENT_NAME") != "push"
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or event.get("ref") != "refs/heads/main"
        or event.get("repository", {}).get("full_name") != REPOSITORY
        or event.get("forced") is not False
        or event.get("deleted") is not False
    ):
        raise ValueError("Inherited coverage policy is available only to normal main pushes")
    before, after = sha(event.get("before")), sha(event.get("after"))
    if before == after or after != sha(environment.get("GITHUB_SHA")) or git("rev-parse", "HEAD") != after:
        raise ValueError("Checkout and push provenance disagree")
    git("merge-base", "--is-ancestor", before, after)
    history = git("rev-list", "--first-parent", "--max-count=2000", before).splitlines()
    if not history or history[0] != before:
        raise ValueError("Pre-push history is unavailable")
    return [sha(commit) for commit in history]


def previous_analysis(analyses: list[dict], current_id: str, current_sha: str, history: list[str]) -> dict:
    """Never compare with an unrelated, future, PR, or stale current-branch analysis."""
    current = [item for item in analyses if item.get("key") == current_id]
    if len(current) != 1 or current[0].get("revision") != current_sha:
        raise ValueError("Current analysis does not match the checked-out main commit")
    current_date = datetime.fromisoformat(current[0]["date"])
    if current_date.tzinfo is None:
        raise ValueError("Analysis date has no timezone")
    candidates = []
    ranks = {commit: index for index, commit in enumerate(history)}
    for item in analyses:
        if item.get("revision") not in ranks or item.get("key") == current_id:
            continue
        date = datetime.fromisoformat(item["date"])
        if date.tzinfo is None:
            raise ValueError("Analysis date has no timezone")
        if date <= current_date:
            candidates.append((ranks[item["revision"]], -date.timestamp(), item))
    if not candidates:
        raise ValueError("No analyzed pre-push ancestor is available; strict gate remains blocking")
    baseline = min(candidates, key=lambda item: item[:2])[2]
    identifier(baseline.get("key"))
    if baseline.get("projectVersion") != current[0].get("projectVersion"):
        raise ValueError("Version changed; strict coverage gate remains blocking")
    return baseline


def evaluate(client: SonarClient, analysis_id: str, environment: dict[str, str], report: dict) -> bool:
    gate = client.gate(analysis_id)
    report.update(analysis_id=analysis_id, sonar_status=gate.get("status"), gate=gate)
    checked = conditions(gate)
    if gate["status"] == "OK":
        report["decision"] = "full-quality-gate-passed"
        return True
    if {key for key, value in checked.items() if value["status"] == "ERROR"} != {"new_coverage"}:
        return False
    if environment.get("GITHUB_EVENT_NAME") != "push" or environment.get("GITHUB_REF") != "refs/heads/main":
        return False
    event_path = Path(environment["GITHUB_EVENT_PATH"])
    with event_path.open("rb") as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("Push event exceeds its byte limit")
    history = trusted_main_history(environment, json.loads(raw))
    baseline = previous_analysis(
        client.main_analyses(current_id=analysis_id, before_sha=history[0]),
        analysis_id,
        sha(environment["GITHUB_SHA"]),
        history,
    )
    previous = client.gate(baseline["key"])
    report.update(baseline=baseline, baseline_gate=previous)
    if not inherited_coverage_allowed(gate, previous):
        return False
    report["decision"] = "inherited-main-coverage-not-worsened"
    return True


def annotation(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def evidence(report: dict, environment: dict[str, str]) -> None:
    output = Path("sonar-quality-evidence")
    output.mkdir(exist_ok=True)
    (output / "quality.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "## Sonar quality decision",
        "",
        f"CI policy: **{escape(report['decision'])}**.",
        f"Raw Sonar gate: **{escape(str(report.get('sonar_status', 'unavailable')))}**.",
        "",
        "| Condition | Actual | Required | Status |",
        "| --- | --- | --- | --- |",
    ]
    items = report.get("gate", {}).get("conditions", [])
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            values = [item.get(key, "missing") for key in ("metricKey", "actualValue", "errorThreshold", "status")]
            lines.append("| " + " | ".join(escape(str(value)).replace("|", "&#124;") for value in values) + " |")
    if "baseline" in report:
        lines += ["", f"Compared with analyzed main ancestor `{sha(report['baseline']['revision'])}`."]
    if report["decision"] == "inherited-main-coverage-not-worsened":
        lines += [
            "",
            "Coverage debt remains visible. The 80% PR gate, every non-coverage condition, "
            "and the no-regression main ratchet remain blocking. No source or test was excluded.",
        ]
    if "error" in report:
        lines += ["", "Evidence error: " + escape(report["error"])]
    markdown = "\n".join(lines) + "\n"
    (output / "summary.md").write_text(markdown, encoding="utf-8")
    if environment.get("GITHUB_STEP_SUMMARY"):
        with Path(environment["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
            stream.write(markdown)


def main() -> int:
    report = {"decision": "blocked", "policy_version": 1, "revision": os.environ.get("GITHUB_SHA")}
    passed = False
    try:
        client = SonarClient(os.environ.get("SONAR_TOKEN", ""))
        analysis_id = client.analysis(metadata_task(Path(".scannerwork/report-task.txt")))
        passed = evaluate(client, analysis_id, dict(os.environ), report)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = f"{type(error).__name__}: {error}"
    evidence(report, dict(os.environ))
    if not passed:
        print("::error::Sonar quality policy failed. See the job summary and sonar-quality-evidence artifact.")
    elif report["decision"] == "inherited-main-coverage-not-worsened":
        print("::warning::Inherited main coverage debt did not worsen; the raw Sonar coverage gate remains red.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
