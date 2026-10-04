"""A reviewed migration anchor and historical high-water mark cannot ratchet down."""

from __future__ import annotations

from datetime import datetime

from scripts.ci.sonar_quality_client import SonarClient, identifier
from scripts.ci.sonar_quality_policy import conditions, coverage_values, inherited_coverage_allowed, number

# One explicit acceptance of existing migration debt. Changing this anchor is a
# reviewed policy change, never something a failed push or new analysis can do.
ANCHOR = {
    "analysis_id": "2ca53ee4-9157-4df2-8dd4-e4df8b1cf840",
    "revision": "846fe97cb2445bbf6e73a05d6c540e8470fc6904",
    "coverage": "61.7",
}


def analyzed_window(analyses: list[dict], current_id: str, current_sha: str, history: list[str]) -> list[dict]:
    """Select all analyzed main ancestors since the anchor, not just the last push."""
    if ANCHOR["revision"] not in history:
        raise ValueError("Reviewed coverage anchor is absent from pre-push first-parent history")
    current = [item for item in analyses if item.get("key") == current_id]
    anchor = [item for item in analyses if item.get("key") == ANCHOR["analysis_id"]]
    if len(current) != 1 or current[0].get("revision") != current_sha:
        raise ValueError("Current analysis does not match the checked-out main commit")
    if len(anchor) != 1 or anchor[0].get("revision") != ANCHOR["revision"]:
        raise ValueError("Reviewed coverage analysis is missing or ambiguous")
    current_date = datetime.fromisoformat(current[0]["date"])
    anchor_date = datetime.fromisoformat(anchor[0]["date"])
    if current_date.tzinfo is None or anchor_date.tzinfo is None or anchor_date >= current_date:
        raise ValueError("Coverage anchor does not precede the current analysis")
    version = current[0].get("projectVersion")
    if not isinstance(version, str) or not version or version != anchor[0].get("projectVersion"):
        raise ValueError("Version changed; strict coverage gate remains blocking")
    revisions = set(history[: history.index(ANCHOR["revision"]) + 1])
    window, seen = [], set()
    for item in analyses:
        if item.get("revision") not in revisions or item.get("key") == current_id:
            continue
        date = datetime.fromisoformat(item["date"])
        if date.tzinfo is None:
            raise ValueError("Analysis date has no timezone")
        if not anchor_date <= date <= current_date:
            continue
        key = identifier(item.get("key"))
        if key in seen or item.get("projectVersion") != version:
            raise ValueError("Duplicate analysis or changed project version in coverage history")
        seen.add(key)
        window.append(item)
    if ANCHOR["analysis_id"] not in seen or len(window) > 128:
        raise ValueError("Coverage history is missing or exceeds its bounded review window")
    return window


def permits(
    client: SonarClient, gate: dict, current_id: str, current_sha: str, history: list[str], report: dict
) -> bool:
    """Every higher measurement advances the floor, even if another check failed.

    Rejected lower measurements therefore cannot become permission for the next
    push. The anchor is an explicit bootstrap, not an automatically moving floor.
    """
    analyses = client.main_analyses(current_id=current_id, stop_id=ANCHOR["analysis_id"])
    window = analyzed_window(analyses, current_id, current_sha, history)
    anchor_gate = client.gate(ANCHOR["analysis_id"])
    report["coverage_anchor"] = {**ANCHOR, "gate": anchor_gate}
    anchor_coverage = number(conditions(anchor_gate)["new_coverage"]["actualValue"])
    if anchor_coverage != number(ANCHOR["coverage"]):
        raise ValueError("Reviewed anchor measurement has changed")
    failures = {key for key, value in conditions(gate).items() if value["status"] == "ERROR"}
    if failures != {"new_coverage"} or not inherited_coverage_allowed(anchor_gate, anchor_gate):
        return False
    if coverage_values(gate, anchor_gate) is None:
        return False
    floor = anchor_coverage
    report["coverage_history"] = []
    for analysis in window:
        previous = anchor_gate if analysis["key"] == ANCHOR["analysis_id"] else client.gate(analysis["key"])
        values = coverage_values(gate, previous)
        if values is None:
            raise ValueError("Coverage history contains a changed or incomplete quality scope")
        _, actual = values
        report["coverage_history"].append(
            {
                "analysis_id": analysis["key"],
                "revision": analysis["revision"],
                "coverage": str(actual),
                "sonar_status": previous["status"],
            }
        )
        if actual >= floor:
            floor = actual
            report.update(baseline=analysis, baseline_gate=previous)
    report["coverage_high_water_mark"] = str(floor)
    return number(conditions(gate)["new_coverage"]["actualValue"]) >= floor
