"""Require source-bound live evidence inside the existing Python CI aggregate."""
from __future__ import annotations

import re
from typing import Any

from .github_ci import CONTEXT, GitHubAPI, requires_gauntlet

EVIDENCE_WORKFLOW = ".github/workflows/guard-gauntlet-evidence.yml"


def require_evidence(api: GitHubAPI, event: dict[str, Any]) -> None:
    """A status alone is insufficient: require its successful trusted producer and artifact."""
    number = event["pull_request"]["number"]
    candidate = event["pull_request"]["head"]["sha"]
    pull = api.pull(number, candidate)
    paths, count = [], 0
    for page in range(1, 32):
        rows = api.request(f"/pulls/{number}/files?per_page=100&page={page}")
        count += len(rows)
        paths.extend(row["filename"] for row in rows)
        paths.extend(row["previous_filename"] for row in rows if "previous_filename" in row)
        if len(rows) < 100:
            break
    if count != pull["changed_files"]:
        raise ValueError("incomplete PR file inventory cannot waive Gauntlet")
    if not requires_gauntlet(paths):
        print("Guard Gauntlet: no enforcement or acceptance-system changes in this PR")
        return
    latest = None
    for page in range(1, 21):
        rows = api.request(f"/commits/{candidate}/statuses?per_page=100&page={page}")
        latest = next((row for row in rows if row.get("context") == CONTEXT), None)
        if latest is not None or len(rows) < 100:
            break
    instruction = ("Guard Gauntlet requires fresh real-agent evidence for this exact PR head. "
                   "Run the live suite, pack the verified public evidence, dispatch Guard Gauntlet evidence, "
                   "wait for its successful validation, then rerun failed CI jobs. See ci/gauntlet/README.md.")
    if latest is None or latest.get("state") != "success":
        raise RuntimeError(instruction)
    match = re.fullmatch(r"https://github\.com/" + re.escape(api.repo) + r"/actions/runs/([0-9]+)",
                         latest.get("target_url", ""))
    if match is None:
        raise RuntimeError("Gauntlet status has no repository-owned producer run")
    run_id = match.group(1)
    run = api.request(f"/actions/runs/{run_id}")
    if (run.get("event") != "workflow_dispatch" or run.get("conclusion") != "success"
            or run.get("path", "").split("@", 1)[0] != EVIDENCE_WORKFLOW
            or run.get("head_repository", {}).get("full_name") != api.repo):
        raise RuntimeError("Gauntlet evidence producer is incomplete, failed or untrusted. " + instruction)
    artifacts = api.request(f"/actions/runs/{run_id}/artifacts?per_page=100")
    names = [artifact for artifact in artifacts.get("artifacts", [])
             if artifact.get("name") == "guard-gauntlet-" + candidate and artifact.get("expired") is False]
    if len(names) != 1:
        raise RuntimeError("Gauntlet producer has no unique unexpired evidence artifact for this head")
    print(f"Guard Gauntlet: verified exact-head live evidence from trusted workflow run {run_id}")
