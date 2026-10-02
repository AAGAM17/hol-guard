"""Generated-artifact freshness gates for contribution-only changes.

Contributor PRs own the canonical source, portable fixture, and trust entry.
Maintainer automation regenerates the catalog, native program, baselines, and
digest vectors after scope review, so a source-only ref legitimately contains a
contribution id that the checked-in projections do not cover yet. Tests that
assert freshness of generated artifacts stand down while such a pending
contribution exists; every other invariant still runs.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts.ci.detect_pending_extension_regen import (
    ROOT,
    GitDiffError,
    changed_regen_inputs,
    contribution_ids,
    is_decision_report_input,
)


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run bounded Git inspection without exposing process or path details."""

    command = ["git", *arguments]
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError:
        return subprocess.CompletedProcess(command, 1, "", "git process unavailable")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 1, "", "git timeout")


def pending_contribution_regen() -> bool:
    from codex_plugin_scanner.guard.runtime.command_extensions import (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )

    registry_ids = {extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions}
    return bool(contribution_ids() - registry_ids)


def _projection_base_sha() -> str | None:
    for variable in ("HOL_GUARD_BASE_SHA", "GITHUB_BASE_SHA"):
        value = os.environ.get(variable)
        if value and value.strip():
            return value.strip()

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            event = json.loads(Path(event_path).read_text(encoding="utf-8"))
            pull_request = event.get("pull_request") if isinstance(event, dict) else None
            if pull_request is None:
                return None
            base_sha = (pull_request.get("base") or {}).get("sha")
        except (OSError, json.JSONDecodeError, AttributeError, TypeError) as error:
            raise RuntimeError(f"Could not read pull-request base revision from {event_path!r}") from error
        if not isinstance(base_sha, str) or not base_sha.strip():
            raise RuntimeError(f"Pull-request event {event_path!r} has no base revision")
        return base_sha.strip()

    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request" or os.environ.get("GITHUB_BASE_REF"):
        raise RuntimeError("Could not determine pull-request base revision from available Git refs")

    completed = _git("merge-base", "HEAD", "origin/main")
    if completed.returncode == 0 and completed.stdout.strip():
        return completed.stdout.strip()
    return None


def pending_source_regen() -> bool:
    """Stand down generated freshness only for exact source-bound changes."""

    if pending_contribution_regen():
        return True
    base_sha = _projection_base_sha()
    if base_sha is None:
        return False
    try:
        changed = changed_regen_inputs(base_sha)
    except GitDiffError as error:
        raise RuntimeError(f"Could not qualify generated-artifact freshness: {error}") from error
    return bool(changed.contribution_paths or changed.implementation_paths)


def _pr_diff_paths() -> list[str] | None:
    """Paths this ref changes relative to the base branch, or None outside PR CI.

    CI checkouts are shallow, so diff against a depth-1 fetch of the base ref —
    tree-to-tree, no merge-base history required. Locally, fall back to the
    merge-base against ``main`` when that ref exists.
    """

    base_sha = _projection_base_sha()
    if base_sha is None:
        return None
    result = _git("diff", "--name-only", base_sha, "HEAD")
    if result.returncode:
        if _git("fetch", "-q", "--depth=1", "origin", base_sha).returncode:
            raise RuntimeError("Could not determine pull-request diff: fetching the captured base commit failed")
        result = _git("diff", "--name-only", base_sha, "HEAD")
    if result.returncode:
        raise RuntimeError("Could not determine pull-request diff after fetching the captured base commit")
    return result.stdout.splitlines()


def pending_decision_diff_regen() -> bool:
    """Defer report freshness only for exact report-bound PR inputs.

    The report is maintainer-owned: generated-artifacts-guard rejects it in
    ordinary PR diffs, so a branch that changes any bound input cannot also
    update the report. Report-bound source changes defer freshness until
    maintainer regeneration; the report itself and unrelated changes remain
    strict.
    """

    if pending_contribution_regen():
        return True
    report_outputs = {
        "tests/fixtures/guard-command-corpus/decision-diff-report.json",
        "tests/fixtures/guard-command-corpus/decision-diff-report.framed-sha256",
    }
    diff = _pr_diff_paths()
    if diff is None:
        # Outside a PR checkout there is no branch diff to qualify.
        return False
    normalized = {path.replace("\\", "/") for path in diff}
    if normalized & report_outputs:
        return False
    return any(is_decision_report_input(path) for path in normalized)


requires_fresh_projections = pytest.mark.skipif(
    pending_source_regen(),
    reason=(
        "checked-in projections do not cover a pending source-bound input; "
        "freshness is enforced after maintainer regeneration"
    ),
)

requires_fresh_decision_diff = pytest.mark.skipif(
    pending_decision_diff_regen(),
    reason="decision-diff report is regen-owned; enforced after maintainer regeneration",
)
