"""Generated-artifact freshness gates for contribution-only changes.

Contributor PRs own the canonical source, portable fixture, and trust entry.
Maintainer automation regenerates the catalog, native program, baselines, and
digest vectors after scope review, so a source-only ref legitimately contains a
contribution id that the checked-in projections do not cover yet. Tests that
assert freshness of generated artifacts stand down while such a pending
contribution exists; every other invariant still runs.
"""

from __future__ import annotations

import subprocess

import pytest

from scripts.ci.detect_pending_extension_regen import contribution_ids


def pending_contribution_regen() -> bool:
    from codex_plugin_scanner.guard.runtime.command_extensions import (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )

    registry_ids = {
        extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    }
    return bool(contribution_ids() - registry_ids)


def pending_decision_diff_regen() -> bool:
    """The branch changes decision inputs but leaves the report to post-merge regen.

    On a pull_request merge ref, HEAD^1 is the base tip and HEAD^2 the branch,
    so ``HEAD^1...HEAD``-style diffs reflect only what the branch introduces.
    Decision drift is reviewed on the regen PR; a branch cannot carry the
    regen-owned report, so enforcing byte-equality here would deadlock any
    change that intentionally alters a corpus decision.
    """

    if pending_contribution_regen():
        return True
    report = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
    inputs = (
        "contributions/",
        "contracts/extensions/",
        "rust/crates/guard-command/",
        "src/codex_plugin_scanner/guard/",
        "tests/fixtures/guard-command-corpus/",
    )
    try:
        head_parents = subprocess.run(
            ["git", "rev-list", "--parents", "-n", "1", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        if len(head_parents) < 3:
            return False
        diff = subprocess.run(
            ["git", "diff", "--name-only", "HEAD^1", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        return False
    if report in diff:
        return False
    return any(path.startswith(inputs) for path in diff)


requires_fresh_projections = pytest.mark.skipif(
    pending_decision_diff_regen(),
    reason=(
        "checked-in projections do not cover a pending regeneration; "
        "freshness is enforced after maintainer regeneration"
    ),
)
