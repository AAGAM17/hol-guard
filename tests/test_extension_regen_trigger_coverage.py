"""Every input hashed into maintained evidence must schedule its regeneration."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/extension-artifact-regen.yml"


def _matches(path: str, pattern: str) -> bool:
    """Match the workflow's positive *, ** subset without crossing / for * alone."""
    assert not any(token in pattern for token in ("!", "?", "[", "]")), pattern
    expression = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(expression, path) is not None


@pytest.mark.parametrize(
    "path,pattern,expected",
    [
        ("rust/crates/example/src/lib.rs", "rust/**", True),
        ("tests/guard_command_corpus_native.py", "tests/guard_command_corpus*.py", True),
        ("tests/nested/guard_command_corpus.py", "tests/guard_command_corpus*.py", False),
        ("other/tests/guard_command_corpus.py", "tests/guard_command_corpus*.py", False),
        ("src/runtime/deep/module.py", "src/runtime/*.py", False),
        ("tests/fixture.json", "tests/fixture.json", True),
        ("tests/fixtureXjson", "tests/fixture.json", False),
    ],
)
def test_trigger_matcher_preserves_path_boundaries(path: str, pattern: str, expected: bool) -> None:
    assert _matches(path, pattern) is expected


def test_regen_trigger_covers_every_decision_diff_input() -> None:
    from tests.guard_command_decision_diff import (
        _EVIDENCE_SOURCE_PATHS,
        KNOWN_GAPS_PATH,
        MANIFEST_PATH,
        NATIVE_CONTRACT_PATH,
        PAIRS_PATH,
        REPO_ROOT,
    )

    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML's YAML 1.1 parser reads the Actions "on" key as True.
    patterns = workflow[True]["push"]["paths"]
    inputs = {
        path.relative_to(REPO_ROOT).as_posix()
        for path in (*_EVIDENCE_SOURCE_PATHS, KNOWN_GAPS_PATH, MANIFEST_PATH, PAIRS_PATH, NATIVE_CONTRACT_PATH)
    }
    assert len(inputs) >= 40
    missing = sorted(path for path in inputs if not any(_matches(path, pattern) for pattern in patterns))
    assert not missing, "Report inputs missing from the regeneration trigger:\n" + "\n".join(missing)


def test_regen_keeps_main_scope_and_reviewed_publication() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert workflow[True]["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in workflow[True]
    assert "pull_request" not in workflow[True]
    assert workflow["concurrency"]["cancel-in-progress"] is False
    steps = workflow["jobs"]["regen"]["steps"]
    publish = next(step for step in steps if step.get("name") == "Regenerate and publish refreshed artifacts")
    assert "gh pr create" in publish["run"]
    assert 'gh pr merge --repo "${GH_REPO}" --auto --squash' in publish["run"]
    assert "--admin" not in publish["run"]
    assert "continue-on-error" not in publish
