"""Detect source changes that require maintainer-owned projection regeneration.

Prints ``{"pending": ..., "pending_ids": [...]}`` (or a bare ``true``/``false``
with ``--flag``) when any canonical contribution under ``contributions/``
declares an extension id that the checked-in ``command-catalog.v1.json`` does
not contain, or when native implementation or decision-report inputs changed
from ``--changed-from``.
That state means the source-only ref is awaiting maintainer-owned projection
regeneration, so generated-artifact freshness gates should stand down for that
ref. Stdlib only; no repository imports.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "contracts/extensions/command-catalog.v1.json"


class GitDiffError(RuntimeError):
    """Raised when a comparison revision cannot be inspected safely."""


# Kept as a compatibility alias for CI tests and callers from the base branch.
ContributionDiffError = GitDiffError


@dataclass(frozen=True)
class ChangedRegenInputs:
    """Inputs whose changes permit source-only projection validation."""

    contribution_paths: tuple[str, ...]
    implementation_paths: tuple[str, ...]
    report_paths: tuple[str, ...] = ()


_GENERATED_OUTPUTS = frozenset(
    {
        "contracts/extensions/command-catalog.v1.json",
        "contracts/extensions/native-command-program.v1.json",
    }
)

_DECISION_REPORT_FIXED_INPUTS = frozenset(
    {
        "contracts/extensions/command-catalog.v1.json",
        "contracts/extensions/native-command-program.v1.json",
        "docs/guard/native-command-corpus-contract.md",
        "docs/guard/declarative-authoring-adr.md",
        "rust/crates/guard-command/src/native_command_source_evaluation_batch.rs",
        "rust/crates/guard-command/src/native_command_source.rs",
        "rust/crates/guard-command/src/bin/guard-command-source.rs",
        "src/codex_plugin_scanner/guard/action_lattice.py",
        "src/codex_plugin_scanner/guard/models.py",
        "src/codex_plugin_scanner/guard/cli/commands_parser.py",
        "src/codex_plugin_scanner/guard/cli/commands_parser_local.py",
        "src/codex_plugin_scanner/guard/cli/commands_router.py",
        "src/codex_plugin_scanner/guard/cli/commands_support.py",
        "src/codex_plugin_scanner/guard/cli/commands_verified_read.py",
        "src/codex_plugin_scanner/guard/cli/commands_contained_write.py",
        "src/codex_plugin_scanner/guard/contained_package_script_execution.py",
        "src/codex_plugin_scanner/guard/contained_workspace_write_execution.py",
        "src/codex_plugin_scanner/guard/durable_harness_launcher.py",
        "src/codex_plugin_scanner/guard/package_shim_gate.py",
        "src/codex_plugin_scanner/guard/package_shim_frozen.py",
        "src/codex_plugin_scanner/guard/shims.py",
        "tests/test_guard_command_corpus.py",
        "tests/guard_test_invariants.py",
        "tests/test_guard_command_corpus_native_contract.py",
        "tests/test_guard_command_decision_diff.py",
        "tests/native_command_test_support.py",
        "tests/test_native_command_test_support_batch.py",
        "tests/test_guard_native_classification_baseline.py",
        "tests/test_guard_contained_package_script_execution.py",
        "tests/test_guard_contained_workspace_write_cli.py",
        "tests/test_guard_contained_workspace_write_contract.py",
        "tests/test_guard_contained_workspace_write_execution.py",
        "tests/test_guard_containment_external_executable.py",
        "tests/test_guard_package_shims.py",
        "tests/test_guard_verified_reads.py",
    }
)


def is_decision_report_input(path: str) -> bool:
    """Return whether ``path`` is hashed into the decision-diff report."""

    normalized = path.replace("\\", "/")
    if normalized in _GENERATED_OUTPUTS:
        return False
    if normalized in _DECISION_REPORT_FIXED_INPUTS:
        return True
    runtime_prefix = "src/codex_plugin_scanner/guard/runtime/"
    if normalized.startswith(runtime_prefix):
        return "/" not in normalized[len(runtime_prefix) :] and normalized.endswith(".py")
    if normalized.startswith("tests/"):
        filename = normalized.removeprefix("tests/")
        if "/" not in filename and filename.endswith(".py"):
            return filename.startswith(("guard_command_corpus", "guard_command_decision_diff"))
    return False


def contribution_ids() -> set[str]:
    """Collect canonical extension identities from each contribution format."""
    ids = {str(json.loads(path.read_text())["id"]) for path in (ROOT / "contributions/extensions").glob("*.json")}
    ids.update(
        str(json.loads(path.read_text())["extension"]["extension_id"])
        for path in (ROOT / "contributions/command-sources").glob("command.*.json")
    )
    ids.update(
        "command.mcp-" + str(json.loads(path.read_text())["id"]).removeprefix("mcp.")
        for path in (ROOT / "contributions/mcp-servers").glob("*.json")
    )
    return ids


def catalog_ids() -> set[str]:
    """Read the identities covered by the checked-in generated catalog."""
    catalog = json.loads(CATALOG.read_text())
    return {entry["extension_id"] for entry in catalog["catalog"]}


def _git_changed_paths(base_sha: str, *, pathspec: tuple[str, ...] = (), nul: bool = True) -> list[str]:
    """Return changed paths only after a bounded, verified Git comparison."""

    if not isinstance(base_sha, str) or not base_sha.strip():
        raise GitDiffError("A non-empty base revision is required; the comparison base must be a full Git commit SHA")
    if re.fullmatch(r"[0-9a-fA-F]{40}", base_sha) is None:
        raise GitDiffError("Could not determine changed files: the comparison base must be a full Git commit SHA")
    normalized_sha = base_sha.lower()
    command = ["git", "diff", "--name-only"]
    if nul:
        command.extend(("--no-renames", "-z"))
    command.extend((normalized_sha, "HEAD", "--", *pathspec))

    def _diff() -> subprocess.CompletedProcess[str]:
        """Read contribution changes without exposing Git output in error messages."""
        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    try:
        completed = _diff()
        if completed.returncode:
            # Shallow checkouts lack the base commit; fetch it and retry once.
            fetched = subprocess.run(
                ["git", "fetch", "--depth=1", "origin", normalized_sha],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            if fetched.returncode:
                raise GitDiffError(
                    "Could not determine changed files: Cannot compare contribution sources: "
                    "fetching the PR base failed"
                )
            completed = _diff()
    except subprocess.TimeoutExpired:
        raise GitDiffError("Cannot compare contribution sources: Git timed out [git_timeout]") from None
    except UnicodeError:
        raise GitDiffError("Cannot compare contribution sources: Git output unreadable [git_encoding]") from None
    except OSError:
        raise GitDiffError("Cannot compare contribution sources: Git unavailable [git_process]") from None
    if completed.returncode:
        raise GitDiffError(
            "Could not determine changed files: Cannot compare contribution sources: "
            "Git diff failed after fetching the PR base"
        )
    output = completed.stdout or ""
    paths = output.split("\0") if nul else output.splitlines()
    return [path.rstrip("\r\n") for path in paths if path]


def _contributions_changed(base_sha: str) -> list[str]:
    """Return contribution paths changed since a verified base revision."""

    return _git_changed_paths(base_sha, pathspec=("contributions/",), nul=False)


def is_native_implementation_input(path: str) -> bool:
    """Return whether ``path`` contributes to guard-command's implementation digest."""

    normalized = path.replace("\\", "/")
    if normalized in {"rust/Cargo.lock", "rust/Cargo.toml"}:
        return True
    parts = PurePosixPath(normalized).parts
    if len(parts) >= 4 and parts[:2] == ("rust", "crates"):
        if len(parts) == 4 and parts[3] in {"Cargo.toml", "build.rs"}:
            return True
        return len(parts) >= 5 and parts[3] == "src" and parts[-1].endswith((".rs", ".json"))
    return False


def changed_regen_inputs(base_sha: str) -> ChangedRegenInputs:
    """Classify exact source inputs changed since ``base_sha``."""

    paths = _git_changed_paths(base_sha)
    return ChangedRegenInputs(
        contribution_paths=tuple(sorted(path for path in paths if path.startswith("contributions/"))),
        implementation_paths=tuple(sorted(path for path in paths if is_native_implementation_input(path))),
        report_paths=tuple(sorted(path for path in paths if is_decision_report_input(path))),
    )


def main() -> int:
    """Print regeneration status only after any requested base comparison succeeds."""
    pending_ids = sorted(contribution_ids() - catalog_ids())
    changed: list[str] = []
    changed_implementation: list[str] = []
    changed_report: list[str] = []
    if "--changed-from" in sys.argv:
        index = sys.argv.index("--changed-from")
        if index + 1 >= len(sys.argv) or sys.argv[index + 1].startswith("-"):
            print("--changed-from requires a base revision.", file=sys.stderr)
            return 2
        try:
            inputs = changed_regen_inputs(sys.argv[index + 1])
        except GitDiffError as error:
            print(str(error), file=sys.stderr)
            return 1
        changed = list(inputs.contribution_paths)
        changed_implementation = list(inputs.implementation_paths)
        changed_report = list(inputs.report_paths)
    pending = bool(pending_ids) or bool(changed) or bool(changed_implementation) or bool(changed_report)
    if "--flag" in sys.argv:
        print("true" if pending else "false")
    else:
        print(
            json.dumps(
                {
                    "pending": pending,
                    "pending_ids": pending_ids,
                    "changed_sources": changed,
                    "changed_implementation_inputs": changed_implementation,
                    "changed_decision_report_inputs": changed_report,
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
