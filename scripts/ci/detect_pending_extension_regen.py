"""Detect source changes that require maintainer-owned projection regeneration.

Prints ``{"pending": ..., "pending_ids": [...]}`` (or a bare ``true``/``false``
with ``--flag``) when any canonical contribution under ``contributions/``
declares an extension id that the checked-in ``command-catalog.v1.json`` does
not contain, or when native implementation inputs changed from ``--changed-from``.
That state means the source-only ref is awaiting maintainer-owned projection
regeneration, so generated-artifact freshness gates should stand down for that
ref. Stdlib only; no repository imports.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "contracts/extensions/command-catalog.v1.json"


class GitDiffError(ValueError):
    """Raised when a comparison revision cannot be inspected safely."""


@dataclass(frozen=True)
class ChangedRegenInputs:
    """Inputs whose changes permit source-only projection validation."""

    contribution_paths: tuple[str, ...]
    implementation_paths: tuple[str, ...]


def contribution_ids() -> set[str]:
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
    catalog = json.loads(CATALOG.read_text())
    return {entry["extension_id"] for entry in catalog["catalog"]}


def _git_changed_paths(base_sha: str) -> list[str]:
    if not base_sha or not base_sha.strip():
        raise GitDiffError("A non-empty base revision is required for regeneration qualification.")

    command = ["git", "diff", "--name-only", "--no-renames", "-z", base_sha, "HEAD", "--"]

    def _diff() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    completed = _diff()
    if completed.returncode:
        # Shallow checkouts lack the base commit; fetch it and retry once.
        fetched = subprocess.run(
            ["git", "fetch", "--depth=1", "origin", base_sha],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if fetched.returncode == 0:
            completed = _diff()
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise GitDiffError(f"Could not determine changed files from base revision {base_sha!r}: {detail[:512]}")
    return [path for path in completed.stdout.split("\0") if path]


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
    """Classify exact contribution and native implementation inputs changed since ``base_sha``."""

    paths = _git_changed_paths(base_sha)
    return ChangedRegenInputs(
        contribution_paths=tuple(sorted(path for path in paths if path.startswith("contributions/"))),
        implementation_paths=tuple(sorted(path for path in paths if is_native_implementation_input(path))),
    )


def main() -> int:
    pending_ids = sorted(contribution_ids() - catalog_ids())
    changed: list[str] = []
    changed_implementation: list[str] = []
    if "--changed-from" in sys.argv:
        index = sys.argv.index("--changed-from")
        if index + 1 >= len(sys.argv) or sys.argv[index + 1].startswith("-"):
            print("--changed-from requires a base revision.", file=sys.stderr)
            return 2
        try:
            inputs = changed_regen_inputs(sys.argv[index + 1])
        except GitDiffError as error:
            print(str(error), file=sys.stderr)
            return 2
        changed = list(inputs.contribution_paths)
        changed_implementation = list(inputs.implementation_paths)
    pending = bool(pending_ids) or bool(changed) or bool(changed_implementation)
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
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
