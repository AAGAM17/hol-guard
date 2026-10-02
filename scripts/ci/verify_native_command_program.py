"""Verify the generated native command program, tolerating source-only refs.

Generated projections are maintainer-owned. A contribution PR that adds or
edits canonical sources legitimately leaves the checked-in program stale, so a
plain ``--check`` would reject an otherwise-valid contribution. This wrapper:

- fresh tree: runs ``build_native_command_program.py --check`` as before
- source-only tree (new/edited contribution source, native implementation,
  or decision-report input): runs the generator without ``--check``, rebuilds
  the native binaries, then runs a strict check against the generated
  workspace projections so subsequent proofs and packaging use the same
  program
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATED_PATHS = (
    "contracts/extensions",
    "contributions/extensions",
    "src/codex_plugin_scanner/guard/contracts/data/extensions",
    "src/codex_plugin_scanner/guard/extension_builder",
)


def _rebuild_command(compiler: str) -> list[str]:
    path = ROOT / compiler
    relative = path.resolve().relative_to((ROOT / "rust" / "target").resolve())
    parts = relative.parts
    if len(parts) not in (2, 3) or parts[-2] not in ("debug", "release"):
        raise ValueError("compiler must be in rust/target/[target/]debug or release")
    command = [
        "cargo",
        "build",
        "--manifest-path",
        "rust/Cargo.toml",
        "--locked",
        "-p",
        "hol-guard-runtime",
        "-p",
        "guard-command",
        "--bin",
        "hol-guard-runtime",
        "--bin",
        "guard-command-source",
    ]
    if parts[-2] == "release":
        command.append("--release")
    if len(parts) == 3:
        command.extend(["--target", parts[0]])
    return command


def _run(command: list[str]) -> None:
    """Propagate a failed command before later verification stages execute."""
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> int:
    """Choose strict or pending-source validation from a successful comparison."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--changed-from")
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from detect_pending_extension_regen import GitDiffError
    except ImportError:
        from detect_pending_extension_regen import ContributionDiffError as GitDiffError
    from detect_pending_extension_regen import catalog_ids, contribution_ids

    try:
        from detect_pending_extension_regen import changed_regen_inputs
    except ImportError:
        changed_regen_inputs = None
    pending = sorted(contribution_ids() - catalog_ids())
    changed = []
    changed_implementation = []
    changed_report = []
    if args.changed_from is not None:
        try:
            if changed_regen_inputs is not None:
                inputs = changed_regen_inputs(args.changed_from)
                changed = list(inputs.contribution_paths)
                changed_implementation = list(inputs.implementation_paths)
                changed_report = list(inputs.report_paths)
            else:
                raise GitDiffError("The regeneration detector does not expose the exact changed-input classifier")
        except GitDiffError as error:
            print(str(error), file=sys.stderr)
            return 1
    command = [
        sys.executable,
        "scripts/build_native_command_program.py",
        "--compiler",
        args.compiler,
    ]
    if args.changed_from is not None and (pending or changed or changed_implementation or changed_report):
        print(
            f"source-only projection regeneration (ids={pending}, changed={changed}, "
            f"implementation={changed_implementation}, report={changed_report}); "
            "validating sources by generating instead of checking freshness",
            file=sys.stderr,
        )
        rebuild = _rebuild_command(args.compiler)
        _run(command)
        _run(rebuild)
        _run([*command, "--check"])
        return 0
    _run([*command, "--check"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
