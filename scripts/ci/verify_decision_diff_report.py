"""Verify deterministic decision evidence with source-only projection qualification."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT_PATHS = (
    "tests/fixtures/guard-command-corpus/decision-diff-report.json",
    "tests/fixtures/guard-command-corpus/decision-diff-report.framed-sha256",
)


def _run(command: list[str], *, strict_decision_report: bool = False) -> None:
    environment = None
    if strict_decision_report:
        environment = os.environ.copy()
        environment["HOL_GUARD_STRICT_DECISION_REPORT"] = "1"
    completed = subprocess.run(command, cwd=ROOT, check=False, env=environment)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def _rebuild_source_compiler(compiler: Path) -> None:
    """Refresh the compiler's embedded program after temporary projection generation."""

    resolved = compiler.resolve(strict=True)
    if resolved.name != "guard-command-source" or resolved.parent.name not in {"debug", "release"}:
        raise SystemExit("The native source compiler must live in a debug or release target profile")
    command = [
        "cargo",
        "+1.88.0",
        "build",
        "--locked",
        "--manifest-path",
        str(ROOT / "rust/Cargo.toml"),
    ]
    if resolved.parent.name == "release":
        command.append("--release")
    command.extend(("-p", "guard-command", "--bin", "guard-command-source"))
    _run(command)


def _source_only_inputs(base_sha: str) -> bool:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from detect_pending_extension_regen import GitDiffError, changed_regen_inputs

    try:
        changed = changed_regen_inputs(base_sha)
    except GitDiffError as error:
        raise SystemExit(str(error)) from error
    return bool(changed.contribution_paths or changed.implementation_paths or changed.report_paths)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--changed-from")
    args = parser.parse_args()

    report_command = [sys.executable, "tests/guard_command_decision_diff.py"]
    if args.changed_from is None or not _source_only_inputs(args.changed_from):
        _run([*report_command, "--check"], strict_decision_report=True)
        return 0

    from verify_native_command_program import GENERATED_PATHS

    generated_paths = (*GENERATED_PATHS, *REPORT_PATHS)
    try:
        _run(
            [
                sys.executable,
                "scripts/build_native_command_program.py",
                "--compiler",
                args.compiler,
            ]
        )
        _rebuild_source_compiler(Path(args.compiler))
        _run([*report_command, "--write"])
        _run([*report_command, "--check"], strict_decision_report=True)
    finally:
        _run(["git", "checkout", "--", *generated_paths])
        _run(["git", "clean", "-fdq", "--", *GENERATED_PATHS])
        _rebuild_source_compiler(Path(args.compiler))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
