from __future__ import annotations

import subprocess
import sys

import pytest

from scripts.ci import detect_pending_extension_regen as detector
from scripts.ci import verify_native_command_program as verifier


def _completed(
    command: list[str], *, returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def test_changed_regen_inputs_classifies_native_bound_and_unrelated_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        assert command[1] == "diff"
        return _completed(
            command,
            stdout=(
                "rust/Cargo.toml\0"
                "rust/crates/guard-command/build.rs\0"
                "rust/crates/guard-command/src/native_command_source.rs\0"
                "rust/crates/guard-command/tests/fixture.json\0"
                "README.md\0"
                "contributions/command-sources/command.example.json\0"
            ),
        )

    monkeypatch.setattr(detector.subprocess, "run", fake_run)

    changed = detector.changed_regen_inputs("base-sha")

    assert changed.contribution_paths == ("contributions/command-sources/command.example.json",)
    assert changed.implementation_paths == (
        "rust/Cargo.toml",
        "rust/crates/guard-command/build.rs",
        "rust/crates/guard-command/src/native_command_source.rs",
    )
    assert not detector.is_native_implementation_input("rust/crates/guard-command/tests/fixture.json")
    assert not detector.is_native_implementation_input("README.md")


def test_changed_regen_inputs_requires_a_base_revision() -> None:
    with pytest.raises(detector.GitDiffError, match="non-empty base revision"):
        detector.changed_regen_inputs("")


def test_changed_regen_inputs_fails_closed_when_git_diff_is_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if command[1] == "fetch":
            return _completed(command, returncode=1, stderr="unknown revision")
        return _completed(command, returncode=128, stderr="bad revision")

    monkeypatch.setattr(detector.subprocess, "run", fake_run)

    with pytest.raises(detector.GitDiffError, match="Could not determine changed files"):
        detector.changed_regen_inputs("invalid-sha")


def test_verifier_generates_and_restores_for_implementation_only_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(detector, "contribution_ids", lambda: set())
    monkeypatch.setattr(detector, "catalog_ids", lambda: set())
    monkeypatch.setattr(
        detector,
        "changed_regen_inputs",
        lambda _: detector.ChangedRegenInputs((), ("rust/Cargo.toml",)),
    )
    monkeypatch.setattr(verifier, "_run", calls.append)
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "compiler", "--changed-from", "base-sha"])

    assert verifier.main() == 0

    assert calls[0] == [
        sys.executable,
        "scripts/build_native_command_program.py",
        "--compiler",
        "compiler",
    ]
    assert calls[1][0:3] == ["git", "checkout", "--"]
    assert calls[2][0:3] == ["git", "clean", "-fdq"]


def test_verifier_keeps_strict_check_for_unrelated_or_current_main_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(detector, "contribution_ids", lambda: set())
    monkeypatch.setattr(detector, "catalog_ids", lambda: set())
    monkeypatch.setattr(
        detector,
        "changed_regen_inputs",
        lambda _: detector.ChangedRegenInputs((), ()),
    )
    monkeypatch.setattr(verifier, "_run", calls.append)

    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "compiler", "--changed-from", "base-sha"])
    assert verifier.main() == 0
    assert calls == [
        [
            sys.executable,
            "scripts/build_native_command_program.py",
            "--compiler",
            "compiler",
            "--check",
        ]
    ]

    calls.clear()
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "compiler"])
    assert verifier.main() == 0
    assert calls == [
        [
            sys.executable,
            "scripts/build_native_command_program.py",
            "--compiler",
            "compiler",
            "--check",
        ]
    ]
