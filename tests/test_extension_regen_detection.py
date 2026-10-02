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
                "src/codex_plugin_scanner/guard/runtime/command_model.py\0"
                "tests/guard_command_decision_diff.py\0"
                "README.md\0"
                "contributions/command-sources/command.example.json\0"
            ),
        )

    monkeypatch.setattr(detector.subprocess, "run", fake_run)

    changed = detector.changed_regen_inputs("a" * 40)

    assert changed.contribution_paths == ("contributions/command-sources/command.example.json",)
    assert changed.implementation_paths == (
        "rust/Cargo.toml",
        "rust/crates/guard-command/build.rs",
        "rust/crates/guard-command/src/native_command_source.rs",
    )
    assert changed.report_paths == (
        "rust/crates/guard-command/src/native_command_source.rs",
        "src/codex_plugin_scanner/guard/runtime/command_model.py",
        "tests/guard_command_decision_diff.py",
    )
    assert not detector.is_native_implementation_input("rust/crates/guard-command/tests/fixture.json")
    assert not detector.is_native_implementation_input("README.md")
    assert detector.is_decision_report_input("src/codex_plugin_scanner/guard/runtime/deleted.py")
    assert detector.is_decision_report_input("tests/guard_command_corpus_deleted.py")
    assert not detector.is_decision_report_input("contracts/extensions/command-catalog.v1.json")
    assert not detector.is_decision_report_input("contracts/extensions/native-command-program.v1.json")
    assert not detector.is_decision_report_input("src/codex_plugin_scanner/guard/runtime/nested/deleted.py")
    assert not detector.is_decision_report_input("tests/support/extension_freshness.py")


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
        detector.changed_regen_inputs("a" * 40)


def test_verifier_generates_rebuilds_and_checks_for_implementation_only_changes(
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
    monkeypatch.setattr(
        sys,
        "argv",
        ["verify", "--compiler", "rust/target/release/guard-command-source", "--changed-from", "base-sha"],
    )

    assert verifier.main() == 0

    assert calls[0] == [
        sys.executable,
        "scripts/build_native_command_program.py",
        "--compiler",
        "rust/target/release/guard-command-source",
    ]
    assert calls[1][0] == "cargo"
    assert calls[2][-1] == "--check"


def test_verifier_generates_for_decision_report_only_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(detector, "contribution_ids", lambda: set())
    monkeypatch.setattr(detector, "catalog_ids", lambda: set())
    monkeypatch.setattr(
        detector,
        "changed_regen_inputs",
        lambda _: detector.ChangedRegenInputs((), (), ("tests/guard_command_decision_diff.py",)),
    )
    monkeypatch.setattr(verifier, "_run", calls.append)
    monkeypatch.setattr(
        sys,
        "argv",
        ["verify", "--compiler", "rust/target/release/guard-command-source", "--changed-from", "base-sha"],
    )

    assert verifier.main() == 0

    assert calls[0][-1] != "--check"
    assert calls[1][0] == "cargo"
    assert calls[2][-1] == "--check"


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
