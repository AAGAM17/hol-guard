"""Native implementation changes must enter the source-only PR preparation path."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def detector():
    path = Path(__file__).parents[1] / "scripts/ci/detect_pending_extension_regen.py"
    spec = importlib.util.spec_from_file_location("pending_native_artifact_regeneration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("changed", [
    "rust/crates/guard-command/src/parser_wrappers.rs",
    "rust/crates/guard-runtime/src/edge.rs",
    "rust/Cargo.lock",
    "contributions/command-sources/command.example.json",
])
def test_source_only_native_changes_report_pending(detector, monkeypatch, capsys, changed):
    def diff(command, **kwargs):
        assert command[-2:] == ["contributions/", "rust/"]
        return subprocess.CompletedProcess(command, 0, stdout=changed + "\n", stderr="")

    monkeypatch.setattr(subprocess, "run", diff)
    monkeypatch.setattr(detector, "contribution_ids", lambda: {"command.example"})
    monkeypatch.setattr(detector, "catalog_ids", lambda: {"command.example"})
    monkeypatch.setattr(sys, "argv", ["detector", "--changed-from", "a" * 40, "--flag"])
    assert detector.main() == 0
    assert capsys.readouterr().out == "true\n"


def test_unchanged_canonical_inputs_still_require_fresh_artifacts(detector, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, stdout="", stderr=""))
    monkeypatch.setattr(detector, "contribution_ids", lambda: {"command.example"})
    monkeypatch.setattr(detector, "catalog_ids", lambda: {"command.example"})
    monkeypatch.setattr(sys, "argv", ["detector", "--changed-from", "a" * 40, "--flag"])
    assert detector.main() == 0
    assert capsys.readouterr().out == "false\n"


@pytest.fixture
def verifier():
    path = Path(__file__).parents[1] / "scripts/ci/verify_native_command_program.py"
    spec = importlib.util.spec_from_file_location("native_program_verifier", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("compiler,target,release", [
    ("rust/target/release/guard-command-source", None, True),
    ("rust/target/debug/guard-command-source", None, False),
    ("rust/target/release/guard-command-source.exe", None, True),
    ("rust/target/x86_64-unknown-linux-musl/release/guard-command-source",
     "x86_64-unknown-linux-musl", True),
    ("rust/target/x86_64-apple-darwin/release/guard-command-source",
     "x86_64-apple-darwin", True),
])
def test_rebuild_uses_original_compiler_target(verifier, compiler, target, release):
    command = verifier._rebuild_command(compiler)
    assert ("--release" in command) is release
    assert (command[-2:] == ["--target", target]) if target else "--target" not in command
    assert "hol-guard-runtime" in command and "guard-command-source" in command


@pytest.mark.parametrize("pending", [True, False])
def test_preparation_retains_generated_outputs_and_checks_after_rebuild(
    verifier, monkeypatch, pending
):
    import types

    detector = types.SimpleNamespace(
        _contributions_changed=lambda base: ["rust/Cargo.lock"] if pending else [],
        catalog_ids=lambda: {"command.example"},
        contribution_ids=lambda: {"command.example"},
    )
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler",
                                    "rust/target/release/guard-command-source",
                                    "--changed-from", "a" * 40])
    commands = []
    monkeypatch.setattr(verifier, "_run", commands.append)
    assert verifier.main() == 0
    assert commands[-1][-1] == "--check"
    if pending:
        assert len(commands) == 3
        assert "--check" not in commands[0]
        assert commands[1][0] == "cargo"
    else:
        assert len(commands) == 1
    assert all(command[0] != "git" for command in commands)
