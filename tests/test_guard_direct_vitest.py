"""Caller regressions after direct-tool authority moved into the resident."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.runtime import direct_vitest
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)
from codex_plugin_scanner.guard.runtime.shell_execution_context import (
    ShellExecutionContext,
    model_shell_execution_context,
)


def _accepted_native_context(
    tool: str, command_text: str, *, cwd: Path | None, home_dir: Path
) -> ShellExecutionContext | None:
    # The recognizer's positive service fact is covered by the frozen native
    # vectors. Here the real native shell model supplies filesystem proofs so
    # consumer regressions still exercise their independent execution gates.
    if tool != "vitest":
        return None
    workspace = Path(command_text.split(" && ", 1)[0].removeprefix("cd "))
    context = model_shell_execution_context(command_text, cwd=workspace, workspace_root=workspace, home_dir=home_dir)
    assert context.complete, context.reason_code
    return context


@pytest.fixture(autouse=True)
def _native_vitest_intents(package_intent_native, native_mcp_probe, tmp_path: Path) -> None:
    native_mcp_probe(tmp_path / "home" / ".guard")


@pytest.fixture(autouse=True)
def _exclude_workspace_virtualenv_from_path(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = Path().resolve()
    entries: list[str] = []
    for raw_entry in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(raw_entry or ".").expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        try:
            _ = candidate.resolve().relative_to(workspace)
        except (OSError, RuntimeError):
            continue
        except ValueError:
            entries.append(raw_entry)
    monkeypatch.setenv("PATH", os.pathsep.join(entries))


def _write_package(root: Path, *, include_lock: bool = True, declares_vitest: bool = True) -> None:
    root.mkdir(parents=True, exist_ok=True)
    dependencies = {"vitest": "^4.1.8"} if declares_vitest else {}
    _ = (root / "package.json").write_text(
        json.dumps({"name": "fixture", "devDependencies": dependencies}),
        encoding="utf-8",
    )
    if include_lock:
        _ = (root / "bun.lock").write_text(
            json.dumps({"packages": {"vitest": ["vitest@4.1.8"]}}),
            encoding="utf-8",
        )


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    home = tmp_path / "home"
    caller = home / "caller"
    workspace = tmp_path / "subject"
    runner_project = home / "runner-project"
    _write_package(workspace)
    _write_package(runner_project)
    caller.mkdir(parents=True)
    test_file = workspace / "tests" / "unit.test.ts"
    test_file.parent.mkdir()
    _ = test_file.write_text("export {};\n", encoding="utf-8")
    package_dir = runner_project / "node_modules" / "vitest"
    package_dir.mkdir(parents=True)
    _ = (package_dir / "package.json").write_text(
        json.dumps({"name": "vitest", "version": "4.1.8", "bin": {"vitest": "./vitest.mjs"}}),
        encoding="utf-8",
    )
    runner = package_dir / "vitest.mjs"
    _ = runner.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    runner.chmod(0o755)
    bin_directory = runner_project / "node_modules" / ".bin"
    bin_directory.mkdir()
    _ = (bin_directory / "vitest").symlink_to("../vitest/vitest.mjs")
    return home, caller, workspace, runner


def _command(workspace: Path, runner: Path, *, suffix: str = "--no-coverage 2>&1 | tail -40") -> str:
    return f"cd {workspace} && {runner} run tests/unit.test.ts {suffix}"


def test_verified_direct_vitest_identity_does_not_bypass_uncontained_code_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    command = _command(workspace, runner)
    monkeypatch.setattr(direct_vitest, "native_direct_tool_context", _accepted_native_context)
    request = extract_sensitive_tool_action_request("bash", {"command": command}, cwd=caller, home_dir=home)
    assert request is not None
    assert request.guard_default_action == "require-reapproval"
    assert not is_explicitly_benign_tool_action_request("bash", {"command": command}, cwd=caller, home_dir=home)
    # A verified launch location is not isolation from local credentials.
    assert (
        _hook_runtime_artifact(
            harness="pi",
            payload={"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": command}},
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=caller,
        )
        is not None
    )


def test_verified_npx_vitest_still_requires_execution_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    _ = (workspace / "node_modules").symlink_to(runner.parents[1], target_is_directory=True)
    command = f"cd {workspace} && npx vitest run tests/unit.test.ts 2>&1 | tail -40"
    # The direct recognizers refuse npx launches; package evidence and the
    # independent execution-authority gate still decide this caller case.
    monkeypatch.setattr(direct_vitest, "native_direct_tool_context", lambda *_args, **_kwargs: None)

    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=caller,
            home_dir=home,
        )
        is None
    )
    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )
    assert (
        _hook_runtime_artifact(
            harness="codex",
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": command},
            },
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=caller,
        )
        is not None
    )
