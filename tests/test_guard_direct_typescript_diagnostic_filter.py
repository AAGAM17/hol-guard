"""Caller regressions after direct-tool authority moved into the resident."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
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
    if tool != "typescript":
        return None
    workspace = Path(command_text.split(" && ", 1)[0].removeprefix("cd "))
    context = model_shell_execution_context(command_text, cwd=workspace, workspace_root=workspace, home_dir=home_dir)
    assert context.complete, context.reason_code
    return context


@pytest.fixture(autouse=True)
def _native_typescript_intents(
    package_intent_native: Path,
    native_mcp_probe: Callable[[Path], None],
    tmp_path: Path,
) -> None:
    native_mcp_probe(tmp_path / "home" / ".guard")


def _fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, native_context_accepted: bool = True
) -> tuple[Path, Path, str]:
    for key in tuple(os.environ):
        normalized_key = key.casefold()
        if (
            key.startswith(("BASH_FUNC_", "DYLD_", "LD_"))
            or normalized_key.startswith("npm_config_")
            or normalized_key in {"bash_env", "env", "node_options", "node_path", "zdotdir"}
        ):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    caller = home / "caller"
    workspace = tmp_path / "subject"
    caller.mkdir(parents=True)
    package_dir = workspace / "node_modules" / "typescript"
    compiler = package_dir / "bin" / "tsc"
    compiler.parent.mkdir(parents=True)
    _ = compiler.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    _ = (package_dir / "package.json").write_text(
        json.dumps({"name": "typescript", "version": "5.9.3", "bin": {"tsc": "./bin/tsc"}}),
        encoding="utf-8",
    )
    bin_directory = workspace / "node_modules" / ".bin"
    bin_directory.mkdir()
    _ = (bin_directory / "tsc").symlink_to("../typescript/bin/tsc")
    _ = (workspace / "package.json").write_text(
        json.dumps({"name": "fixture", "devDependencies": {"typescript": "^5.9.3"}}),
        encoding="utf-8",
    )
    _ = (workspace / "bun.lock").write_text(
        json.dumps(
            {
                "packages": {
                    "typescript": [
                        "typescript@5.9.3",
                        "",
                        {"bin": {"tsc": "bin/tsc"}},
                        (
                            "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdia"
                            "UpFT4bXlb1RHhLpp8wtm6M5TgSw=="
                        ),
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    if native_context_accepted:
        monkeypatch.setattr(direct_vitest, "native_direct_tool_context", _accepted_native_context)
    else:
        monkeypatch.setattr(direct_vitest, "native_direct_tool_context", lambda *_args, **_kwargs: None)
    command = (
        f"cd {workspace} && npx tsc --noEmit 2>&1 "
        '| grep -E "harnesses/page|enterprises/page" || echo "NO_ERRORS_IN_TOUCHED_FILES"'
    )
    return home, caller, command


def test_verified_typescript_diagnostic_filter_is_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)

    request = extract_sensitive_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )

    assert request is None
    assert is_explicitly_benign_tool_action_request(
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
                "tool_name": "Bash",
                "tool_input": {"command": command},
            },
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=caller,
        )
        is None
    )


def test_typescript_diagnostic_filter_accepts_escaped_literal_dots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)

    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command.replace("harnesses/page|enterprises/page", r"src/page\.tsx|app/route\.tsx")},
        cwd=caller,
        home_dir=home,
    )


def test_verified_routine_typescript_pipeline_is_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    source = workspace / "src" / "index.ts"
    source.parent.mkdir()
    _ = source.write_text("export const value = 1;\n", encoding="utf-8")
    command = (
        f"cd {workspace} && npx tsc --noEmit --types @cloudflare/workers-types "
        "--lib es2022 --target es2022 --module esnext --moduleResolution bundler "
        '--skipLibCheck src/index.ts 2>&1 | grep -v "npm warn" | head -8; echo "TSC_DONE"'
    )

    heap_command = command.replace("npx tsc", 'NODE_OPTIONS="--max-old-space-size=8192" npx tsc').replace(
        '| grep -v "npm warn" | head -8',
        "| head -40",
    )
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": heap_command},
        cwd=caller,
        home_dir=home,
    )

    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=caller,
            home_dir=home,
        )
        is None
    )
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


def test_verified_direct_typescript_diagnostic_is_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, caller, command = _fixture(tmp_path, monkeypatch)
    workspace = Path(command.split(" && ", 1)[0].removeprefix("cd "))
    source = workspace / "workers" / "services" / "risk.ts"
    source.parent.mkdir(parents=True)
    _ = source.write_text("export {};\n", encoding="utf-8")
    command = (
        f'cd {workspace} && NODE_OPTIONS="--max-old-space-size=8192" npx tsc --noEmit '
        + "--strict --skipLibCheck --esModuleInterop --moduleResolution bundler --module esnext --target es2022 "
        + str(source.relative_to(workspace))
    )
    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=caller,
            home_dir=home,
        )
        is None
    )
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )
    assert (
        _hook_runtime_artifact(
            harness="pi",
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
        is None
    )
