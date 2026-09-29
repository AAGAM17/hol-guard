"""Generated Cursor hooks cannot allow unparsed actions without Guard imports."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source


@pytest.mark.parametrize(
    "event",
    ["beforeReadFile", "beforeShellExecution", "beforeMCPExecution", "beforeWriteFile", ""],
)
def test_generated_cursor_import_failure_denies_unparsed_actions(tmp_path: Path, event: str) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    unavailable = [sys.executable, "-S", "-c", "raise AssertionError('Unparsed input must not invoke an evaluator')"]
    script = tmp_path / "cursor-hook.py"
    script.write_text(
        cursor_hook_script_source(context, guard_cli=unavailable, recovery_command=unavailable), encoding="utf-8"
    )
    command = [sys.executable, "-S", str(script)]
    if event:
        command.extend(["--cursor-hook-event", event])
    result = subprocess.run(
        command,
        input="",
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(context.home_dir)},
        timeout=10,
        check=False,
    )
    assert result.returncode == 2, result.stderr
    response = json.loads(result.stdout)
    assert response["permission"] == "deny"
    assert response["user_message"] == (
        "Guard could not process this hook request safely. Retry or repair Guard from a terminal."
    )
