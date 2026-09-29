"""Bounded bridge failures cannot authorize protected actions by command shape."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

from .bounded_cli_hook_test_support import config

_HARNESSES = ["copilot", "grok", "hermes", "openclaw", "kimi", "zcode", "devin"]
_FAILURES = [
    BoundedHookProcessResult(None, "", False, True),
    BoundedHookProcessResult(None, "", False, False),
    BoundedHookProcessResult(1, "not-json", False, False),
]
_ACTIONS = [
    {"tool_name": "Read", "tool_input": {"file_path": "private.txt"}},
    {"tool_name": "Bash", "tool_input": {"command": "hol-guard doctor"}},
    {"tool_name": "Bash", "tool_input": {"command": "git push"}},
]


@pytest.mark.parametrize("harness", _HARNESSES)
@pytest.mark.parametrize("local_mode", ["prompt", "observe"])
@pytest.mark.parametrize("failure", _FAILURES, ids=["timeout", "not-started", "invalid-output"])
@pytest.mark.parametrize("action", _ACTIONS, ids=["read", "repair-shape", "mutation"])
def test_bounded_bridge_unavailable_pretool_denies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    harness: str,
    local_mode: str,
    failure: BoundedHookProcessResult,
    action: dict[str, object],
) -> None:
    monkeypatch.setattr(bridge, "run_isolated_hook_process", lambda *_args, **_kwargs: failure)
    monkeypatch.setattr(daemon, "try_daemon_hook", lambda **_kwargs: None)
    hook_config = config(tmp_path, harness=harness)
    config_path = Path(str(hook_config["guard_home"])) / "config.toml"
    config_bytes = f'mode = "{local_mode}"\n'.encode()
    config_path.write_bytes(config_bytes)
    result = bridge.run_bounded_cli_hook(
        hook_config,
        input_text=json.dumps({"hook_event_name": "PreToolUse", **action}),
    )
    response = json.loads(capsys.readouterr().out)
    assert config_path.read_bytes() == config_bytes
    if harness == "copilot":
        assert response["permissionDecision"] == "deny"
        assert result == 0
    elif harness in {"grok", "hermes", "openclaw"}:
        assert response["decision"] == ("block" if harness == "hermes" else "deny")
        assert result == (2 if harness == "hermes" else 0)
    else:
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert result == 2
