"""Blocked request behavior is global, persisted, and opt-in for prompting."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config, update_guard_settings


def test_prompt_mode_defaults_and_round_trip(tmp_path: Path) -> None:
    assert GuardConfig(guard_home=tmp_path, workspace=None).blocked_request_mode == "safe-alternative"
    assert load_guard_config(tmp_path).blocked_request_mode == "safe-alternative"
    update_guard_settings(tmp_path, {"blocked_request_mode": "ask"})
    assert load_guard_config(tmp_path).blocked_request_mode == "ask"
    update_guard_settings(tmp_path, {"blocked_request_mode": "safe-alternative"})
    assert load_guard_config(tmp_path).blocked_request_mode == "safe-alternative"


@pytest.mark.parametrize("value", ["always-allow", None, True, {}])
def test_prompt_mode_rejects_invalid_settings(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError):
        update_guard_settings(tmp_path, {"blocked_request_mode": value})


def test_workspace_cannot_enable_prompts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".hol-guard.toml").write_text('blocked_request_mode = "ask"\n')
    assert load_guard_config(tmp_path / "guard-home", workspace=workspace).blocked_request_mode == "safe-alternative"
