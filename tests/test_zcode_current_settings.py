"""Current CLI settings take precedence over one-time migration input."""

import json

import pytest

from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode_config import is_guard_managed_hook_command
from tests.test_zcode_adapter import _ctx, _write_cli_config


def test_install_and_uninstall_preserve_current_settings(tmp_path):
    context = _ctx(tmp_path)
    legacy = _write_cli_config(context.home_dir, {"hooks": {}, "legacy": True})
    legacy_before = legacy.read_bytes()
    settings = legacy.with_name("setting.json")
    user_handler = {"type": "command", "command": "echo user"}
    payload = {
        "ui": {"theme": "dark"},
        "hooks": {"enabled": False, "events": {
            "PreToolUse": [{"matcher": "Read", "hooks": [user_handler]}],
        }},
    }
    settings.write_text(json.dumps(payload))
    adapter = ZCodeHarnessAdapter()
    manifest = adapter.install(context)
    installed = json.loads(settings.read_text())
    assert manifest["config_path"] == str(settings)
    assert installed["hooks"]["enabled"] is True
    assert installed["ui"] == payload["ui"]
    handlers = [handler for group in installed["hooks"]["events"]["PreToolUse"] for handler in group["hooks"]]
    assert user_handler in handlers
    assert any(is_guard_managed_hook_command(handler["command"]) for handler in handlers)
    assert legacy.read_bytes() == legacy_before
    detected = adapter.detect(context)
    assert str(settings) in detected.config_paths
    assert str(legacy) in detected.config_paths
    adapter.uninstall(context)
    remaining = json.loads(settings.read_text())
    assert remaining["ui"] == payload["ui"]
    handlers = [handler for group in remaining["hooks"]["events"]["PreToolUse"] for handler in group["hooks"]]
    assert handlers == [user_handler]
    assert legacy.read_bytes() == legacy_before


@pytest.mark.parametrize("contents", ["[]", "not json"])
def test_invalid_current_settings_do_not_fall_back_to_legacy(tmp_path, contents):
    context = _ctx(tmp_path)
    legacy = _write_cli_config(context.home_dir, {"legacy": True})
    settings = legacy.with_name("setting.json")
    settings.write_text(contents)
    with pytest.raises(ValueError):
        ZCodeHarnessAdapter().prepare_install(context)
    assert settings.read_text() == contents
    assert json.loads(legacy.read_text()) == {"legacy": True}
