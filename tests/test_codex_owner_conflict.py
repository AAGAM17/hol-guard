"""An unowned Guard-looking handler must not be removed or accepted as healthy."""

from __future__ import annotations

import json
import shlex
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_config import dump_toml, read_toml_payload
from codex_plugin_scanner.guard.codex_hook_registration import require_codex_hook_owner


@pytest.mark.parametrize("scope", ("group", "handler"))
@pytest.mark.parametrize("activation", ({"enabled": False}, {"disabled": True}))
def test_install_preserves_inactive_unowned_handlers(tmp_path, scope, activation):
    home = tmp_path / "home"
    config = home / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    handler = {"type": "command", "command": "python -m codex_plugin_scanner.cli guard hook --harness codex"}
    group = {"matcher": "Bash", "hooks": [handler]}
    (group if scope == "group" else handler).update(activation)
    config.write_text(dump_toml({"hooks": {"PreToolUse": [group]}}), encoding="utf-8")
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")
    CodexHarnessAdapter().install(context)
    groups = read_toml_payload(config)["hooks"]["PreToolUse"]
    assert group in groups
    assert len(groups) == 2


@pytest.mark.parametrize("argument", ("--harness codex-other", "--harness=codexevil", "--harness claude"))
def test_other_harness_module_hook_is_not_a_codex_conflict(argument):
    require_codex_hook_owner(
        "python -m codex_plugin_scanner.cli guard hook " + argument,
        ownership="unmanaged",
    )


@pytest.mark.parametrize("argument", ("--harness codex", "--harness=codex"))
def test_exact_codex_module_hook_requires_ownership(argument):
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(
            "python -m codex_plugin_scanner.cli guard hook " + argument,
            ownership="unmanaged",
        )


@pytest.mark.parametrize("binding_kind", ("same_home_bridge", "foreign_home_guard_cli"))
@pytest.mark.parametrize("source_format", ("toml", "json"))
@pytest.mark.parametrize("feature_enabled", (True, False))
def test_install_rejects_unowned_guard_bridge_without_committing(
    tmp_path: Path, binding_kind: str, source_format: str, feature_enabled: bool
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    config_path = home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    if binding_kind == "same_home_bridge":
        old_command = "python -I /opt/pipx/hol-guard/adapters/codex_daemon_hook_bridge.py " + shlex.quote(
            '{"state_path":"' + str(guard_home / "daemon-state.json") + '"}'
        )
    else:
        foreign_home = tmp_path / "other-guard-home"
        old_command = (
            "python -m codex_plugin_scanner.cli guard hook --harness codex "
            f"--guard-home {shlex.quote(str(foreign_home))}"
        )
    old_bridge = {"matcher": "Bash", "hooks": [{"type": "command", "command": old_command}]}
    third_party = {"matcher": "Bash", "hooks": [{"type": "command", "command": "lean-ctx hook observe"}]}
    events = ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")
    hook_payload = {"hooks": {event: [deepcopy(old_bridge), deepcopy(third_party)] for event in events}}
    hooks_path = config_path.with_name("hooks.json")
    config_payload = {"features": {"hooks": feature_enabled}, **(hook_payload if source_format == "toml" else {})}
    config_path.write_text(dump_toml(config_payload), encoding="utf-8")
    if source_format == "json":
        hooks_path.write_text(json.dumps(hook_payload), encoding="utf-8")
    before_json = hooks_path.read_bytes() if hooks_path.exists() else None
    before = config_path.read_bytes()
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    result: dict[str, object] | None = None
    failure: Exception | None = None
    try:
        result = CodexHarnessAdapter().install(context)
    except Exception as error:
        failure = error

    installed = (
        read_toml_payload(config_path)
        if source_format == "toml"
        else json.loads(hooks_path.read_text(encoding="utf-8"))
    )
    hooks = installed.get("hooks")
    assert isinstance(hooks, dict)
    group_counts = {event: len(groups) for event in events if isinstance((groups := hooks.get(event)), list)}
    pretool_groups = hooks.get("PreToolUse")
    assert isinstance(pretool_groups, list)
    commands = [
        handler["command"]
        for group in pretool_groups
        if isinstance(group, dict)
        for handler in group.get("hooks", [])
        if isinstance(handler, dict) and isinstance(handler.get("command"), str)
    ]
    manifest_path = codex_adapter.hook_manifest_path(guard_home, config_path)
    assert failure is not None, (
        "Install accepted an unowned Guard bridge; "
        f"event group counts are {group_counts}, active={result.get('active') if result else None}, "
        f"integrity={result.get('managed_hook_integrity') if result else None}, manifest={manifest_path.exists()}, "
        f"old_present={old_command in commands}, third_party_present={'lean-ctx hook observe' in commands}"
    )
    expected_reason = "codex_hook_owner_conflict" if feature_enabled else "codex_hook_inventory_unmanaged_executable"
    assert expected_reason in str(failure)
    assert config_path.read_bytes() == before
    if before_json is not None:
        assert hooks_path.read_bytes() == before_json
    assert not manifest_path.exists()
