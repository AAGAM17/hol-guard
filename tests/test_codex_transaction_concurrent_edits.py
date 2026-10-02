"""A failed Codex transaction must preserve intervening configuration edits."""

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_rollback as rollback
from codex_plugin_scanner.guard.adapters import codex as adapter_module
from codex_plugin_scanner.guard.adapters import codex_lifecycle_lock as locks
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter


@pytest.mark.parametrize("existing_installation", [False, True])
def test_config_edit_during_failed_write_survives_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_installation: bool
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    adapter = CodexHarnessAdapter()
    if existing_installation:
        adapter.install(context)
    config_path = adapter._hook_config_path(context)
    original_write = adapter_module.atomic_write_text
    concurrent_text = 'model = "user-selected-model"\n'
    injected = False

    def interrupted_write(path: Path, text: str, *, mode: int = 0o600) -> None:
        nonlocal injected
        if path == config_path and not injected:
            injected = True
            original_write(path, concurrent_text, mode=mode)
            raise OSError("injected configuration write failure after another writer")
        original_write(path, text, mode=mode)

    monkeypatch.setattr(adapter_module, "atomic_write_text", interrupted_write)
    with pytest.raises(RuntimeError, match="codex_hook_rollback_conflict"):
        adapter.install(context)

    assert injected
    assert config_path.is_file()
    assert config_path.read_text(encoding="utf-8") == concurrent_text
    assert not adapter_module.codex_native_hook_state(context)["protection_active"]


@pytest.mark.parametrize(
    "substitution",
    [
        "removed",
        "hardlink",
        pytest.param("symlink", marks=pytest.mark.skipif(os.name == "nt", reason="Windows symlink privileges")),
    ],
)
def test_failed_write_preserves_substituted_config_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, substitution: str
) -> None:
    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = CodexHarnessAdapter()
    adapter.install(context)
    config_path = adapter._hook_config_path(context)
    target = config_path.parent / "user-target.toml"
    target.write_bytes(b'owner = "other-writer"\n')
    original_write = adapter_module.atomic_write_text
    injected = False

    def interrupted_write(path: Path, text: str, *, mode: int = 0o600) -> None:
        nonlocal injected
        if path == config_path and not injected:
            injected = True
            path.unlink()
            if substitution == "symlink":
                path.symlink_to(target)
            elif substitution == "hardlink":
                os.link(target, path)
            raise OSError("injected write failure after target substitution")
        original_write(path, text, mode=mode)

    monkeypatch.setattr(adapter_module, "atomic_write_text", interrupted_write)
    with pytest.raises(RuntimeError, match="codex_hook_rollback_conflict"):
        adapter.install(context)

    assert injected
    assert target.read_bytes() == b'owner = "other-writer"\n'
    if substitution == "removed":
        assert not config_path.exists()
    elif substitution == "symlink":
        assert config_path.is_symlink()
    else:
        assert config_path.stat().st_ino == target.stat().st_ino
        assert config_path.stat().st_nlink == 2


def test_failed_descriptor_wrapping_releases_the_open_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b"original")
    opened: list[int] = []

    def failed_fdopen(descriptor: int, mode: str) -> None:
        opened.append(descriptor)
        raise OSError("injected descriptor wrapping failure")

    monkeypatch.setattr(rollback.os, "fdopen", failed_fdopen)
    with pytest.raises(RuntimeError, match="codex_hook_rollback_conflict"):
        rollback.require_unchanged_config_for_rollback(path, b"original", b"candidate")

    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    assert path.read_bytes() == b"original"
