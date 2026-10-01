"""Concurrent lifecycle callers must not discover or mutate the same files."""

import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.adapters.codex_lifecycle_lock import codex_lifecycle_locks


@pytest.mark.parametrize("competing_operation", ("install", "uninstall"))
def test_competing_lifecycle_call_is_rejected_before_discovery(tmp_path, monkeypatch, competing_operation):
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    entered = Event()
    release = Event()
    calls = []

    def paused_discovery(self, current_context):
        calls.append(current_context)
        entered.set()
        assert release.wait(5), "test owner was not released"
        raise RuntimeError("test_discovery_complete")

    monkeypatch.setattr(CodexHarnessAdapter, "detect", paused_discovery)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(CodexHarnessAdapter().install, context)
        try:
            assert entered.wait(5), "test owner did not enter discovery"
            with pytest.raises(RuntimeError, match="codex_lifecycle_busy"):
                getattr(CodexHarnessAdapter(), competing_operation)(context)
            assert calls == [context]
        finally:
            release.set()
        with pytest.raises(RuntimeError, match="test_discovery_complete"):
            first.result(timeout=5)


def _hold_process_lock(home, guard_home, connection):
    context = HarnessContext(home_dir=Path(home), workspace_dir=None, guard_home=Path(guard_home))
    with codex_lifecycle_locks(context):
        connection.send(True)
        connection.recv()


@pytest.mark.parametrize("owner_exit", ("normal", "interrupted"))
def test_separate_installation_owners_contend_and_process_exit_releases_lock(tmp_path, owner_exit):
    spawn = multiprocessing.get_context("spawn")
    parent_connection, child_connection = spawn.Pipe()
    home = tmp_path / "home"
    child = spawn.Process(target=_hold_process_lock, args=(str(home), str(tmp_path / "first-guard"), child_connection))
    child.start()
    child_connection.close()
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "second-guard")
    try:
        assert parent_connection.poll(5), "test owner did not acquire its lock"
        assert parent_connection.recv() is True
        with pytest.raises(RuntimeError, match="codex_lifecycle_busy"), codex_lifecycle_locks(context):
            pytest.fail("competing owner entered")
        if owner_exit == "normal":
            parent_connection.send("release")
        else:
            child.terminate()
        child.join(timeout=5)
        assert not child.is_alive()
        if owner_exit == "normal":
            assert child.exitcode == 0
        with codex_lifecycle_locks(context):
            pass
    finally:
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)
        parent_connection.close()


def test_shared_workspace_contends_between_different_home_directories(tmp_path):
    workspace = tmp_path / "workspace"
    first = HarnessContext(home_dir=tmp_path / "one", workspace_dir=workspace, guard_home=tmp_path / "guard-one")
    second = HarnessContext(home_dir=tmp_path / "two", workspace_dir=workspace, guard_home=tmp_path / "guard-two")
    with (
        codex_lifecycle_locks(first),
        pytest.raises(RuntimeError, match="codex_lifecycle_busy"),
        codex_lifecycle_locks(second),
    ):
        pytest.fail("competing workspace owner entered")
    with codex_lifecycle_locks(second):
        pass


@pytest.mark.parametrize("link_kind", ("symbolic", "hard"))
def test_lock_links_are_rejected_without_changing_the_target(tmp_path, link_kind):
    home = tmp_path / "home"
    directory = home / ".codex"
    directory.mkdir(parents=True)
    target = tmp_path / "user-file"
    target.write_bytes(b"preserved user content")
    lock = directory / ".hol-guard-lifecycle.lock"
    if link_kind == "symbolic":
        lock.symlink_to(target)
    else:
        lock.hardlink_to(target)
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard")
    with pytest.raises(RuntimeError, match="codex_lifecycle_lock_invalid"), codex_lifecycle_locks(context):
        pytest.fail("linked lock accepted")
    assert target.read_bytes() == b"preserved user content"
