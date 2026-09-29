"""Onefile extraction-dir owner markers and orphan reclamation."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import onefile_extraction
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.onefile_extraction import (
    OWNER_MARKER_NAME,
    ExtractionReclaimResult,
    is_onefile_extraction_dir,
    reclaim_orphaned_extraction_dirs,
    record_extraction_owner,
)

_ENTRY_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mdm" / "hol-guard-entry.py"
_SENTINEL_PARTS = ("codex_plugin_scanner", "guard", "daemon", "static", "index.html")
_NOW = datetime(2026, 2, 1, tzinfo=timezone.utc)
_OLD_AGE_SECONDS = 20 * 60


def _extraction_dir(temp_root: Path, name: str = "_MEIabc123") -> Path:
    directory = temp_root / name
    directory.mkdir(parents=True)
    return directory


def _age_directory(directory: Path) -> None:
    """Backdate dir mtime after contents are written; file writes bump it."""

    stamp = _NOW.timestamp() - _OLD_AGE_SECONDS
    os.utime(directory, (stamp, stamp))


def _write_marker(directory: Path, *, pid: int = 4242, parent_pid: int = 4241) -> Path:
    marker = directory / OWNER_MARKER_NAME
    marker.write_text(
        json.dumps(
            {
                "schema": "guard.onefile-extraction-owner.v1",
                "pid": pid,
                "parent_pid": parent_pid,
                "started_at": _NOW.isoformat(),
                "guard_version": "0.0.0-test",
            }
        ),
        encoding="utf-8",
    )
    return marker


def _no_live_pids(pid: int) -> bool:
    return False


def _all_live_pids(pid: int) -> bool:
    return True


def test_is_onefile_extraction_dir_requires_mei_name_and_real_directory(tmp_path: Path) -> None:
    extraction = _extraction_dir(tmp_path)
    assert is_onefile_extraction_dir(extraction, tmp_path)
    assert not is_onefile_extraction_dir(tmp_path / "_MEImissing0", tmp_path)
    assert not is_onefile_extraction_dir(_extraction_dir(tmp_path, "other"), tmp_path)
    assert not is_onefile_extraction_dir(_extraction_dir(tmp_path, "_MEIab"), tmp_path)

    not_a_dir = tmp_path / "_MEIfile000"
    not_a_dir.write_text("x", encoding="utf-8")
    assert not is_onefile_extraction_dir(not_a_dir, tmp_path)

    nested_root = tmp_path / "nested"
    nested = _extraction_dir(nested_root)
    assert not is_onefile_extraction_dir(nested, tmp_path)


def test_is_onefile_extraction_dir_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = tmp_path / "_MEIlink99"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert not is_onefile_extraction_dir(link, tmp_path)


def test_record_extraction_owner_marks_real_extraction_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    extraction = _extraction_dir(tmp_path)

    assert record_extraction_owner(meipass=str(extraction), temp_root=tmp_path)

    marker = extraction / OWNER_MARKER_NAME
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["schema"] == "guard.onefile-extraction-owner.v1"
    assert payload["pid"] == os.getpid()
    assert payload["parent_pid"] == os.getppid()
    assert isinstance(payload["started_at"], str)
    assert isinstance(payload["guard_version"], str) and payload["guard_version"]
    assert str(tmp_path) not in marker.read_text(encoding="utf-8")
    mode = stat.S_IMODE(marker.stat().st_mode)
    if os.name != "nt":
        assert mode == 0o600


def test_record_extraction_owner_skips_onedir_and_non_frozen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extraction = _extraction_dir(tmp_path)

    monkeypatch.delattr(sys, "frozen", raising=False)
    assert not record_extraction_owner(meipass=str(extraction), temp_root=tmp_path)

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    onedir = tmp_path / "hol-guard"
    onedir.mkdir()
    assert not record_extraction_owner(meipass=str(onedir), temp_root=tmp_path)
    assert not record_extraction_owner(meipass=None, temp_root=tmp_path)
    assert not record_extraction_owner(meipass="", temp_root=tmp_path)
    outside_root = tmp_path / "other-root"
    nested = _extraction_dir(outside_root)
    assert not record_extraction_owner(meipass=str(nested), temp_root=tmp_path)
    assert not (extraction / OWNER_MARKER_NAME).exists()


def test_record_extraction_owner_never_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert not record_extraction_owner(meipass=str(tmp_path / "_MEImissing0"), temp_root=tmp_path)


def test_reclaim_deletes_dead_owner_dir_and_counts_bytes(tmp_path: Path) -> None:
    extraction = _extraction_dir(tmp_path)
    (extraction / "blob.bin").write_bytes(b"x" * 100)
    _write_marker(extraction, pid=4242, parent_pid=4241)
    _age_directory(extraction)

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.reclaimed_count == 1
    assert result.killed_launches == 1
    assert result.reclaimed_bytes >= 100
    assert not extraction.exists()
    assert result.errors == []


def test_reclaim_keeps_dirs_whose_owner_or_parent_is_alive(tmp_path: Path) -> None:
    pid_alive_dir = _extraction_dir(tmp_path, "_MEIalive00")
    _write_marker(pid_alive_dir, pid=1, parent_pid=2)
    parent_alive_dir = _extraction_dir(tmp_path, "_MEIparent0")
    _write_marker(parent_alive_dir, pid=3, parent_pid=4)
    _age_directory(pid_alive_dir)
    _age_directory(parent_alive_dir)

    live = {1, 4}
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=lambda pid: pid in live,
    )

    assert result.reclaimed_count == 0
    assert pid_alive_dir.exists()
    assert parent_alive_dir.exists()


def test_reclaim_skips_young_and_current_extraction_dirs(tmp_path: Path) -> None:
    young = _extraction_dir(tmp_path, "_MEIyoung00")
    _write_marker(young, pid=5, parent_pid=6)
    current = _extraction_dir(tmp_path, "_MEIcurrent")
    _write_marker(current, pid=7, parent_pid=8)
    _age_directory(current)

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=str(current),
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.reclaimed_count == 0
    assert young.exists()
    assert current.exists()


def test_reclaim_counts_unmarked_guard_dirs_without_deleting(tmp_path: Path) -> None:
    legacy = _extraction_dir(tmp_path, "_MEIlegacy0")
    sentinel = legacy.joinpath(*_SENTINEL_PARTS)
    sentinel.parent.mkdir(parents=True)
    sentinel.write_bytes(b"<html></html>")
    non_guard = _extraction_dir(tmp_path, "_MEIother00")
    (non_guard / "unrelated.bin").write_bytes(b"y" * 10)
    _age_directory(legacy)
    _age_directory(non_guard)

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.unmarked_count == 1
    assert result.unmarked_bytes_estimate >= len(b"<html></html>")
    assert result.reclaimed_count == 0
    assert legacy.exists()
    assert non_guard.exists()


def test_reclaim_unmarked_byte_sampling_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for index in range(15):
        legacy = _extraction_dir(tmp_path, f"_MEIlegacy{index}")
        sentinel = legacy.joinpath(*_SENTINEL_PARTS)
        sentinel.parent.mkdir(parents=True)
        sentinel.write_bytes(b"<html></html>")
        _age_directory(legacy)

    walks: list[Path] = []
    original = onefile_extraction._dir_bytes

    def counting_walk(root: Path) -> int:
        walks.append(root)
        return original(root)

    monkeypatch.setattr(onefile_extraction, "_dir_bytes", counting_walk)
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.unmarked_count == 15
    assert len(walks) == 10
    assert result.unmarked_bytes_estimate == round(sum(original(path) for path in walks) / 10 * 15)


def test_reclaim_ignores_symlinked_extraction_dirs(tmp_path: Path) -> None:
    nested_root = tmp_path / "real"
    target = _extraction_dir(nested_root, "_MEItarget0")
    _write_marker(target, pid=9, parent_pid=10)
    link = tmp_path / "_MEIlink000"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")

    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert link.is_symlink()
    assert result.reclaimed_count == 0
    assert result.unmarked_count == 0
    assert target.exists()


def test_reclaim_rechecks_marker_before_deleting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extraction = _extraction_dir(tmp_path)
    _write_marker(extraction, pid=11, parent_pid=12)
    _age_directory(extraction)

    original = onefile_extraction._read_owner_marker
    calls: list[Path] = []

    def flaky_marker(marker_path: Path) -> dict[str, int] | None:
        calls.append(marker_path)
        if len(calls) > 1:
            return None
        return original(marker_path)

    monkeypatch.setattr(onefile_extraction, "_read_owner_marker", flaky_marker)
    result = reclaim_orphaned_extraction_dirs(
        temp_root=tmp_path,
        current_meipass=None,
        now=_NOW,
        pid_alive=_no_live_pids,
    )

    assert result.reclaimed_count == 0
    assert extraction.exists()
    assert len(calls) == 2


def test_entry_records_owner_after_fast_paths_before_guard_imports() -> None:
    source = _ENTRY_SCRIPT.read_text(encoding="utf-8")
    bridge = source.index("_try_codex_daemon_bridge()")
    record = source.index("record_extraction_owner(meipass=")
    heavy = source.index("from codex_plugin_scanner.guard.frozen_daemon_runtime import")
    assert bridge < record < heavy


class _StubDiagnostics:
    def __init__(self) -> None:
        self.events: list[str] = []

    def record(self, event: str, *, detail: str | None = None) -> bool:
        self.events.append(event)
        return True

    def record_exception(self, event: str, **kwargs: object) -> bool:
        self.events.append(event)
        return True


def _bare_daemon_server() -> GuardDaemonServer:
    server = GuardDaemonServer.__new__(GuardDaemonServer)
    server._shutdown_started = threading.Event()
    server._onefile_extraction_reclaim_thread = None
    server.onefile_extraction_status = None
    server._diagnostics = _StubDiagnostics()
    return server


def test_reclaim_worker_starts_only_when_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    server = _bare_daemon_server()
    server._start_onefile_extraction_reclaim()
    assert server._onefile_extraction_reclaim_thread is None

    calls: list[dict[str, object]] = []

    def fake_reclaim(**kwargs: object) -> ExtractionReclaimResult:
        calls.append(kwargs)
        return ExtractionReclaimResult(
            reclaimed_count=2,
            reclaimed_bytes=2048,
            killed_launches=2,
            unmarked_count=1,
            unmarked_bytes_estimate=512,
        )

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(onefile_extraction, "reclaim_orphaned_extraction_dirs", fake_reclaim)
    server._start_onefile_extraction_reclaim()
    thread = server._onefile_extraction_reclaim_thread
    assert thread is not None
    try:
        deadline = time.monotonic() + 5
        while not calls and time.monotonic() < deadline:
            time.sleep(0.01)
        assert calls, "reclaim worker never ran"
        assert calls[0]["temp_root"] == Path(tempfile.gettempdir())
        assert calls[0]["current_meipass"] is None

        status = server.onefile_extraction_status
        assert status is not None
        assert status["reclaimed_count"] == 2
        assert status["reclaimed_bytes"] == 2048
        assert status["killed_launches_last_run"] == 2
        assert status["unmarked_legacy_count"] == 1
        assert status["unmarked_legacy_bytes_estimate"] == 512
        assert isinstance(status["last_run_at"], str)
        assert "onefile_extraction_reclaimed" in server._diagnostics.events
    finally:
        server._shutdown_started.set()
        thread.join(timeout=5)
    assert not thread.is_alive()


def test_detailed_healthz_exposes_onefile_extraction_status() -> None:
    import inspect

    from codex_plugin_scanner.guard.daemon import server as server_module

    source = inspect.getsource(server_module._GuardDaemonHandler._detailed_healthz_payload)
    assert '"onefile_extraction": daemon_server.onefile_extraction_status' in source
