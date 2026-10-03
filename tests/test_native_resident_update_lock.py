"""Cross-process native resident replacement barrier tests."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.native_resident_update_lock import (
    NativeResidentUpdateLockError,
    hold_native_resident_update_lock,
)
from tests.update_context_test_support import (
    build_legacy_status_distribution,
    build_legacy_update_context,
    stage_legacy_wheel,
)

_REAL_SUBPROCESS_RUN = subprocess.run

_PROBE = """
import fcntl
import hashlib
import os
import sys

lock_path, expected_digest = sys.argv[1:]
descriptor = os.open(lock_path, os.O_RDWR)
try:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        print("blocked")
    else:
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = os.read(descriptor, 128).decode("ascii").strip()
        print("accepted" if observed == expected_digest else "rejected")
finally:
    os.close(descriptor)
""".strip()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _probe(lock_path: Path, expected_digest: str) -> str:
    result = _REAL_SUBPROCESS_RUN(
        (sys.executable, "-c", _PROBE, str(lock_path), expected_digest),
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout.strip()


@pytest.mark.skipif(os.name == "nt", reason="probe uses POSIX flock directly")
def test_update_barrier_blocks_simultaneous_old_request_and_allows_new_runtime(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"old-runtime")
    runtime.chmod(0o700)
    old_digest = _digest(runtime)

    with hold_native_resident_update_lock(guard_home, initial_executable=runtime) as update_lock:
        lock_path = guard_home / "native-runtime" / "resident-update.v1.lock"
        assert _probe(lock_path, old_digest) == "blocked"

        runtime.write_bytes(b"new-runtime")
        runtime.chmod(0o700)
        new_digest = _digest(runtime)
        update_lock.publish_runtime_digest(runtime)

    assert _probe(lock_path, old_digest) == "rejected"
    assert _probe(lock_path, new_digest) == "accepted"


@pytest.mark.skipif(os.name == "nt", reason="probe uses POSIX flock directly")
def test_missing_runtime_does_not_clear_update_marker(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"old-runtime")
    runtime.chmod(0o700)
    old_digest = _digest(runtime)

    with hold_native_resident_update_lock(guard_home, initial_executable=runtime) as update_lock:
        with pytest.raises(
            NativeResidentUpdateLockError,
            match="update_native_resident_lock_finalize_failed",
        ):
            update_lock.publish_runtime_digest(tmp_path / "missing-runtime")
        lock_path = guard_home / "native-runtime" / "resident-update.v1.lock"
        assert lock_path.read_text(encoding="ascii") == f"{old_digest}\n"

    assert _probe(lock_path, old_digest) == "accepted"


@pytest.mark.skipif(os.name == "nt", reason="probe uses POSIX flock directly")
def test_run_guard_update_holds_barrier_through_installer_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    wheel = tmp_path / "hol_guard-2.2.3-py3-none-any.whl"
    wheel.write_bytes(b"fixture-wheel")
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"old-runtime")
    runtime.chmod(0o700)
    old_digest = _digest(runtime)
    callback_observations: list[str] = []

    monkeypatch.setattr(update_commands, "build_trusted_update_context", build_legacy_update_context)
    monkeypatch.setattr(update_commands, "_status_installed_distribution", build_legacy_status_distribution)
    monkeypatch.setattr(update_commands, "stage_trusted_wheel", stage_legacy_wheel)
    monkeypatch.setattr(update_commands, "load_managed_policy", lambda: ManagedPolicyState("absent", "test"))
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.2.1")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.2.3")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.2.3")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(update_commands, "_bundled_runtime_candidate", lambda: runtime)
    monkeypatch.setattr(update_commands, "_retire_native_resident_before_update", lambda _guard_home: True)
    monkeypatch.setattr(update_commands, "_refresh_package_shims_after_update", lambda **_: (None, None))
    monkeypatch.setattr(update_commands, "_repair_supported_harnesses", lambda **_: ([], []))

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        lock_path = guard_home / "native-runtime" / "resident-update.v1.lock"
        callback_observations.append(_probe(lock_path, old_digest))
        runtime.write_bytes(b"new-runtime")
        runtime.chmod(0o700)
        callback_observations.append(_probe(lock_path, old_digest))
        return subprocess.CompletedProcess(command, 0, "installed", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(
        dry_run=False,
        wheel=str(wheel),
        guard_home=guard_home,
    )

    assert exit_code == 0, payload
    assert payload["status"] == "updated"
    assert callback_observations == ["blocked", "blocked"]
    lock_path = guard_home / "native-runtime" / "resident-update.v1.lock"
    assert _probe(lock_path, old_digest) == "rejected"
    assert _probe(lock_path, _digest(runtime)) == "accepted"
