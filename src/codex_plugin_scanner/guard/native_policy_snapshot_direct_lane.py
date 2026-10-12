"""Publisher half of the direct resident hook lane.

A hook that reaches the resident without passing through this daemon still
needs the publisher's ACK. Each push carries the state its snapshot was
compiled against (settled workspaces and watched non-database input stats),
and the publisher mirrors its ``_acked`` barrier into a short-lease ACK file
that the resident checks before answering directly. Withdrawing the barrier
unlinks the file; a crashed daemon stops renewing the lease. Anything the
resident cannot prove makes the hook take the daemon path instead.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import threading
import time
from collections.abc import Iterable, Mapping
from pathlib import Path

from .native_command_control_authority import AUTHORITY_FILE_NAME
from .native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY

DIRECT_LANE_PUSH_FEATURE = "policy-snapshot-direct-lane-v1"
DIRECT_LANE_ACK_DIRECTORY = "direct-lane"
DIRECT_LANE_ACK_FILE_NAME = "ack.json"
DIRECT_LANE_ACK_SCHEMA = "guard-direct-lane-ack.v1"
DIRECT_LANE_ACK_LEASE_MS = 15_000
# Renew once a third of the lease has elapsed so one slow poll cannot lapse it.
DIRECT_LANE_ACK_RENEW_REMAINING_MS = 10_000

# Mirrors the resident limits in guard-policy-snapshot's direct_lane module.
_MAX_WORKSPACES = 512
_MAX_INPUTS = 256
_MAX_PATH_BYTES = 4096
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1
_U64_MAX = (1 << 64) - 1

# Database writes and the publisher's own command-control marker commit are
# hints the publisher recompiles and compares; they never revoke the ACK up
# front, so the resident does not watch them either. The marker is replaced
# atomically during publication, so binding its stat would close the lane on
# every publish that commits it.
_DATABASE_FILE_NAMES = frozenset({"guard.db", "guard.db-wal", "guard.db-shm", "guard.db-journal"})

# Serializes each barrier value change with its file operation, so a renewal
# can never resurrect an ACK that a concurrent withdrawal just unlinked.
_ACK_LOCK = threading.Lock()


def _path_valid(value: str) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return 0 < len(encoded) <= _MAX_PATH_BYTES and "\0" not in value and os.path.isabs(value)


def _stat_valid(stat_identity: tuple[int, int, int, int]) -> bool:
    mtime_ns, size, ino, ctime_ns = stat_identity
    return (
        _I64_MIN <= mtime_ns <= _I64_MAX
        and 0 <= size <= _U64_MAX
        and 0 <= ino <= _U64_MAX
        and _I64_MIN <= ctime_ns <= _I64_MAX
    )


def _hint_only(path: Path) -> bool:
    if path.name in _DATABASE_FILE_NAMES:
        return True
    return path.name == AUTHORITY_FILE_NAME and path.parent.name == NATIVE_RUNTIME_STATE_DIRECTORY


def direct_lane_binding(
    *,
    inputs: Iterable[tuple[str, tuple[int, int, int, int] | None]],
    workspaces: Iterable[Path],
) -> dict[str, object] | None:
    """Build the push binding, or None when the lane cannot be proven."""

    if os.name == "nt":
        return None
    bound_inputs: list[dict[str, object]] = []
    for path, stat_identity in inputs:
        if _hint_only(Path(path)):
            continue
        # An input the resident cannot re-stat exactly would leave a change
        # unobserved, so the whole lane stays closed.
        if not _path_valid(path) or (stat_identity is not None and not _stat_valid(stat_identity)):
            return None
        bound_inputs.append(
            {
                "path": path,
                "stat": (
                    None
                    if stat_identity is None
                    else dict(zip(("mtime_ns", "size", "ino", "ctime_ns"), stat_identity, strict=True))
                ),
            }
        )
    # A workspace the resident cannot name simply defers as unknown.
    bound_workspaces = sorted({str(path) for path in workspaces if _path_valid(str(path))})
    if len(bound_inputs) > _MAX_INPUTS or len(bound_workspaces) > _MAX_WORKSPACES:
        return None
    if len({entry["path"] for entry in bound_inputs}) != len(bound_inputs):
        return None
    return {"workspaces": bound_workspaces, "inputs": bound_inputs}


class NativePolicySnapshotDirectLaneAck:
    """Mirror the publisher's ACK barrier into the resident's direct-lane ACK file."""

    guard_home: Path  # pyright: ignore[reportUninitializedInstanceVariable]
    _acked_value: bool = False
    _direct_lane_ack_target: tuple[int, str] | None = None
    _direct_lane_lease_expires_at_ms: int = 0

    @property
    def _acked(self) -> bool:
        return self._acked_value

    @_acked.setter
    def _acked(self, value: bool) -> None:
        with _ACK_LOCK:
            self._acked_value = value
            if not value:
                self._direct_lane_ack_target = None
                self._direct_lane_lease_expires_at_ms = 0
                self._unlink_direct_lane_ack()

    def _publish_direct_lane_ack(self, snapshot: Mapping[str, object]) -> None:
        """Open the lane for the snapshot whose ACK was just committed."""

        generation = snapshot.get("generation")
        policy_digest = snapshot.get("policy_digest")
        if isinstance(generation, bool) or not isinstance(generation, int) or not isinstance(policy_digest, str):
            return
        with _ACK_LOCK:
            if not self._acked_value:
                return
            self._direct_lane_ack_target = (generation, policy_digest)
            self._write_direct_lane_ack_locked()

    def _renew_direct_lane_ack(self) -> None:
        """Extend the lease while the barrier stays acknowledged."""

        if self._direct_lane_ack_target is None:
            return
        if self._direct_lane_lease_expires_at_ms - _now_ms() > DIRECT_LANE_ACK_RENEW_REMAINING_MS:
            return
        with _ACK_LOCK:
            if self._acked_value and self._direct_lane_ack_target is not None:
                self._write_direct_lane_ack_locked()

    def _direct_lane_ack_path(self) -> Path:
        return self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / DIRECT_LANE_ACK_DIRECTORY / DIRECT_LANE_ACK_FILE_NAME

    def _unlink_direct_lane_ack(self) -> None:
        if os.name == "nt":
            return
        try:
            self._direct_lane_ack_path().unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # The lease still bounds how long the resident can trust it.
            self._direct_lane_lease_expires_at_ms = 0

    def _write_direct_lane_ack_locked(self) -> None:
        target = self._direct_lane_ack_target
        if os.name == "nt" or target is None:
            return
        generation, policy_digest = target
        lease_expires_at_ms = _now_ms() + DIRECT_LANE_ACK_LEASE_MS
        body = json.dumps(
            {
                "schema": DIRECT_LANE_ACK_SCHEMA,
                "generation": generation,
                "policy_digest": policy_digest,
                "lease_expires_at_ms": lease_expires_at_ms,
            },
            separators=(",", ":"),
        ).encode("ascii")
        path = self._direct_lane_ack_path()
        try:
            _ensure_private_directory(path.parent)
            temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(body)
                os.replace(temporary, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    temporary.unlink()
                raise
        except OSError:
            # Without a fresh ACK file the resident defers every direct hook.
            self._direct_lane_lease_expires_at_ms = 0
            return
        self._direct_lane_lease_expires_at_ms = lease_expires_at_ms


def _ensure_private_directory(directory: Path) -> None:
    with contextlib.suppress(FileExistsError):
        os.mkdir(directory, 0o700)
    metadata = os.lstat(directory)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise OSError("direct lane ACK directory is not private")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        # Owner-only. A directory needs the execute bit, and 0o644 would leave it readable.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(directory, 0o700)


def _now_ms() -> int:
    return time.time_ns() // 1_000_000
