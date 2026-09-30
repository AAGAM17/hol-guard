"""Serialize Guard-owned OpenCode config readers and writers.

OpenCode and external editors do not participate in this advisory protocol.
Byte comparisons detect their earlier edits, but cannot protect the final
comparison-to-replacement window against an uncooperative writer.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ..daemon.file_locking import try_lock_daemon_file
from ..mdm.file_lock import release_file_lock


@contextmanager
def opencode_config_lock(home_dir: Path, *, timeout: float = 5.0) -> Iterator[None]:
    """Lock before reading configs; retain the lock through writes and rollback."""
    path = home_dir / ".config" / "opencode" / ".hol-guard-config.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("OpenCode config lock must not be a symlink")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "r+b") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or (os.name != "nt" and info.st_uid != os.geteuid()):
            raise ValueError("OpenCode config lock must be an owned regular file")
        deadline = time.monotonic() + timeout
        while not try_lock_daemon_file(handle):
            if time.monotonic() >= deadline:
                raise TimeoutError("Another Guard operation is updating OpenCode config; try again shortly")
            time.sleep(0.05)
        try:
            yield
        finally:
            release_file_lock(handle)
