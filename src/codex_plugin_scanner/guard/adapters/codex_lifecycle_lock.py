"""Serialize cooperating Codex lifecycle writers across installation owners."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Generator
from contextlib import ExitStack, contextmanager
from functools import wraps
from pathlib import Path

from ..daemon.file_locking import try_lock_daemon_file
from ..mdm.file_lock import release_file_lock
from .base import HarnessContext, _ensure_path_within_root


def _lock_identity(path: Path) -> tuple[int, int] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle lock must be a regular file with one link")
    return metadata.st_dev, metadata.st_ino


@contextmanager
def _target_lock(root: Path) -> Generator[None]:
    directory = root / ".codex"
    _ensure_path_within_root(root, directory, label="Codex lifecycle lock")
    directory.mkdir(parents=True, exist_ok=True)
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle directory must not be a symbolic link")
    _ensure_path_within_root(root, directory, label="Codex lifecycle lock")
    path = directory / ".hol-guard-lifecycle.lock"
    prior = _lock_identity(path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        identity = metadata.st_dev, metadata.st_ino
        if _lock_identity(path) != identity or (prior is not None and prior != identity):
            raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle lock changed while opening")
        with os.fdopen(descriptor, "a+b") as handle:
            descriptor = -1
            if not try_lock_daemon_file(handle):
                raise RuntimeError("codex_lifecycle_busy: another lifecycle operation owns this Codex configuration")
            try:
                yield
            finally:
                release_file_lock(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def codex_lifecycle_locks(context: HarnessContext) -> Generator[None]:
    # Store locks beside shared configurations, not in an owner's Guard home.
    # A different owner must contend on the same file before reading inventory.
    roots = [context.home_dir]
    if context.workspace_dir is not None:
        roots.append(context.workspace_dir)
    targets = sorted({os.path.normcase(str(root.resolve())): root for root in roots}.items())
    with ExitStack() as stack:
        for _identity, root in targets:
            stack.enter_context(_target_lock(root))
        yield


def serialized_codex_lifecycle(method: Callable[..., dict[str, object]]) -> Callable[..., dict[str, object]]:
    @wraps(method)
    def wrapped(self: object, context: HarnessContext) -> dict[str, object]:
        with codex_lifecycle_locks(context):
            return method(self, context)

    return wrapped
