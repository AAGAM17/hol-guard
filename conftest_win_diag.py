"""TEMPORARY pytest plugin for the Windows native-hook-worker repair run.

Loaded with `-p conftest_win_diag` by win-native-hook-diag.yml only. Unmasks
the in-process native_hook_worker_exception fallback and replays any worker
traceback dumps left under HOL_GUARD_WIN_DIAG_DIR.
"""
from __future__ import annotations

import os
import sys
import traceback


def pytest_configure(config):
    from codex_plugin_scanner.guard.cli import commands_hook_native_authority as na
    from codex_plugin_scanner.guard.daemon import hook_availability_policy as ap

    orig = ap.availability_harness_response

    def _unmask(payload, *, reason_code=None, **kw):
        if reason_code == "native_hook_worker_exception" and sys.exception() is not None:
            exc = sys.exception()
            traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
            raise exc
        return orig(payload, reason_code=reason_code, **kw)

    na.availability_harness_response = _unmask


def pytest_sessionfinish(session, exitstatus):
    diag_dir = os.environ.get("HOL_GUARD_WIN_DIAG_DIR")
    if not diag_dir:
        return
    from pathlib import Path

    for path in sorted(Path(diag_dir).glob("*.txt")):
        sys.stderr.write(f"\n===== win-diag {path.name} =====\n")
        sys.stderr.write(path.read_text(encoding="utf-8", errors="replace"))
        sys.stderr.write("\n")
    sys.stderr.flush()
