"""TEMPORARY pytest plugin for the Windows native-hook-worker repair run.

Loaded with `-p conftest_win_diag` by win-native-hook-diag.yml only.

Two jobs:

1. Unmask the in-process fallback: when the hook-authority path falls into
   `except Exception` -> availability_harness_response with
   reason_code='native_hook_worker_exception', re-raise the live exception so
   pytest prints the real traceback instead of the masked availability result.

2. The spawned worker/evaluator grandchildren write a real traceback file into
   HOL_GUARD_WIN_DIAG_DIR via _diag_dump_exception; after the session, print
   their contents to stderr so the Actions log shows the true root cause even
   when the masking happened in a child process.
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
