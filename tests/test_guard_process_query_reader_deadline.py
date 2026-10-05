"""Process inventory must distinguish reader scheduling lag from unavailable output."""

from __future__ import annotations

import io
import threading
import time

from codex_plugin_scanner.guard.daemon import manager


class CompletedQuery:
    pid = None
    returncode = 0

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"verified inventory\n")

    def poll(self) -> int:
        return 0

    def wait(self, *, timeout: float) -> int:
        return 0


def test_completed_query_accepts_reader_lag_within_original_deadline(monkeypatch):
    query = CompletedQuery()
    gate = threading.Event()
    readers: list[threading.Thread] = []
    capture = manager._capture_bounded_process_query_stdout

    def delayed_capture(*args):
        readers.append(threading.current_thread())
        gate.wait()
        capture(*args)

    monkeypatch.setattr(manager, "_spawn_bounded_process_query", lambda _command: query)
    monkeypatch.setattr(manager, "_capture_bounded_process_query_stdout", delayed_capture)
    release = threading.Timer(1.0, gate.set)
    release.start()
    try:
        assert manager._bounded_process_query_stdout(["fixture-query"], timeout_seconds=5.0) == "verified inventory\n"
    finally:
        gate.set()
        release.cancel()
        release.join()
        for reader in readers:
            reader.join(timeout=1.0)


def test_completed_query_rejects_reader_that_misses_original_deadline(monkeypatch):
    query = CompletedQuery()
    gate = threading.Event()
    readers: list[threading.Thread] = []
    capture = manager._capture_bounded_process_query_stdout

    def delayed_capture(*args):
        readers.append(threading.current_thread())
        gate.wait()
        capture(*args)

    monkeypatch.setattr(manager, "_spawn_bounded_process_query", lambda _command: query)
    monkeypatch.setattr(manager, "_capture_bounded_process_query_stdout", delayed_capture)
    started = time.monotonic()
    try:
        assert manager._bounded_process_query_stdout(["fixture-query"], timeout_seconds=0.05) is None
        assert time.monotonic() - started < 2.0
    finally:
        gate.set()
        for reader in readers:
            reader.join(timeout=1.0)
