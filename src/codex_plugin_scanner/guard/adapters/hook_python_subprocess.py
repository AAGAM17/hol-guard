"""Bounded subprocess runner for the Guard interpreter probe."""

from __future__ import annotations

import contextlib
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

_PROBE_TIMEOUT_SECONDS: Final = 15
_PROBE_OUTPUT_LIMIT_BYTES: Final = 64 * 1024


@dataclass(frozen=True, slots=True)
class ProbeResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_overflow: bool
    capture_incomplete: bool = False


def _read_bounded_stream(
    stream: BinaryIO,
    chunks: list[bytes],
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
    output_limit_bytes: int,
) -> None:
    total = 0
    while True:
        chunk = stream.read(4096)
        if not chunk:
            return
        remaining = output_limit_bytes - total
        if remaining > 0:
            chunks.append(chunk[:remaining])
        total += len(chunk)
        if total > output_limit_bytes:
            overflow.set()
            with contextlib.suppress(OSError):
                process.kill()
            return


def run_probe(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float = _PROBE_TIMEOUT_SECONDS,
    output_limit_bytes: int = _PROBE_OUTPUT_LIMIT_BYTES,
) -> ProbeResult:
    """Run a probe with no stdin and strictly bounded output and duration."""

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise RuntimeError("guard_hook_python_probe_execution_failed") from error
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    overflow = threading.Event()
    readers = (
        threading.Thread(
            target=_read_bounded_stream,
            args=(process.stdout, stdout_chunks, overflow, process, output_limit_bytes),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded_stream,
            args=(process.stderr, stderr_chunks, overflow, process, output_limit_bytes),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        _ = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        _ = process.wait()
    for reader in readers:
        reader.join(timeout=2)
    capture_incomplete = any(reader.is_alive() for reader in readers)
    return ProbeResult(
        returncode=process.returncode,
        stdout=b"".join(stdout_chunks),
        stderr=b"".join(stderr_chunks),
        timed_out=timed_out,
        output_overflow=overflow.is_set(),
        capture_incomplete=capture_incomplete,
    )


__all__ = ["ProbeResult", "run_probe"]
