"""A native MCP relay session whose direct lane is not ready runs as the Python proxy.

The relay must decide before it reads any stdin byte or starts the MCP server,
and then exec the exact Python proxy argv with its environment unchanged, so
the proxy sees the host's untouched stdio stream.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="the native MCP relay is Unix only")

_STDIN = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n\x00tail without newline \xff'
_FAKE_PROXY = """#!{python}
import json, os, sys
record = {{"argv": sys.argv[1:], "env": dict(os.environ), "stdin": sys.stdin.buffer.read().hex()}}
name = "ensure" if "daemon" in sys.argv[1:] else "proxy"
with open(os.path.join({log!r}, name + ".json"), "w", encoding="utf-8") as handle:
    json.dump(record, handle)
"""


def _runtime() -> Path:
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary or not Path(binary).is_file():
        pytest.skip("HOL_GUARD_NATIVE_BINARY does not name a compiled runtime")
    return Path(binary).resolve()


def _wait_for(path: Path, seconds: float = 10.0) -> dict[str, object]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        time.sleep(0.05)
    raise AssertionError(f"{path.name} was never written")


def test_an_unready_lane_hands_the_untouched_session_to_the_python_proxy(tmp_path: Path) -> None:
    runtime = _runtime()
    log, guard_home, workspace = tmp_path / "log", tmp_path / "guard-home", tmp_path / "workspace"
    for directory in (log, guard_home, workspace):
        directory.mkdir(mode=0o700)
    fake = tmp_path / "python"
    fake.write_text(_FAKE_PROXY.format(python=sys.executable, log=str(log)), encoding="utf-8")
    fake.chmod(0o700)
    proxy_args = [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "codex-mcp-proxy",
        "--guard-home",
        str(guard_home),
        "--home",
        str(tmp_path),
        "--workspace",
        str(workspace),
        "--server-name",
        "canary",
        "--config-path",
        str(workspace / ".codex" / "config.toml"),
        "--command",
        "/bin/cat",
    ]
    # LC_ALL keeps the fake interpreter from coercing its own locale variables.
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "LC_ALL": "C.UTF-8", "HOL_GUARD_TEST_MARK": "kept"}
    completed = subprocess.run(
        [str(runtime), "mcp-relay", str(fake), *proxy_args],
        input=_STDIN,
        env=env,
        cwd=workspace,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    proxy = _wait_for(log / "proxy.json")
    assert proxy["argv"] == proxy_args
    assert bytes.fromhex(str(proxy["stdin"])) == _STDIN
    recorded = {key: value for key, value in dict(proxy["env"]).items() if not key.startswith("__")}
    assert recorded == env
    stderr = completed.stderr.decode("utf-8", errors="replace")
    assert "hol-guard mcp-relay: python proxy: mcp_relay_daemon_unreachable" in stderr
    assert "no native decision" not in stderr
    # The daemon is down, so one detached ensure ran without the host's input.
    ensure = _wait_for(log / "ensure.json")
    assert ensure["argv"] == [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "daemon",
        "ensure",
        "--guard-home",
        str(guard_home),
        "--home",
        str(tmp_path),
    ]
    assert ensure["stdin"] == ""
