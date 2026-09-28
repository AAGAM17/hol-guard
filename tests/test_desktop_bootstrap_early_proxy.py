"""Desktop bootstrap answers from the running daemon before frozen imports."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FROZEN_ENTRYPOINT = ROOT / "scripts" / "mdm" / "hol-guard-entry.py"


def _poison_guard_import(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    marker = tmp_path / "guard-imported"
    package = tmp_path / "codex_plugin_scanner"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import os\nfrom pathlib import Path\nPath(os.environ['GUARD_IMPORT_MARKER']).write_text('imported')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(tmp_path)
    environment["GUARD_IMPORT_MARKER"] = str(marker)
    environment["HOME"] = str(tmp_path)
    return marker, environment


def _write_daemon_identity(
    home: Path,
    *,
    host: str,
    port: int,
    token: str = "desktop-bootstrap-test-token",
    tamper_signature: bool = False,
) -> None:
    from codex_plugin_scanner.guard.daemon.discovery import authenticate_daemon_state

    guard_home = home / ".hol-guard"
    guard_home.mkdir()
    discovery_key = "ab" * 32
    state = authenticate_daemon_state({"host": host, "port": port}, discovery_key=discovery_key)
    if tamper_signature:
        signature = state["state_signature"]
        assert isinstance(signature, str)
        state["state_signature"] = f"{signature[:-1]}{'0' if signature[-1] != '0' else '1'}"
    files = {
        guard_home / "daemon-discovery-key": discovery_key,
        guard_home / "daemon-state.json": json.dumps(state),
        guard_home / "daemon-auth-token": token,
    }
    for path, contents in files.items():
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o600)


def _serve_bootstrap(body: bytes, *, status: int = 200) -> tuple[ThreadingHTTPServer, list[tuple[str, str | None]]]:
    hits: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append((self.path, self.headers.get("X-Guard-Token")))
            payload = body if status == 200 else b""
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, template: str, *args: object) -> None:
            del template, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hits


def test_desktop_bootstrap_proxy_answers_before_guard_imports(tmp_path: Path) -> None:
    document = {"coreVersion": "9.9.9", "schema": "guard-desktop-bootstrap.v1"}
    server, hits = _serve_bootstrap(json.dumps(document).encode("utf-8"))
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=server.server_address[1])
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode == 0
    assert json.loads(result.stdout) == document
    assert result.stderr == ""
    assert not marker.exists()
    assert hits == [("/v1/desktop/bootstrap", "desktop-bootstrap-test-token")]


def test_desktop_bootstrap_proxy_falls_through_when_daemon_lacks_route(tmp_path: Path) -> None:
    server, _hits = _serve_bootstrap(b"", status=404)
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=server.server_address[1])
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert "guard-desktop-bootstrap.v1" not in result.stdout
    assert marker.is_file()


def test_desktop_bootstrap_proxy_ignores_non_loopback_daemon_state(tmp_path: Path) -> None:
    server, hits = _serve_bootstrap(b'{"schema":"guard-desktop-bootstrap.v1"}')
    try:
        _write_daemon_identity(tmp_path, host="10.0.0.8", port=server.server_address[1])
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert hits == []
    assert marker.is_file()


def test_desktop_bootstrap_proxy_ignores_unauthenticated_daemon_state(tmp_path: Path) -> None:
    server, hits = _serve_bootstrap(b'{"schema":"guard-desktop-bootstrap.v1"}')
    try:
        _write_daemon_identity(
            tmp_path,
            host="127.0.0.1",
            port=server.server_address[1],
            tamper_signature=True,
        )
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert hits == []
    assert marker.is_file()


def test_desktop_bootstrap_proxy_skips_candidate_preflight(tmp_path: Path) -> None:
    document = {"coreVersion": "9.9.9", "schema": "guard-desktop-bootstrap.v1"}
    server, hits = _serve_bootstrap(json.dumps(document).encode("utf-8"))
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=server.server_address[1])
        marker, environment = _poison_guard_import(tmp_path)
        environment["HOL_GUARD_DESKTOP_PREFLIGHT"] = "1"
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert hits == []
    assert "guard-desktop-bootstrap.v1" not in result.stdout
    assert marker.is_file()


def test_cached_desktop_bootstrap_document_skips_rebuild_while_fresh() -> None:
    from codex_plugin_scanner.guard.cli.commands_dispatch_desktop import (
        cached_desktop_bootstrap_document,
        reset_desktop_bootstrap_cache,
    )

    reset_desktop_bootstrap_cache()
    try:
        calls = 0

        def build() -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {"schema": "guard-desktop-bootstrap.v1", "n": calls}

        key = ("guard-home", "http://127.0.0.1:1", "token-a")
        other = ("guard-home", "http://127.0.0.1:2", "token-b")
        assert cached_desktop_bootstrap_document(key, build)["n"] == 1
        assert cached_desktop_bootstrap_document(key, build)["n"] == 1
        assert cached_desktop_bootstrap_document(other, build)["n"] == 2
        assert calls == 2
    finally:
        reset_desktop_bootstrap_cache()


def test_cached_desktop_bootstrap_document_single_flights_a_miss() -> None:
    from codex_plugin_scanner.guard.cli.commands_dispatch_desktop import (
        cached_desktop_bootstrap_document,
        reset_desktop_bootstrap_cache,
    )

    reset_desktop_bootstrap_cache()
    entered = threading.Event()
    release = threading.Event()
    calls = 0
    try:

        def build() -> dict[str, object]:
            nonlocal calls
            calls += 1
            entered.set()
            assert release.wait(timeout=2)
            return {"schema": "guard-desktop-bootstrap.v1", "n": calls}

        key = ("guard-home", "http://127.0.0.1:1", "token-a")
        leader: dict[str, object] = {}
        follower: dict[str, object] = {}

        def lead() -> None:
            leader["document"] = cached_desktop_bootstrap_document(key, build)

        def follow() -> None:
            follower["document"] = cached_desktop_bootstrap_document(key, build)

        worker = threading.Thread(target=lead)
        worker.start()
        assert entered.wait(timeout=2)
        waiter = threading.Thread(target=follow)
        waiter.start()
        time.sleep(0.05)
        assert calls == 1
        release.set()
        worker.join(timeout=2)
        waiter.join(timeout=2)
        assert calls == 1
        assert follower["document"] == leader["document"]
    finally:
        release.set()
        reset_desktop_bootstrap_cache()


def test_desktop_bootstrap_route_is_critical() -> None:
    from codex_plugin_scanner.guard.daemon.server import _DAEMON_CRITICAL_PATHS
    from codex_plugin_scanner.guard.dashboard_launcher import build_desktop_dashboard_session_url_for_daemon

    assert "/v1/desktop/bootstrap" in _DAEMON_CRITICAL_PATHS
    with pytest.raises(ValueError):
        build_desktop_dashboard_session_url_for_daemon(daemon_url="http://10.0.0.8:9", auth_token="token")
