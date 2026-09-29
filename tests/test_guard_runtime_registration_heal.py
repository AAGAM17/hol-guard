"""Runtime registration self-heal after the guard_runtime_state row is lost."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import cast, final

import pytest

from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import protection_repair_retry
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.protection_repair_retry import containment_repair_outcome
from codex_plugin_scanner.guard.daemon.runtime_heartbeat import RuntimeHeartbeatWriter
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardRuntimeRegistration
from codex_plugin_scanner.guard.runtime.containment_contract import (
    CONTAINMENT_POLICY_VERSION,
    CONTAINMENT_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_HEALTH_SCHEMA_VERSION,
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
)
from codex_plugin_scanner.guard.runtime.effect_contract import EFFECT_CONTRACT_SCHEMA_VERSION
from codex_plugin_scanner.guard.runtime.effect_decision import EFFECT_DECISION_SCHEMA_VERSION
from codex_plugin_scanner.guard.runtime.protection_health import ProtectionCheckStatus
from codex_plugin_scanner.guard.store import GuardStore

_T0 = "2026-07-25T00:00:00+00:00"
_T1 = "2026-07-25T00:00:01+00:00"
_CONTAINMENT_CHECK_IDS = (
    "policy_engine",
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
)


def _registration() -> GuardRuntimeRegistration:
    return GuardRuntimeRegistration(daemon_host="127.0.0.1", daemon_port=9100, started_at=_T0)


def _passing_containment_health() -> dict[str, object]:
    fingerprint = hashlib.sha256(b"daemon-runtime").hexdigest()
    return {
        "backend": "macos-sandbox",
        "backend_digest": hashlib.sha256(b"backend").hexdigest(),
        "policy_contract_digest": CONTAINMENT_POLICY_CONTRACT_DIGEST,
        "daemon_fingerprint": fingerprint,
        "runtime_fingerprint": fingerprint,
        "probe_at": datetime.now(timezone.utc).isoformat(),
        "probe_enforced": True,
        "containment_schema_version": CONTAINMENT_SCHEMA_VERSION,
        "policy_version": CONTAINMENT_POLICY_VERSION,
        "effect_contract_schema_version": EFFECT_CONTRACT_SCHEMA_VERSION,
        "effect_decision_schema_version": EFFECT_DECISION_SCHEMA_VERSION,
        "schema_version": CONTAINMENT_HEALTH_SCHEMA_VERSION,
    }


def _delete_runtime_row(store: GuardStore) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.execute("delete from guard_runtime_state")


def _protection_check(snapshot: dict[str, object], check_id: str) -> dict[str, str]:
    health = cast(dict[str, object], snapshot["protection_health"])
    checks = cast(list[dict[str, str]], health["checks"])
    return next(check for check in checks if check["check_id"] == check_id)


def _serving_runtime(daemon: GuardDaemonServer) -> dict[str, object]:
    server = daemon._server  # pyright: ignore[reportPrivateUsage]
    return {
        "session_id": server.runtime_session_id,
        "daemon_host": server.runtime_host,
        "daemon_port": server.daemon_port(),
        "started_at": server.runtime_started_at,
        "last_heartbeat_at": datetime.now(timezone.utc).isoformat(),
    }


def _get_json(daemon: GuardDaemonServer, path: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        headers={"X-Guard-Token": daemon._server.auth_token},  # pyright: ignore[reportPrivateUsage]
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return cast(dict[str, object], json.loads(response.read().decode("utf-8")))


def _post_repair(daemon: GuardDaemonServer, check_id: str) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
        data=json.dumps({"check_id": check_id}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": daemon._server.auth_token,  # pyright: ignore[reportPrivateUsage]
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, cast(dict[str, object], json.loads(response.read().decode("utf-8")))
    except urllib.error.HTTPError as error:
        return error.code, cast(dict[str, object], json.loads(error.read().decode("utf-8")))


def _start_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[GuardStore, GuardDaemonServer]:
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: [],
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    return store, daemon


def _stub_supported_repair(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stub_evidence_health: bool = True,
) -> None:
    monkeypatch.setattr(
        GuardStore,
        "setup_policy_integrity",
        lambda self, **_kwargs: {"mode": "protected"},
    )
    monkeypatch.setattr(
        daemon_server_module._GuardDaemonHandler,
        "_containment_health_payload",
        lambda self, **_kwargs: _passing_containment_health(),
    )
    monkeypatch.setattr(GuardStore, "maintain_command_activity", lambda self, **_kwargs: None)
    if stub_evidence_health:
        monkeypatch.setattr(
            GuardStore,
            "get_command_activity_persistence_health",
            lambda self: SimpleNamespace(active_error_count=0),
        )
    monkeypatch.setattr(daemon_server_module, "repair_failing_managed_harness_hooks", lambda _store: ((), ()))
    monkeypatch.setattr(GuardStore, "list_managed_installs", lambda self: [{"harness": "codex", "active": True}])


def test_heartbeat_recreates_missing_runtime_row_with_registration(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.upsert_runtime_state(
        session_id="daemon-1",
        daemon_host="127.0.0.1",
        daemon_port=9100,
        started_at=_T0,
        last_heartbeat_at=_T0,
    )
    _delete_runtime_row(store)
    assert store.get_runtime_state() is None

    assert store.try_touch_runtime_state(
        session_id="daemon-1",
        last_heartbeat_at=_T1,
        timeout_seconds=1.0,
        registration=_registration(),
    )

    assert store.get_runtime_state() == {
        "session_id": "daemon-1",
        "daemon_host": "127.0.0.1",
        "daemon_port": 9100,
        "started_at": _T0,
        "last_heartbeat_at": _T1,
        "approval_center_url": "http://127.0.0.1:9100",
    }


def test_heartbeat_without_registration_leaves_missing_row_absent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.upsert_runtime_state(
        session_id="daemon-1",
        daemon_host="127.0.0.1",
        daemon_port=9100,
        started_at=_T0,
        last_heartbeat_at=_T0,
    )
    _delete_runtime_row(store)

    assert store.try_touch_runtime_state(
        session_id="daemon-1",
        last_heartbeat_at=_T1,
        timeout_seconds=1.0,
    )
    assert store.get_runtime_state() is None


def test_heartbeat_registration_never_steals_a_foreign_session_row(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.upsert_runtime_state(
        session_id="other-session",
        daemon_host="127.0.0.1",
        daemon_port=9200,
        started_at=_T0,
        last_heartbeat_at=_T0,
    )

    assert store.try_touch_runtime_state(
        session_id="daemon-1",
        last_heartbeat_at=_T1,
        timeout_seconds=1.0,
        registration=_registration(),
    )

    state = store.get_runtime_state()
    assert state is not None
    assert state["session_id"] == "other-session"
    assert state["daemon_port"] == 9200
    assert state["last_heartbeat_at"] == _T0


def test_heartbeat_writer_passes_registration_to_the_store() -> None:
    @final
    class RecordingStore:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def try_touch_runtime_state(
            self,
            *,
            session_id: str,
            last_heartbeat_at: str,
            timeout_seconds: float,
            registration: GuardRuntimeRegistration | None = None,
        ) -> bool:
            self.calls.append(
                {
                    "session_id": session_id,
                    "last_heartbeat_at": last_heartbeat_at,
                    "timeout_seconds": timeout_seconds,
                    "registration": registration,
                }
            )
            return True

    store = RecordingStore()
    writer = RuntimeHeartbeatWriter(
        store=store,
        session_id="session",
        write_timeout_seconds=0.01,
        retry_interval_seconds=0.01,
    )
    registration = _registration()
    writer.register(registration)
    writer.start()
    try:
        writer.touch("heartbeat-1")
        deadline = time.monotonic() + 1
        while not store.calls and time.monotonic() < deadline:
            time.sleep(0.005)
    finally:
        writer.stop()

    assert len(store.calls) == 1
    assert store.calls[0]["registration"] == registration


def test_heartbeat_writer_stops_inserting_after_clear_registration() -> None:
    @final
    class RecordingStore:
        def __init__(self) -> None:
            self.calls: list[GuardRuntimeRegistration | None] = []

        def try_touch_runtime_state(
            self,
            *,
            session_id: str,
            last_heartbeat_at: str,
            timeout_seconds: float,
            registration: GuardRuntimeRegistration | None = None,
        ) -> bool:
            self.calls.append(registration)
            return True

    store = RecordingStore()
    writer = RuntimeHeartbeatWriter(
        store=store,
        session_id="session",
        write_timeout_seconds=0.01,
        retry_interval_seconds=0.01,
    )
    writer.register(_registration())
    writer.clear_registration()
    writer.start()
    try:
        writer.touch("heartbeat-1")
        deadline = time.monotonic() + 1
        while not store.calls and time.monotonic() < deadline:
            time.sleep(0.005)
    finally:
        writer.stop()

    assert store.calls == [None]


def test_snapshot_reports_missing_registration_while_serving(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url="http://127.0.0.1:9100",
        containment_health=_passing_containment_health(),
        serving_runtime={
            "session_id": "daemon-1",
            "daemon_host": "127.0.0.1",
            "daemon_port": 9100,
            "started_at": _T0,
            "last_heartbeat_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    runtime_state = cast(dict[str, object], snapshot["runtime_state"])
    assert runtime_state["registration_status"] == "missing"
    assert runtime_state["session_id"] == "daemon-1"
    assert _protection_check(snapshot, "daemon") == {
        "check_id": "daemon",
        "status": "unknown",
        "reason_code": "daemon_registration_missing",
    }
    for check_id in _CONTAINMENT_CHECK_IDS:
        check = _protection_check(snapshot, check_id)
        assert check["reason_code"] != "containment_health_invalid"
        assert check["status"] == "pass"
    assert snapshot["headline_state"] != "setup"


def test_snapshot_without_serving_runtime_still_fails_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=None,
        containment_health=_passing_containment_health(),
    )

    assert snapshot["runtime_state"] is None
    assert _protection_check(snapshot, "daemon") == {
        "check_id": "daemon",
        "status": "fail",
        "reason_code": "daemon_runtime_unavailable",
    }
    assert snapshot["headline_state"] == "setup"


def test_snapshot_stale_runtime_row_still_fails_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    stale = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    store.upsert_runtime_state(
        session_id="daemon-1",
        daemon_host="127.0.0.1",
        daemon_port=9100,
        started_at=_T0,
        last_heartbeat_at=stale,
    )

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=None,
        serving_runtime={
            "session_id": "daemon-1",
            "daemon_host": "127.0.0.1",
            "daemon_port": 9100,
            "started_at": _T0,
            "last_heartbeat_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    assert _protection_check(snapshot, "daemon") == {
        "check_id": "daemon",
        "status": "fail",
        "reason_code": "daemon_heartbeat_stale",
    }


def _assert_row_reappears_with_daemon_identity(store: GuardStore, daemon: GuardDaemonServer) -> None:
    server = daemon._server  # pyright: ignore[reportPrivateUsage]
    deadline = time.monotonic() + 2
    state: dict[str, object] | None = None
    while time.monotonic() < deadline:
        _get_json(daemon, "/healthz")
        state = store.get_runtime_state()
        if state is not None:
            break
        time.sleep(0.02)
    assert state is not None
    assert state["session_id"] == server.runtime_session_id
    assert state["daemon_host"] == server.runtime_host
    assert state["daemon_port"] == server.daemon_port()
    assert state["started_at"] == server.runtime_started_at
    snapshot = _get_json(daemon, "/v1/runtime")
    assert _protection_check(snapshot, "daemon")["status"] == "pass"


def test_daemon_re_registers_runtime_row_after_it_is_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, daemon = _start_daemon(tmp_path, monkeypatch)
    heartbeat = daemon._server.runtime_heartbeat  # pyright: ignore[reportPrivateUsage]
    original_touch = heartbeat.touch
    monkeypatch.setattr(heartbeat, "touch", lambda _at: None)
    try:
        _delete_runtime_row(store)
        snapshot = _get_json(daemon, "/v1/runtime")
        assert _protection_check(snapshot, "daemon") == {
            "check_id": "daemon",
            "status": "unknown",
            "reason_code": "daemon_registration_missing",
        }
        assert snapshot["headline_state"] != "setup"

        original_touch(datetime.now(timezone.utc).isoformat())
        _assert_row_reappears_with_daemon_identity(store, daemon)
    finally:
        daemon.stop()


def test_daemon_re_registers_after_fatal_store_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, daemon = _start_daemon(tmp_path, monkeypatch)
    heartbeat = daemon._server.runtime_heartbeat  # pyright: ignore[reportPrivateUsage]
    original_touch = heartbeat.touch
    monkeypatch.setattr(heartbeat, "touch", lambda _at: None)
    monkeypatch.setattr(store, "_store_is_proven_unusable", lambda _error: True)
    monkeypatch.setattr(store_connection_schema, "restore_readable_sqlite_store", lambda **_kwargs: False)
    try:
        assert store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
            sqlite3.DatabaseError("database disk image is malformed")
        )
        assert store.get_runtime_state() is None

        snapshot = _get_json(daemon, "/v1/runtime")
        assert _protection_check(snapshot, "daemon") == {
            "check_id": "daemon",
            "status": "unknown",
            "reason_code": "daemon_registration_missing",
        }

        original_touch(datetime.now(timezone.utc).isoformat())
        _assert_row_reappears_with_daemon_identity(store, daemon)
    finally:
        daemon.stop()


def test_protection_repair_all_restores_runtime_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_supported_repair(monkeypatch)
    monkeypatch.setattr(
        daemon_server_module,
        "_repair_command_activity_persistence_health",
        lambda _store: None,
    )
    store, daemon = _start_daemon(tmp_path, monkeypatch)
    heartbeat = daemon._server.runtime_heartbeat  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(heartbeat, "touch", lambda _at: None)
    try:
        _delete_runtime_row(store)
        status, payload = _post_repair(daemon, "all")

        assert status == 200
        assert payload["repaired"] is True
        assert "daemon" in cast(list[str], payload["check_ids"])
        state = store.get_runtime_state()
        assert state is not None
        assert state["session_id"] == daemon._server.runtime_session_id  # pyright: ignore[reportPrivateUsage]
    finally:
        daemon.stop()


def test_protection_repair_all_reports_unavailable_native_probe_truthfully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_supported_repair(monkeypatch, stub_evidence_health=False)
    monkeypatch.setattr(daemon_server_module, "current_extension_control_snapshot", lambda: None)
    monkeypatch.setattr(
        daemon_server_module,
        "evaluate_command_native",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("native evaluation unavailable")),
    )
    store, daemon = _start_daemon(tmp_path, monkeypatch)
    try:
        before = store.get_command_activity_persistence_health().persistence_error_count
        status, payload = _post_repair(daemon, "all")
    finally:
        daemon.stop()

    assert status == 409
    assert payload["error"] == "protection_repair_incomplete"
    assert "decision_stream" in cast(list[str], payload["pending_check_ids"])
    check_reasons = cast(dict[str, str], payload["check_reasons"])
    assert check_reasons["decision_stream"] == "native_evaluation_unavailable"
    after = store.get_command_activity_persistence_health().persistence_error_count
    assert after == before


def test_containment_repair_outcome_reports_signal_reasons(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        protection_repair_retry,
        "containment_health_signals",
        lambda _value, **_kwargs: {
            "decision_plane_compatibility": SimpleNamespace(
                status=ProtectionCheckStatus.PASS,
                reason_code="decision_plane_compatible",
            ),
            "containment_compatibility": SimpleNamespace(
                status=ProtectionCheckStatus.FAIL,
                reason_code="containment_probe_stale",
            ),
            "sandbox": SimpleNamespace(
                status=ProtectionCheckStatus.FAIL,
                reason_code="unsupported_platform",
            ),
        },
    )

    repaired, failed, reasons = containment_repair_outcome(lambda: {"ok": True})

    assert repaired == ["decision_plane_compatibility"]
    assert failed == ["containment_compatibility"]
    assert reasons == {"containment_compatibility": "containment_probe_stale"}


def test_containment_repair_outcome_marks_unavailable_health(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_probe() -> dict[str, object]:
        raise RuntimeError("probe failed")

    repaired, failed, reasons = containment_repair_outcome(raise_probe, attempts=2)

    assert repaired == []
    assert failed == [
        "decision_plane_compatibility",
        "containment_compatibility",
        "sandbox",
    ]
    assert reasons == {
        "decision_plane_compatibility": "containment_health_unavailable",
        "containment_compatibility": "containment_health_unavailable",
        "sandbox": "containment_health_unavailable",
    }
