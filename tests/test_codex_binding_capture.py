"""Bounded, opt-in Codex ingress to native-edge receipt diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from types import MethodType, SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.codex_binding_capture import (
    CAPTURE_MARKER_NAME,
    CAPTURE_OUTPUT_PREFIX,
    CAPTURE_OUTPUT_SUFFIX,
    CAPTURE_SCHEMA,
    join_binding_records,
    record_bridge_ingress,
    record_native_worker,
)
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes


def _enable_capture(
    guard_home: Path,
    *,
    run_id: str = "run-1",
    expires_at: int | None = None,
    max_records: int = 16,
    max_bytes: int = 64 * 1024,
) -> Path:
    directory = guard_home / "diagnostics"
    guard_home.mkdir(parents=True, exist_ok=True)
    guard_home.chmod(0o700)
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    marker = directory / CAPTURE_MARKER_NAME
    marker.write_text(
        json.dumps(
            {
                "schema": CAPTURE_SCHEMA,
                "enabled": True,
                "run_id": run_id,
                "expires_at": int(time.time()) + 300 if expires_at is None else expires_at,
                "max_records": max_records,
                "max_bytes": max_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    marker.chmod(0o600)
    return directory


def _valid_native_receipt() -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "sha256:request-1",
        "request_digest": "a" * 64,
        "harness": "codex",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": None,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": "allow",
        "model_output_action": "not_applicable",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_allow",
        "workspace_bound": False,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 100,
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    return receipt


def _output_path(directory: Path, run_id: str = "run-1") -> Path:
    return directory / f"{CAPTURE_OUTPUT_PREFIX}{run_id}{CAPTURE_OUTPUT_SUFFIX}"


def _rows(directory: Path, run_id: str = "run-1") -> list[dict[str, object]]:
    path = _output_path(directory, run_id)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_no_marker_is_inert_and_does_not_create_capture_directory(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"

    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_call_id":"call-1"}',
        event_name="PreToolUse",
    )
    assert not (guard_home / "diagnostics").exists()


def test_capture_keeps_raw_and_forwarded_fingerprints_separate_without_raw_content(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = {
        "hook_event_name": "PreToolUse",
        "tool_call_id": "call-1",
        "tool_input": {"command": "echo SECRET_COMMAND"},
    }
    forwarded = {**raw, "guard_remaining_ms": 250}
    receipt = _valid_native_receipt()

    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=json.dumps(raw),
        event_name="PreToolUse",
    )
    assert record_native_worker(
        guard_home=guard_home,
        payload=forwarded,
        harness="codex",
        event_name="PreToolUse",
        receipt=receipt,
    )

    output = _output_path(directory).read_text(encoding="utf-8")
    assert "SECRET_COMMAND" not in output
    rows = _rows(directory)
    assert rows[0]["raw_payload_sha256"] != rows[1]["forwarded_payload_sha256"]
    assert rows[1]["decision_scope"] == "native_edge"
    assert cast(dict[str, object], rows[1]["receipt"])["request_digest"] == "a" * 64
    assert "request_digest" not in rows[1]
    assert join_binding_records(rows)["status"] == "bound"


def test_bridge_capture_happens_before_forwarded_transport_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge

    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_call_id":"call-early"}'
    monkeypatch.setattr(bridge, "_hook_input", lambda _limit: raw)
    monkeypatch.setattr(
        bridge,
        "_with_browser_wait_process",
        lambda data, *, wait_timeout_seconds: data[:-1] + ',"transport_added":true}',
    )

    bound = bridge._bound_hook_input(
        {"PreToolUse": 10},
        capture_guard_home=guard_home,
    )
    assert bound is not None
    event_name, forwarded, _timeout = bound

    assert event_name == "PreToolUse"
    assert json.loads(forwarded)["transport_added"] is True
    row = _rows(directory)[0]
    assert row["raw_payload_sha256"] == hashlib.sha256(
        b'{"hook_event_name":"PreToolUse","tool_call_id":"call-early"}'
    ).hexdigest()


def test_expired_or_unsafe_marker_is_inert(tmp_path: Path) -> None:
    expired_home = tmp_path / "expired"
    expired_directory = _enable_capture(expired_home, expires_at=int(time.time()) - 1)
    assert not record_bridge_ingress(
        guard_home=expired_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_call_id":"call-expired"}',
        event_name="PreToolUse",
    )
    assert not _output_path(expired_directory).exists()

    unsafe_home = tmp_path / "unsafe"
    unsafe_directory = _enable_capture(unsafe_home)
    (unsafe_directory / CAPTURE_MARKER_NAME).chmod(0o644)
    assert not record_bridge_ingress(
        guard_home=unsafe_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_call_id":"call-unsafe"}',
        event_name="PreToolUse",
    )
    assert not _output_path(unsafe_directory).exists()


def test_missing_id_is_unbound_and_duplicate_rows_are_ambiguous(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    missing = '{"hook_event_name":"PreToolUse","tool_input":{"command":"echo hidden"}}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=missing, event_name="PreToolUse")
    missing_result = join_binding_records(_rows(directory))
    assert missing_result["status"] == "unbound"
    assert missing_result["issues"] == [{"status": "unbound", "reason": "missing_tool_call_id"}]

    guard_home = tmp_path / "duplicates"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_call_id":"call-duplicate"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert join_binding_records(_rows(directory))["status"] == "ambiguous"


def test_unsupported_id_is_explicitly_unbound_without_echoing_path_content(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    secret_path = "/private/secret/path?token=hidden"
    raw = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_call_id": secret_path,
            "tool_input": {"command": "echo hidden"},
        }
    )

    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    output = _output_path(directory).read_text(encoding="utf-8")
    assert secret_path not in output
    rows = _rows(directory)
    assert rows[0]["tool_call_id_state"] == "unsupported"
    assert join_binding_records(rows)["issues"] == [
        {"status": "unbound", "reason": "unsupported_tool_call_id"}
    ]


def test_unmanaged_event_label_is_never_persisted_or_joined(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    secret_label = "/private/secret/config"
    raw = '{"hook_event_name":"PreToolUse","tool_call_id":"call-event"}'

    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=raw,
        event_name=secret_label,
    )
    assert not _output_path(directory).exists()

    externally_supplied = {
        "schema": CAPTURE_SCHEMA,
        "run_id": "run-1",
        "route": "bridge_ingress",
        "harness": "codex",
        "event_name": secret_label,
        "tool_call_id_state": "present",
        "tool_call_id": "call-event",
        "raw_payload_sha256": "a" * 64,
    }
    result = join_binding_records([externally_supplied])
    assert result["status"] == "invalid"
    assert result["issues"] == [{"status": "invalid", "reason": "record_shape"}]
    assert secret_label not in json.dumps(result, sort_keys=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("route", []),
        ("route", {}),
        ("tool_call_id_state", []),
        ("tool_call_id_state", {}),
        ("harness", "claude-code"),
    ],
)
def test_malformed_external_rows_are_invalid_without_normalizer_or_output_parser_errors(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    row: dict[str, object] = {
        "schema": CAPTURE_SCHEMA,
        "run_id": "run-1",
        "route": "bridge_ingress",
        "harness": "codex",
        "event_name": "PreToolUse",
        "tool_call_id_state": "present",
        "tool_call_id": "call-malformed",
        "raw_payload_sha256": "a" * 64,
    }
    row[field] = value

    result = join_binding_records([row])
    assert result["status"] == "invalid"
    assert result["issues"] == [{"status": "invalid", "reason": "record_shape"}]

    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    output = _output_path(directory)
    output.write_text(json.dumps(row, separators=(",", ":")) + "\n", encoding="utf-8")
    output.chmod(0o600)
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_call_id":"call-next"}',
        event_name="PreToolUse",
    )


def test_record_and_byte_bounds_reject_without_decision_side_effect(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home, max_records=1)
    raw = '{"hook_event_name":"PreToolUse","tool_call_id":"call-once"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert len(_rows(directory)) == 1

    oversized_home = tmp_path / "oversized"
    oversized_directory = _enable_capture(oversized_home)
    oversized = json.dumps(
        {"hook_event_name": "PreToolUse", "tool_call_id": "call-large", "tool_input": {"command": "x" * 70_000}}
    )
    assert not record_bridge_ingress(guard_home=oversized_home, raw_payload=oversized, event_name="PreToolUse")
    assert not _output_path(oversized_directory).exists()


@pytest.mark.skipif(not hasattr(os, "link"), reason="hard links unavailable")
def test_output_hardlink_is_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_call_id":"call-hardlink"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    output = _output_path(directory)
    alias = directory / "alias"
    os.link(output, alias)
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_marker_symlink_is_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    marker = directory / CAPTURE_MARKER_NAME
    target = tmp_path / "foreign-marker.json"
    target.write_text(marker.read_text(encoding="utf-8"), encoding="utf-8")
    target.chmod(0o600)
    marker.unlink()
    marker.symlink_to(target)
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_call_id":"call-symlink"}',
        event_name="PreToolUse",
    )
    assert not _output_path(directory).exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_guard_home_ancestor_symlink_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_home = real_parent / "real-guard-home"
    directory = _enable_capture(real_home)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    alias = alias_parent / "real-guard-home"

    assert not record_bridge_ingress(
        guard_home=alias,
        raw_payload='{"hook_event_name":"PreToolUse","tool_call_id":"call-alias"}',
        event_name="PreToolUse",
    )
    assert not _output_path(directory).exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_marker_and_output_fifos_are_nonblocking_and_inert(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    directory = guard_home / "diagnostics"
    directory.mkdir(mode=0o700)
    marker = directory / CAPTURE_MARKER_NAME
    os.mkfifo(marker, 0o600)

    started = time.monotonic()
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_call_id":"call-marker-fifo"}',
        event_name="PreToolUse",
    )
    assert time.monotonic() - started < 1.0

    marker.unlink()
    _enable_capture(guard_home)
    output = _output_path(directory)
    os.mkfifo(output, 0o600)
    started = time.monotonic()
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_call_id":"call-output-fifo"}',
        event_name="PreToolUse",
    )
    assert time.monotonic() - started < 1.0


def test_native_receipt_validation_rejects_forged_or_mismatched_receipt(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    payload = {"hook_event_name": "PreToolUse", "tool_call_id": "call-receipt"}
    forged = _valid_native_receipt()
    forged["decision_id"] = "f" * 64
    assert not record_native_worker(
        guard_home=guard_home,
        payload=payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=forged,
    )
    mismatch = _valid_native_receipt()
    mismatch["event_name"] = "PostToolUse"
    assert not record_native_worker(
        guard_home=guard_home,
        payload=payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=mismatch,
    )
    assert not _output_path(directory).exists()


@pytest.mark.parametrize("harness", ["claude-code", "pi"])
def test_native_worker_capture_is_codex_only(tmp_path: Path, harness: str) -> None:
    guard_home = tmp_path / harness
    directory = _enable_capture(guard_home)
    assert not record_native_worker(
        guard_home=guard_home,
        payload={"hook_event_name": "PreToolUse", "tool_call_id": "call-foreign"},
        harness=harness,
        event_name="PreToolUse",
        receipt=_valid_native_receipt(),
    )
    assert not _output_path(directory).exists()


def test_shared_native_worker_boundary_captures_after_receipt_acceptance(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin

    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    receipt = _valid_native_receipt()
    edge = {
        "event_name": "PreToolUse",
        "harness": "codex",
        "result": {
            "decision": "allow",
            "minimum_action": "allow",
            "policy_action": "allow",
            "reason_code": "native_allow",
        },
        "receipt": receipt,
    }
    host = SimpleNamespace(
        store=SimpleNamespace(),
        activity_writer=None,
        _last_native_decision_receipt=None,
        _review_raw_hook_native=lambda **_kwargs: edge,
    )
    record_receipt = cast(
        Callable[..., object],
        HookWorkerNativeMixin._record_native_decision_receipt,  # pyright: ignore[reportAttributeAccessIssue]
    )
    host._record_native_decision_receipt = MethodType(record_receipt, host)

    review_native_edge = cast(
        Callable[..., tuple[dict[str, object], bool]],
        HookWorkerNativeMixin._review_native_edge_with_snapshot,  # pyright: ignore[reportAttributeAccessIssue]
    )
    response, native_used = review_native_edge(
        host,
        payload={"hook_event_name": "PreToolUse", "tool_call_id": "call-worker"},
        harness="codex",
        event_name="PreToolUse",
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=None,
        deadline=None,
        policy_snapshot=None,
        recording_only=False,
    )

    assert native_used is True
    assert response["policy_action"] == "allow"
    rows = _rows(directory)
    assert len(rows) == 1
    assert rows[0]["decision_scope"] == "native_edge"
    assert cast(dict[str, object], rows[0]["receipt"])["decision_id"] == receipt["decision_id"]


def test_capture_latency_does_not_extend_bridge_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge

    clock = [100.0]
    captured: dict[str, object] = {}
    raw = '{"hook_event_name":"PreToolUse","tool_call_id":"call-deadline"}'
    monkeypatch.setattr(bridge.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(bridge, "_hook_input", lambda _limit: raw)
    monkeypatch.setattr(bridge, "_with_browser_wait_process", lambda data, *, wait_timeout_seconds: data)

    def slow_capture(**_kwargs: object) -> bool:
        clock[0] += 3.0
        return True

    monkeypatch.setattr(bridge, "record_bridge_ingress", slow_capture)

    def review(**kwargs: object) -> tuple[dict[str, object], bool, bool]:
        captured.update(kwargs)
        return {"continue": True}, False, False

    monkeypatch.setattr(bridge, "bridge_review_response", review)
    monkeypatch.setattr(bridge, "_bridge_output", lambda *_args, **_kwargs: "{}")

    assert (
        bridge.main(
            state_path=tmp_path / "guard-home" / "daemon-state.json",
            fallback_command=("fallback",),
            start_command=("start",),
            query="",
            hook_timeouts={"PreToolUse": 10},
        )
        == 0
    )
    assert captured["deadline"] == 108.0
    assert capsys.readouterr().out == "{}"
