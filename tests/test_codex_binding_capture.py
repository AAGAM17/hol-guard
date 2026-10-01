"""Bounded, opt-in Codex ingress to native-edge receipt diagnostics."""

from __future__ import annotations

import base64
import builtins
import hashlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import MethodType, SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard import codex_binding_capture_fs as capture_fs
from codex_plugin_scanner.guard.codex_binding_capture import (
    CAPTURE_MARKER_NAME,
    CAPTURE_OUTPUT_PREFIX,
    CAPTURE_OUTPUT_SUFFIX,
    CAPTURE_SCHEMA,
    MAX_CAPTURE_BYTES,
    initialize_capture_marker,
    join_binding_records,
    read_capture_session,
    record_bridge_ingress,
    record_native_worker,
)
from codex_plugin_scanner.guard.codex_binding_capture_bounds import canonical_json_bytes
from codex_plugin_scanner.guard.codex_binding_capture_crypto import (
    new_capture_session,
    open_receipt,
    payload_hmac,
    row_aad,
    row_hmac,
)
from codex_plugin_scanner.guard.codex_binding_capture_join import valid_existing_records
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
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    guard_home.chmod(0o700)
    requested_expiry = int(time.time()) + 300 if expires_at is None else expires_at
    session_expiry = requested_expiry if requested_expiry > int(time.time()) else int(time.time()) + 300
    session = initialize_capture_marker(
        guard_home,
        run_id=run_id,
        expires_at=session_expiry,
        max_records=max_records,
        max_bytes=max_bytes,
    )
    assert session is not None
    if requested_expiry != session_expiry:
        marker = directory / CAPTURE_MARKER_NAME
        marker_payload = json.loads(marker.read_text(encoding="utf-8"))
        marker_payload["expires_at"] = requested_expiry
        marker.write_text(json.dumps(marker_payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
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


def _session(guard_home: Path):
    session = read_capture_session(guard_home)
    assert session is not None
    return session


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
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-1"}',
        event_name="PreToolUse",
    )
    assert not (guard_home / "diagnostics").exists()


def test_capture_keeps_raw_and_forwarded_fingerprints_separate_without_raw_content(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = {
        "hook_event_name": "PreToolUse",
        "tool_use_id": "call-1",
        "tool_input": {"command": "echo SECRET_COMMAND"},
    }
    forwarded = {**raw, "guard_remaining_ms": 250}
    receipt = _valid_native_receipt()

    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=json.dumps(raw),
        forwarded_payload=json.dumps(forwarded),
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
    assert rows[0]["raw_payload_hmac_sha256"] != rows[0]["forwarded_payload_hmac_sha256"]
    assert rows[0]["forwarded_payload_hmac_sha256"] == rows[1]["forwarded_payload_hmac_sha256"]
    assert rows[1]["decision_scope"] == "native_edge"
    sealed = cast(dict[str, object], rows[1]["sealed_receipt"])
    decrypted = open_receipt(_session(guard_home), rows[1], sealed)
    assert decrypted is not None
    assert decrypted["request_digest"] == "a" * 64
    assert "request_digest" not in rows[1]
    assert join_binding_records(rows, capture_session=_session(guard_home))["status"] == "bound"


def _capture_pair(tmp_path: Path) -> tuple[Path, list[dict[str, object]]]:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_use_id": "call-security",
        "tool_input": {"command": "echo synthetic-secret"},
    }
    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=json.dumps(payload),
        event_name="PreToolUse",
    )
    assert record_native_worker(
        guard_home=guard_home,
        payload=payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=_valid_native_receipt(),
    )
    return guard_home, _rows(directory)


def test_keyed_rows_hide_secret_material_and_unkeyed_dictionary_digests(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    serialized = json.dumps(rows, sort_keys=True)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_use_id": "call-security",
        "tool_input": {"command": "echo synthetic-secret"},
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    unkeyed_digest = hashlib.sha256(canonical).hexdigest()
    marker_key = base64.urlsafe_b64encode(session.key).decode("ascii")
    assert "synthetic-secret" not in serialized
    assert unkeyed_digest not in serialized
    assert marker_key not in serialized
    assert all(
        field not in serialized
        for field in (
            "request_digest",
            "decision_id",
            "reviewed_output_sha256",
            "raw_payload_sha256",
            "forwarded_payload_sha256",
        )
    )
    assert rows[0]["raw_payload_hmac_sha256"] != rows[0]["forwarded_payload_hmac_sha256"]


def test_join_requires_same_run_key_and_rejects_missing_rotation_or_expiry(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    assert join_binding_records(rows)["status"] == "unbound"
    missing_issues = cast(list[dict[str, object]], join_binding_records(rows)["issues"])
    assert all(item["reason"] == "missing_capture_key" for item in missing_issues)

    wrong_key = replace(session, key=b"w" * 32)
    assert join_binding_records(rows, capture_session=wrong_key)["status"] == "unbound"
    rotated = new_capture_session("run-1", expires_at=int(time.time()) + 300)
    assert rotated is not None
    assert join_binding_records(rows, capture_session=rotated)["status"] == "unbound"
    cross_run = new_capture_session("different-run", expires_at=int(time.time()) + 300)
    assert cross_run is not None
    assert join_binding_records(rows, capture_session=cross_run)["status"] == "unbound"
    expired = replace(session, expires_at=int(time.time()) - 1)
    assert join_binding_records(rows, capture_session=expired)["status"] == "unbound"


def test_aggregate_capture_limits_include_newlines_and_session_cap(tmp_path: Path) -> None:
    many_rows = [{"padding": "x" * 1_000} for _ in range(70)]
    result = join_binding_records(many_rows)
    assert result["status"] == "invalid"
    assert result["joins"] == []
    assert result["issues"] == [{"status": "invalid", "reason": "record_size"}]

    guard_home, rows = _capture_pair(tmp_path / "tight")
    tight_session = replace(_session(guard_home), max_bytes=1)
    tight_result = join_binding_records(rows, capture_session=tight_session)
    assert tight_result["status"] == "invalid"
    assert tight_result["joins"] == []
    assert tight_result["issues"] == [{"status": "invalid", "reason": "record_size"}]

    oversized_raw = b"{}\n" * (MAX_CAPTURE_BYTES // 3 + 1)
    assert valid_existing_records(oversized_raw, run_id="run-1", capture_session=_session(guard_home)) is None


def test_session_record_limit_prevents_pair_binding_and_existing_rows(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = replace(_session(guard_home), max_records=1)

    result = join_binding_records(rows, capture_session=session)
    assert result["status"] == "ambiguous"
    assert result["joins"] == []
    assert result["issues"] == [{"status": "ambiguous", "reason": "record_limit_exceeded"}]

    raw = _output_path(guard_home / "diagnostics").read_bytes()
    assert valid_existing_records(raw, run_id="run-1", capture_session=session) is None


def test_ingress_rejects_oversized_utf8_before_json_parse_and_deep_json(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    oversized = '{"hook_event_name":"PreToolUse","tool_use_id":"call-preparse","tool_input":{"command":"' + (
        "x" * MAX_CAPTURE_BYTES
    ) + '"}}'
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=oversized, event_name="PreToolUse")
    unicode_oversized = '{"hook_event_name":"PreToolUse","tool_use_id":"call-utf8","tool_input":{"command":"' + (
        "é" * (MAX_CAPTURE_BYTES // 2)
    ) + '"}}'
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=unicode_oversized, event_name="PreToolUse")
    assert not (directory / f"{CAPTURE_OUTPUT_PREFIX}run-1{CAPTURE_OUTPUT_SUFFIX}").exists()

    deep: dict[str, object] = {"hook_event_name": "PreToolUse", "tool_use_id": "call-deep"}
    cursor = deep
    for _ in range(70):
        nested: dict[str, object] = {}
        cursor["nested"] = nested
        cursor = nested
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=json.dumps(deep), event_name="PreToolUse")


def test_canonical_json_rejects_deep_and_cyclic_values_without_serializing_unbounded() -> None:
    deep: list[object] = []
    cursor = deep
    for _ in range(70):
        nested: list[object] = []
        cursor.append(nested)
        cursor = nested
    assert canonical_json_bytes(deep) is None

    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    assert canonical_json_bytes(cyclic) is None


def test_missing_aesgcm_backend_fails_closed_at_seal_and_open_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seal_home = tmp_path / "seal"
    seal_directory = _enable_capture(seal_home)
    existing_home, existing_rows = _capture_pair(tmp_path / "open")
    payload = {"hook_event_name": "PreToolUse", "tool_use_id": "call-backend"}
    real_import = builtins.__import__

    def missing_backend(
        name: str,
        globals_arg: object = None,
        locals_arg: object = None,
        fromlist: object = (),
        level: int = 0,
    ) -> object:
        if name == "cryptography.hazmat.primitives.ciphers.aead":
            raise ImportError("injected missing AESGCM backend")
        return real_import(name, globals_arg, locals_arg, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", missing_backend)
    assert not record_native_worker(
        guard_home=seal_home,
        payload=payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=_valid_native_receipt(),
    )
    assert not (seal_directory / f"{CAPTURE_OUTPUT_PREFIX}run-1{CAPTURE_OUTPUT_SUFFIX}").exists()
    open_session = _session(existing_home)
    sealed = cast(dict[str, object], existing_rows[1]["sealed_receipt"])
    assert open_receipt(open_session, existing_rows[1], sealed) is None


def test_row_mac_and_aead_tampering_never_bind(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    row_tampered = [dict(row) for row in rows]
    row_tampered[0]["forwarded_payload_hmac_sha256"] = "f" * 64
    result = join_binding_records(row_tampered, capture_session=session)
    assert result["status"] == "unbound"
    assert result["issues"] == [{"status": "unbound", "reason": "row_mac_mismatch"}]

    aead_tampered = [dict(row) for row in rows]
    sealed = dict(cast(dict[str, object], aead_tampered[1]["sealed_receipt"]))
    ciphertext = str(sealed["ciphertext_b64"])
    sealed["ciphertext_b64"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    aead_tampered[1]["sealed_receipt"] = sealed
    refreshed_mac = row_hmac(session, aead_tampered[1])
    assert refreshed_mac is not None
    aead_tampered[1]["row_mac"] = refreshed_mac
    assert join_binding_records(aead_tampered, capture_session=session)["status"] == "invalid"


@pytest.mark.parametrize(
    "plaintext",
    [
        pytest.param(b'{"nested":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}", id="parser-recursion"),
        pytest.param(b'{"nested":' + b"[" * 65 + b"0" + b"]" * 65 + b"}", id="structural-depth"),
        pytest.param(b'{"nodes":[' + b"0," * 4096 + b"0]}", id="structural-nodes"),
    ],
)
def test_authenticated_malformed_receipt_plaintext_fails_closed(tmp_path: Path, plaintext: bytes) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    aad = row_aad(rows[1])
    assert aad is not None
    nonce = os.urandom(12)
    ciphertext = AESGCM(session.key).encrypt(nonce, plaintext, aad)
    sealed = {
        "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }
    rows[1]["sealed_receipt"] = sealed
    mac = row_hmac(session, rows[1])
    assert mac is not None
    rows[1]["row_mac"] = mac

    assert open_receipt(session, rows[1], sealed) is None
    assert join_binding_records(rows, capture_session=session)["status"] == "invalid"


def test_legacy_and_mixed_capture_rows_are_quarantined_without_migration(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = _session(guard_home)
    legacy = dict(rows[0])
    legacy["schema"] = "guard-codex-binding-capture.v1"
    legacy_result = join_binding_records([legacy], capture_session=session)
    assert legacy_result["status"] == "invalid"
    assert legacy_result["issues"] == [{"status": "invalid", "reason": "legacy_capture_schema"}]

    mixed = dict(rows[0])
    mixed["fingerprint_scheme"] = "sha256-unkeyed-v1"
    mixed_result = join_binding_records([mixed], capture_session=session)
    assert mixed_result["status"] == "invalid"
    assert mixed_result["issues"] == [{"status": "invalid", "reason": "record_shape"}]


def test_payload_fingerprint_mismatch_is_not_bound(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = {"hook_event_name": "PreToolUse", "tool_use_id": "call-mismatch", "tool_input": {"command": "one"}}
    changed = {**raw, "tool_input": {"command": "two"}}
    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=json.dumps(raw),
        event_name="PreToolUse",
    )
    assert record_native_worker(
        guard_home=guard_home,
        payload=changed,
        harness="codex",
        event_name="PreToolUse",
        receipt=_valid_native_receipt(),
    )
    result = join_binding_records(_rows(directory), capture_session=_session(guard_home))
    assert result["status"] == "invalid"
    assert result["joins"] == [
        {
            "status": "invalid",
            "reason": "payload_fingerprint_mismatch",
            "identity": ("run-1", "codex", "PreToolUse", "call-mismatch"),
        }
    ]


def test_documented_tool_use_id_is_captured(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = json.dumps({"hook_event_name": "PreToolUse", "tool_use_id": "call-use"})
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    row = _rows(directory)[0]
    assert row["tool_use_id_state"] == "present"
    assert row["tool_use_id"] == "call-use"


def test_legacy_tool_call_id_is_unbound_without_alias_fallback(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = json.dumps({"hook_event_name": "PreToolUse", "tool_call_id": "legacy-call"})
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    row = _rows(directory)[0]
    assert row["tool_use_id_state"] == "missing"
    assert "tool_use_id" not in row
    assert join_binding_records([row], capture_session=_session(guard_home))["issues"] == [
        {"status": "unbound", "reason": "missing_tool_use_id"}
    ]


def test_event_alias_is_canonicalized_and_prompt_rows_are_not_applicable(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"pre_tool_use","tool_use_id":"call-alias-event"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="pre_tool_use")
    assert _rows(directory)[0]["event_name"] == "PreToolUse"

    prompt_home = tmp_path / "prompt"
    prompt_directory = _enable_capture(prompt_home)
    assert record_bridge_ingress(
        guard_home=prompt_home,
        raw_payload='{"hook_event_name":"UserPromptSubmit","tool_use_id":"prompt-1"}',
        event_name="UserPromptSubmit",
    )
    assert (
        join_binding_records(_rows(prompt_directory), capture_session=_session(prompt_home))["status"]
        == "not_applicable"
    )


@pytest.mark.parametrize(
    "raw",
    [
        '{"hook_event_name":"UserPromptSubmit","prompt":"hello"}',
        '{"hook_event_name":"UserPromptSubmit","tool_use_id":"/private/secret"}',
    ],
)
def test_non_bindable_missing_or_unsupported_id_is_not_applicable(tmp_path: Path, raw: str) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)

    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload=raw,
        event_name="UserPromptSubmit",
    )

    result = join_binding_records(_rows(directory), capture_session=_session(guard_home))
    assert result["status"] == "not_applicable"
    assert result["joins"] == []
    assert result["issues"] == [{"status": "not_applicable", "reason": "native_receipt_unsupported_event"}]


def test_bridge_capture_happens_before_forwarded_transport_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge

    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-early"}'
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
    event_name, forwarded, _timeout, _input_ready_at = bound

    assert event_name == "PreToolUse"
    assert json.loads(forwarded)["transport_added"] is True
    row = _rows(directory)[0]
    session = _session(guard_home)
    assert row["raw_payload_hmac_sha256"] == payload_hmac(
        session,
        "raw",
        {"hook_event_name": "PreToolUse", "tool_use_id": "call-early"},
    )
    assert row["forwarded_payload_hmac_sha256"] == payload_hmac(session, "forwarded", json.loads(forwarded))


def test_expired_or_unsafe_marker_is_inert(tmp_path: Path) -> None:
    expired_home = tmp_path / "expired"
    expired_directory = _enable_capture(expired_home, expires_at=int(time.time()) - 1)
    assert not record_bridge_ingress(
        guard_home=expired_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-expired"}',
        event_name="PreToolUse",
    )
    assert not _output_path(expired_directory).exists()

    unsafe_home = tmp_path / "unsafe"
    unsafe_directory = _enable_capture(unsafe_home)
    (unsafe_directory / CAPTURE_MARKER_NAME).chmod(0o644)
    assert not record_bridge_ingress(
        guard_home=unsafe_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-unsafe"}',
        event_name="PreToolUse",
    )
    assert not _output_path(unsafe_directory).exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_marker_initializer_rejects_symlinked_directories_and_overwrite(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_home = real_parent / "real-guard-home"
    real_home.mkdir(mode=0o700, parents=True)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    assert (
        initialize_capture_marker(
            alias_parent / "real-guard-home",
            run_id="run-symlink",
            expires_at=int(time.time()) + 300,
        )
        is None
    )

    first = initialize_capture_marker(real_home, run_id="run-existing", expires_at=int(time.time()) + 300)
    assert first is not None
    second = initialize_capture_marker(real_home, run_id="run-overwrite", expires_at=int(time.time()) + 300)
    assert second is None

    swapped_home = tmp_path / "swapped-home"
    swapped_home.mkdir(mode=0o700)
    foreign_diagnostics = tmp_path / "foreign-diagnostics"
    foreign_diagnostics.mkdir(mode=0o700)
    (swapped_home / "diagnostics").symlink_to(foreign_diagnostics, target_is_directory=True)
    assert (
        initialize_capture_marker(
            swapped_home,
            run_id="run-swap",
            expires_at=int(time.time()) + 300,
        )
        is None
    )


def test_marker_write_failure_preserves_replacement_sentinel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    directory = guard_home / "diagnostics"
    directory.mkdir(mode=0o700)
    marker = directory / CAPTURE_MARKER_NAME
    replacement = directory / "renamed-original-marker"
    sentinel = b"replacement-sentinel"
    state = {"swapped": False}

    def fail_after_replacement(_descriptor: int, _payload: bytes) -> int:
        if not state["swapped"]:
            marker.rename(replacement)
            marker.write_bytes(sentinel)
            marker.chmod(0o600)
            state["swapped"] = True
        raise OSError("injected marker write failure")

    monkeypatch.setattr(capture_fs.os, "write", fail_after_replacement)
    assert (
        initialize_capture_marker(
            guard_home,
            run_id="run-write-failure",
            expires_at=int(time.time()) + 300,
        )
        is None
    )
    assert marker.read_bytes() == sentinel
    assert replacement.exists()


@pytest.mark.parametrize("write_result", [0, -1])
def test_marker_nonpositive_write_is_bounded_and_inert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_result: int,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)

    monkeypatch.setattr(capture_fs.os, "write", lambda _descriptor, _payload: write_result)
    started = time.monotonic()
    assert (
        initialize_capture_marker(
            guard_home,
            run_id="run-no-progress",
            expires_at=int(time.time()) + 300,
        )
        is None
    )
    assert time.monotonic() - started < 1.0
    assert (guard_home / "diagnostics" / CAPTURE_MARKER_NAME).exists()


def test_missing_id_is_unbound_and_duplicate_rows_are_ambiguous(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    missing = '{"hook_event_name":"PreToolUse","tool_input":{"command":"echo hidden"}}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=missing, event_name="PreToolUse")
    missing_result = join_binding_records(_rows(directory), capture_session=_session(guard_home))
    assert missing_result["status"] == "unbound"
    assert missing_result["issues"] == [{"status": "unbound", "reason": "missing_tool_use_id"}]

    guard_home = tmp_path / "duplicates"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-duplicate"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert join_binding_records(_rows(directory), capture_session=_session(guard_home))["status"] == "ambiguous"


def test_unsupported_id_is_explicitly_unbound_without_echoing_path_content(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    secret_path = "/private/secret/path?token=hidden"
    raw = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_use_id": secret_path,
            "tool_input": {"command": "echo hidden"},
        }
    )

    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    output = _output_path(directory).read_text(encoding="utf-8")
    assert secret_path not in output
    rows = _rows(directory)
    assert rows[0]["tool_use_id_state"] == "unsupported"
    assert join_binding_records(rows, capture_session=_session(guard_home))["issues"] == [
        {"status": "unbound", "reason": "unsupported_tool_use_id"}
    ]


def test_unmanaged_event_label_is_never_persisted_or_joined(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    secret_label = "/private/secret/config"
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-event"}'

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
        "tool_use_id_state": "present",
        "tool_use_id": "call-event",
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
        ("tool_use_id_state", []),
        ("tool_use_id_state", {}),
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
        "tool_use_id_state": "present",
        "tool_use_id": "call-malformed",
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
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-next"}',
        event_name="PreToolUse",
    )


def test_malformed_missing_id_row_is_invalid_after_full_shape_validation() -> None:
    row = {
        "schema": CAPTURE_SCHEMA,
        "run_id": "run-1",
        "route": "bridge_ingress",
        "harness": "codex",
        "event_name": "PreToolUse",
        "tool_use_id_state": "missing",
        "raw_payload_sha256": "z" * 64,
        "forwarded_payload_sha256": "a" * 64,
    }

    result = join_binding_records([row])
    assert result["status"] == "invalid"
    assert result["issues"] == [{"status": "invalid", "reason": "record_shape"}]


def test_record_and_byte_bounds_reject_without_decision_side_effect(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home, max_records=1)
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-once"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert len(_rows(directory)) == 1

    oversized_home = tmp_path / "oversized"
    oversized_directory = _enable_capture(oversized_home)
    oversized = json.dumps(
        {"hook_event_name": "PreToolUse", "tool_use_id": "call-large", "tool_input": {"command": "x" * 70_000}}
    )
    assert not record_bridge_ingress(guard_home=oversized_home, raw_payload=oversized, event_name="PreToolUse")
    assert not _output_path(oversized_directory).exists()


@pytest.mark.skipif(not hasattr(os, "link"), reason="hard links unavailable")
def test_output_hardlink_is_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-hardlink"}'
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
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-symlink"}',
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
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-alias"}',
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
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-marker-fifo"}',
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
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-output-fifo"}',
        event_name="PreToolUse",
    )
    assert time.monotonic() - started < 1.0


def test_native_receipt_validation_rejects_forged_or_mismatched_receipt(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    payload = {"hook_event_name": "PreToolUse", "tool_use_id": "call-receipt"}
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
        payload={"hook_event_name": "PreToolUse", "tool_use_id": "call-foreign"},
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
        payload={"hook_event_name": "PreToolUse", "tool_use_id": "call-worker"},
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
    assert "receipt" not in rows[0]
    assert "decision_id" not in rows[0]
    decrypted = open_receipt(_session(guard_home), rows[0], cast(dict[str, object], rows[0]["sealed_receipt"]))
    assert decrypted is not None
    assert decrypted["decision_id"] == receipt["decision_id"]


def test_capture_latency_does_not_extend_bridge_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge

    clock = [100.0]
    captured: dict[str, object] = {}
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-deadline"}'
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
