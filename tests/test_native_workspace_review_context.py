from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.review_contracts import GuardReviewOAuthMetadata
from codex_plugin_scanner.guard.runtime import cloud_review_event_projection as projection
from codex_plugin_scanner.guard.runtime import native_workspace_review_context as context
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_cloud_review_sync_worker import Store


def _authority() -> dict[str, object]:
    return {
        "schema": "guard-native-workspace-review-authority.v1",
        "version": 1,
        "purpose": "cloud_review_team_delegation",
        "key_algorithm": "ed25519",
        "key_id": "a" * 64,
        "public_key": "b" * 64,
        "workspace_binding": "c" * 64,
        "device_binding": "d" * 64,
        "installation_binding": "e" * 64,
        "enrollment_generation": 1,
        "previous_key_id": None,
        "scope_contract_version": "guard-native-workspace-review-scope.v1",
        "scope_binding": "f" * 64,
        "issued_at_ms": 1,
        "expires_at_ms": 2,
        "status": "active",
        "enrollment_signature": "1" * 128,
    }


def _response(request_id: str = "request-1") -> dict[str, object]:
    authority = _authority()
    return {
        "schema": "guard-native-workspace-review-context.v1",
        "version": 1,
        "request_id": request_id,
        "authority_record": authority,
        "authority_record_digest": "2" * 64,
        "authority_generation": 1,
        "authority_key_id": authority["key_id"],
        "workspace_binding": authority["workspace_binding"],
        "device_binding": authority["device_binding"],
        "installation_binding": authority["installation_binding"],
        "scope_binding": authority["scope_binding"],
        "request_snapshot_digest": "3" * 64,
        "request_binding": "4" * 64,
        "action_binding": "5" * 64,
        "intent_binding": "6" * 64,
        "revision_binding": "7" * 64,
        "policy_binding": "8" * 64,
        "retry_scope_binding": "9" * 64,
    }


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native/hol-guard-runtime")),
        capabilities=SimpleNamespace(
            features=(
                "resident-protocol-v2",
                "native-workspace-review-context-v1",
            )
        ),
    )


def test_context_uses_resident_response_without_reimplementing_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(context, "native_runtime_status", _status)
    monkeypatch.setattr(context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(context, "stage_workspace_review_request", lambda *_args: {})

    def request(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return json.dumps(_response()).encode("utf-8")

    monkeypatch.setattr(context, "native_resident_client_request", request)
    result = context.build_native_workspace_review_context(
        cast(context.NativeWorkspaceReviewStore, object()), tmp_path, "request-1"
    )
    assert result == _response()
    payload = cast(bytes, captured["payload"])
    assert json.loads(payload.decode("utf-8")) == {
        "operation": "workspace_review_context",
        "request": {"request_id": "request-1"},
    }


def test_invalid_authority_context_is_omitted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(context, "native_runtime_status", _status)
    monkeypatch.setattr(context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(context, "stage_workspace_review_request", lambda *_args: {})
    invalid = _response()
    authority = invalid["authority_record"]
    assert isinstance(authority, dict)
    authority["status"] = "revoked"
    monkeypatch.setattr(
        context,
        "native_resident_client_request",
        lambda **_kwargs: json.dumps(invalid).encode("utf-8"),
    )
    assert (
        context.build_native_workspace_review_context(
            cast(context.NativeWorkspaceReviewStore, object()), tmp_path, "request-1"
        )
        is None
    )


def test_cloud_projection_attaches_optional_context_only_for_pending_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(projection, "build_local_review_request_claim", lambda **_kwargs: None)
    monkeypatch.setattr(
        projection,
        "build_native_workspace_review_context",
        lambda *_args: {"schema": "guard-native-workspace-review-context.v1"},
    )
    event = projection.build_cloud_review_event(
        {
            "request_id": "request-1",
            "status": "pending",
            "harness": "guard-review",
            "raw_command_text": "git status",
            "created_at": "2026-09-25T12:00:00+00:00",
            "last_seen_at": "2026-09-25T12:00:00+00:00",
        },
        oauth=cast(GuardReviewOAuthMetadata, object()),
        redaction_level="none",
        store=cast(GuardStore, cast(object, Store(tmp_path))),
        event_sequence=1,
    )
    assert event is not None
    request_payload = event["requestPayload"]
    assert isinstance(request_payload, dict)
    assert request_payload["nativeWorkspaceReview"] == {"schema": "guard-native-workspace-review-context.v1"}
