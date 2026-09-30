from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.daemon import mcp_registry_undo
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.codex_mcp_setup import CodexMcpSetupReceipt
from codex_plugin_scanner.guard.store import GuardStore


def _setup(tmp_path: Path):
    store = GuardStore(tmp_path / "guard")
    service = LocalCliApiService(store=store)
    candidate = {
        "host": "codex",
        "kind": "remote",
        "setup_name": "example",
        "registry_name": "org.example/server",
        "version": "1.0.0",
        "endpoint": "https://example.test/mcp",
        "selection_digest": "a" * 64,
        "permissions_granted": False,
        "host_change_applied": False,
    }
    receipt = CodexMcpSetupReceipt(
        "example", "/synthetic/private/config.toml", "v1", json.dumps({"url": candidate["endpoint"]})
    )
    handle = service._registry_setup_undo.remember(receipt, candidate)
    payload = {
        "operation": "rollback",
        "rollback_handle": handle,
        "setup_name": "example",
        "selection_digest": "a" * 64,
        "confirm_host_change": True,
        "session_nonce": "n" * 32,
    }
    return store, service, receipt, handle, payload


def _protect(store):
    update_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": "synthetic-password",
            "confirm_password": "synthetic-password",
            "cooldown_seconds": 0,
        },
    )


def test_undo_requires_fresh_proof_and_success_cannot_be_replayed(tmp_path, monkeypatch):
    store, service, receipt, handle, payload = _setup(tmp_path)
    calls = []
    monkeypatch.setattr(mcp_registry_undo.shutil, "which", lambda _name: "/synthetic/codex")
    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", lambda *args: calls.append(args))
    with pytest.raises(LocalCliApiError) as missing:
        service.registry_setup(payload)
    assert missing.value.status == 423 and not calls
    _protect(store)
    with pytest.raises(LocalCliApiError):
        service.registry_setup({**payload, "approval_password": "wrong"})
    assert not calls
    result = service.registry_setup({**payload, "approval_password": "synthetic-password"})
    assert result["setup_rolled_back"] is True and result["permissions_granted"] is False
    assert calls == [("/synthetic/codex", receipt)]
    assert service.registry_setup({"operation": "recent"})["setups"] == []
    with pytest.raises(LocalCliApiError) as replay:
        service.registry_setup({**payload, "approval_password": "synthetic-password"})
    assert replay.value.status == 404 and len(calls) == 1
    assert handle not in service._registry_setup_undo._receipts


@pytest.mark.parametrize(
    "change", [{"confirm_host_change": False}, {"setup_name": "other"}, {"selection_digest": "b" * 64}]
)
def test_undo_review_must_match_owned_receipt(tmp_path, monkeypatch, change):
    _, service, _, _, payload = _setup(tmp_path)
    calls = []
    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", lambda *args: calls.append(args))
    with pytest.raises(LocalCliApiError) as mismatch:
        service.registry_setup({**payload, **change})
    assert mismatch.value.status == 409 and not calls
    assert len(service.registry_setup({"operation": "recent"})["setups"]) == 1


def test_receipts_are_daemon_owned_expire_and_never_expose_host_config(tmp_path, monkeypatch):
    store, service, _, handle, _ = _setup(tmp_path)
    recent = service.registry_setup({"operation": "recent"})["setups"]
    assert recent == [
        {
            "rollback_handle": handle,
            "setup_name": "example",
            "kind": "remote",
            "registry_name": "org.example/server",
            "version": "1.0.0",
            "selection_digest": "a" * 64,
        }
    ]
    preview = service.registry_setup({"operation": "rollback-preview", "rollback_handle": handle})
    assert preview["permissions_granted"] is False and preview["host_change_applied"] is False
    assert "private" not in json.dumps(preview) and "file_path" not in preview
    other = LocalCliApiService(store=store)
    with pytest.raises(LocalCliApiError) as foreign:
        other.registry_setup({"operation": "rollback-preview", "rollback_handle": handle})
    assert foreign.value.status == 404
    record = service._registry_setup_undo._receipts[handle]
    monkeypatch.setattr(mcp_registry_undo.time, "monotonic", lambda: record.expires_at + 1)
    assert service.registry_setup({"operation": "recent"})["setups"] == []
    with pytest.raises(LocalCliApiError) as expired:
        service.registry_setup({"operation": "rollback-preview", "rollback_handle": handle})
    assert expired.value.status == 404


def test_config_conflict_keeps_receipt_and_does_not_depend_on_registry(tmp_path, monkeypatch):
    store, service, _, handle, payload = _setup(tmp_path)
    _protect(store)
    monkeypatch.setattr(mcp_registry_undo.shutil, "which", lambda _name: "/synthetic/codex")

    def conflict(*_args):
        raise ValueError("codex_config_changed")

    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", conflict)
    with pytest.raises(LocalCliApiError) as changed:
        service.registry_setup({**payload, "approval_password": "synthetic-password"})
    assert changed.value.status == 409
    assert "kept it unchanged" in str(changed.value)
    assert service.registry_setup({"operation": "recent"})["setups"][0]["rollback_handle"] == handle


def test_receipt_capacity_is_bounded_and_rejects_mismatched_entries(tmp_path):
    _, service, receipt, handle, _ = _setup(tmp_path)
    undo = service._registry_setup_undo
    candidate = undo.preview({"rollback_handle": handle})
    for _ in range(31):
        undo.remember(receipt, candidate)
    with pytest.raises(ValueError, match="receipt_limit"):
        undo.remember(receipt, candidate)
    with pytest.raises(ValueError, match="outcome_uncertain"):
        undo.remember(receipt, {**candidate, "endpoint": "https://other.test/mcp"})
    assert len(undo.recent()) == 32
