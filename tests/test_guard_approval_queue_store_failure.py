"""A quarantined store must not drop the deny-path approval_requests contract.

When ``queue_blocked_approvals`` raises (e.g. ``sqlite3.OperationalError`` from a
quarantined SQLite store), ``resolve_from_local_queue`` must still emit an
explicit ``approval_requests`` key so downstream consumers never hit ``KeyError``
and the action stays blocked.
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_support_hook_payload as payload_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore


def _detection() -> HarnessDetection:
    artifact = GuardArtifact(
        artifact_id="art-1",
        name="tool",
        harness="claude-code",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="",
    )
    return HarnessDetection(
        harness="claude-code",
        installed=True,
        command_available=True,
        config_paths=("",),
        artifacts=(artifact,),
    )


def test_store_failure_still_emits_approval_requests_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    args = argparse.Namespace(harness="claude-code", json=True)

    def failing_queue(**_kwargs):
        raise sqlite3.OperationalError("database is quarantined")

    monkeypatch.setattr(payload_module, "queue_blocked_approvals", failing_queue)
    monkeypatch.setattr(
        payload_module, "schedule_guard_daemon_ensure", lambda *_a, **_k: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(payload_module, "_managed_install_for", lambda *_a, **_k: None)
    monkeypatch.setattr(
        payload_module,
        "approval_prompt_flow",
        lambda *_a, **_k: {"tier": "local"},
    )
    # Force the local-queue path (daemon client unavailable).
    monkeypatch.setattr(
        payload_module,
        "load_guard_surface_daemon_client",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("no daemon")),
    )

    resolver = payload_module._headless_approval_resolver(
        args=args, context=context, store=store, config=config
    )
    result = resolver(
        _detection(),
        {"artifacts": [{"artifact_id": "art-1", "policy_action": "require-reapproval"}]},
    )

    assert "approval_requests" in result
    assert result["approval_requests"] == []
    assert result["approval_queue_unavailable"] == "OperationalError"
