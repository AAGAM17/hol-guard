"""Credential-free stdio regressions for fresh OpenCode MCP approval retries."""

import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, require_approval_decision
from codex_plugin_scanner.guard.approvals import apply_approval_resolution, bulk_allow_read_only_once
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import evaluate_tool_call
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.proxy import OpenCodeMcpGuardProxy
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_bulk_allow_once import PASSWORD, _enable_gate
from tests.test_guard_runtime_mcp_saved_blocks import _child_command, _context, _messages

pytestmark = pytest.mark.usefixtures("bundle_first_cloud")


def _save_rule(store, request, action):
    now = datetime.now(timezone.utc).isoformat()
    grant = require_approval_decision(
        store.guard_home,
        action=action,
        scope="artifact",
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        now=now,
    )
    store.upsert_policy(
        PolicyDecision(
            harness="opencode",
            scope="artifact",
            action=action,
            artifact_id=request["artifact_id"],
            artifact_hash=request["artifact_hash"],
            source="approval-gate",
            reason="synthetic concurrent rule",
        ),
        now,
        approval_gate_grant=grant,
    )


@pytest.mark.parametrize("grant_kind", ["single", "local-once", "bulk"])
@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "older-allow",
        "args",
        "catalog",
        "config",
        "deny-after-claim",
        "corrupt",
        "final-catalog",
        "postclaim-config",
    ],
)
def test_fresh_opencode_reapproval_runs_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
    grant_kind: str,
    mutation: str,
    direct: bool = False,
) -> None:
    install_fake_system_keyring()
    ctx = _context(tmp_path)
    store = GuardStore(ctx.guard_home)
    _enable_gate(store)
    config = GuardConfig(
        guard_home=ctx.guard_home,
        workspace=ctx.workspace_dir,
        security_level="custom",
        risk_actions={"mcp_dangerous_tool": "require-reapproval"},
    )
    marker = tmp_path / "synthetic-write.json"
    command = _child_command(marker)
    command[-1] = (
        command[-1]
        .replace("dangerous_delete", "issue_write")
        .replace("Dangerous delete", "Write a synthetic issue")
        .replace(
            "marker_path.write_text(json.dumps(message.get('params', {})), encoding='utf-8')",
            "with marker_path.open('a', encoding='utf-8') as marker: "
            "marker.write(json.dumps(message.get('params', {})) + '\\n')",
        )
    )
    proxy = OpenCodeMcpGuardProxy(
        server_name="synthetic-no-network",
        command=command,
        context=ctx,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(ctx.workspace_dir / ".opencode" / "opencode.json"),
        current_config_provider=lambda: config,
    )
    monkeypatch.setattr(runtime, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    messages = _messages(tool_name="issue_write", arguments={"target": "synthetic.txt"}, elicitation=False)
    first = proxy.run_session(messages)
    assert first["responses"][2]["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    assert not marker.exists()
    request = store.list_approval_requests(limit=1)[0]
    if mutation == "older-allow":
        _save_rule(store, request, "allow")
    if grant_kind == "single":
        apply_approval_resolution(
            store=store,
            request_id=request["request_id"],
            action="allow",
            scope="artifact",
            workspace=str(ctx.workspace_dir),
            reason="synthetic single approve once",
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
        )
    elif grant_kind == "bulk":
        result = bulk_allow_read_only_once(
            store=store,
            request_ids=[request["request_id"]],
            approval_gate_input=ApprovalGateInput(password=PASSWORD),
        )
        assert result["resolved_count"] == 1, result
    elif grant_kind == "retained":
        _save_rule(store, request, "allow")
    else:
        store.record_local_once_approval(
            request_id=request["request_id"],
            harness="opencode",
            artifact_id=request["artifact_id"],
            artifact_hash=request["artifact_hash"],
            workspace=str(ctx.workspace_dir),
            publisher=None,
            action="allow",
            created_at="2026-10-02T00:00:00+00:00",
            expires_at="2099-10-02T00:00:00+00:00",
        )
    if mutation == "args":
        messages[2]["params"]["arguments"] = {"target": "different.txt"}
    elif mutation == "catalog":
        proxy.command[-1] = proxy.command[-1].replace("Write a synthetic issue", "Changed tool definition")
    elif mutation == "config":
        proxy._current_config_provider = lambda: replace(config, risk_actions={"mcp_dangerous_tool": "block"})
    elif mutation == "corrupt":
        with sqlite3.connect(ctx.guard_home / "guard.db") as connection:
            for table in ("policy_decisions", "guard_local_once_approvals"):
                connection.execute(f"update {table} set artifact_hash = artifact_hash || '-tampered'")
    elif mutation in {"deny-after-claim", "final-catalog", "postclaim-config"}:
        real_claim = store.claim_approval_reuse_decisions
        mutation_applied = []

        def mutate_after_claim(decisions, **kwargs):
            claimed = real_claim(decisions, **kwargs)
            if claimed and mutation == "deny-after-claim":
                _save_rule(store, request, "block")
            elif claimed and mutation == "postclaim-config":
                proxy._current_config_provider = lambda: replace(config, risk_actions={"mcp_dangerous_tool": "block"})
            elif claimed:
                assert proxy._child_output_queue is not None
                proxy._child_output_queue.put(
                    runtime._ChildOutputFrame(
                        line=json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {}})
                        + "\n"
                    )
                )
            if claimed:
                mutation_applied.append(True)
            return claimed

        monkeypatch.setattr(store, "claim_approval_reuse_decisions", mutate_after_claim)
    if direct:

        def fresh_authority():
            authority = proxy._resolve_tool_call_authority(
                tool_name="issue_write", arguments=messages[2]["params"]["arguments"], config=config
            )
            return config, authority.artifact, authority.artifact_hash, messages[2]["params"]["arguments"]

        _, artifact, artifact_hash, arguments = fresh_authority()
        decision = evaluate_tool_call(
            store=store,
            config=config,
            artifact=artifact,
            artifact_hash=artifact_hash,
            arguments=arguments,
            fresh_authority_provider=fresh_authority,
        )
        assert decision.action == "allow", decision
        assert decision.post_claim_revalidated
        assert (
            evaluate_tool_call(
                store=store,
                config=config,
                artifact=artifact,
                artifact_hash=artifact_hash,
                arguments=arguments,
            ).action
            != "allow"
        )
        assert not marker.exists()
        return
    second = proxy.run_session(messages)
    if mutation not in {"none", "older-allow"} or grant_kind == "retained":
        assert not marker.exists(), second["events"][2]
        assert "error" in second["responses"][2]
        if mutation in {"deny-after-claim", "final-catalog", "postclaim-config"}:
            assert mutation_applied == [True]
        if mutation == "final-catalog":
            evidence = second["events"][2]["scanner_evidence"][-1]
            assert evidence["phase"] == "immediately_before_forward"
        return
    assert marker.exists(), second["events"][2].get("scanner_evidence")
    assert second["responses"][2]["result"]["content"][0]["text"] == "forwarded"
    marker_before = marker.read_bytes()
    messages[2]["id"] = 4
    third = proxy.run_session(messages)
    assert "error" in third["responses"][2]
    assert marker.read_bytes() == marker_before
    assert len(marker.read_text().splitlines()) == 1


def test_retained_rule_cannot_satisfy_fresh_approval(tmp_path, monkeypatch, install_fake_system_keyring):
    test_fresh_opencode_reapproval_runs_exactly_once(
        tmp_path, monkeypatch, install_fake_system_keyring, "retained", "none"
    )


@pytest.mark.parametrize("grant_kind", ["single", "local-once", "bulk"])
@pytest.mark.parametrize("mutation", ["none", "older-allow"])
def test_direct_postclaim_revalidation(tmp_path, monkeypatch, install_fake_system_keyring, grant_kind, mutation):
    test_fresh_opencode_reapproval_runs_exactly_once(
        tmp_path, monkeypatch, install_fake_system_keyring, grant_kind, mutation, direct=True
    )
