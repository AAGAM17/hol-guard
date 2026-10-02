"""A terminal native denial cannot retain an approval invitation."""

from types import SimpleNamespace

from codex_plugin_scanner.guard.cli.commands_hook_native_review import review_native_artifact_hook
from codex_plugin_scanner.guard.cli.commands_hook_native_state import NativeArtifactHookState
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_protect_approval_guidance import _pending_package_payload
from tests.test_guard_runtime_mcp_saved_blocks import _context, _package_artifact


def test_native_package_denial_clears_approval_copy(tmp_path):
    context = _context(tmp_path)
    payload = _pending_package_payload()
    payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"] = "http://127.0.0.1:4455/requests/stale"
    artifact = _package_artifact(context=context, harness="zcode", config_path="config.json")
    state = NativeArtifactHookState(
        action_envelope=None,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        browser_approval_daemon_client=None,
        changed_capabilities=[],
        decision_signals=(),
        decision_v2_payload={},
        event_name="PreToolUse",
        initial_policy_action="require-reapproval",
        package_evaluation=None,
        policy_action="require-reapproval",
        receipt=build_receipt(
            "zcode",
            artifact.artifact_id,
            "a" * 64,
            "require-reapproval",
            "package",
            [],
            "test",
            artifact.name,
            "project",
        ),
        requested_policy_action=None,
        response_payload=payload,
        risk_summary="Package integrity changed.",
        runtime_artifact=artifact,
        runtime_artifact_hash="a" * 64,
        scanner_evidence_payload=[],
        stored_policy_action=None,
    )
    result = review_native_artifact_hook(
        state,
        SimpleNamespace(harness="zcode"),
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        context=context,
        guard_home=context.guard_home,
        managed_install=None,
        payload={},
        store=GuardStore(context.guard_home),
        workspace=context.workspace_dir,
    )
    assert result is None
    assert state.policy_action == "block"
    assert payload["terminal_action"] == "block"
    copy = payload["supply_chain_evaluation"]["user_copy"]
    assert copy["dashboard_url"] is None
    assert "safe, permitted alternative" in copy["next_step"]
    assert "safe, permitted alternative" in copy["harness_message"]
    assert "safe, permitted alternative" in payload["decision_v2_json"]["harness_message"]
