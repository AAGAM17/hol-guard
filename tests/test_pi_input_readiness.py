"""Prompt readiness through the generated Pi-family input handler."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_input_prepares_cold_workspace_and_retries_failed_setup(tmp_path: Path, harness: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
    )
    cache_start = source.index("  let workspaceReadiness = null;")
    cache_end = source.index("  const approvalContinuationActivity", cache_start)
    input_start = source.index('  pi.on("input", async (event, ctx) => {')
    input_end = source.index('  pi.on("tool_call",', input_start)
    javascript = (
        """
const callbacks = {}, notices = [], events = [];
const GUARD_CONFIG_PATH = '/fixture/settings.json';
const pi = { on(name, callback) { callbacks[name] = callback; } };
let connection = {stateId: 'daemon-a'}, ready = true, setupCalls = 0;
function loadGuardDaemonConnection() { return connection; }
function invalidateInputApprovalResumes() {}
function captureInputApprovalResumeBinding() { return null; }
function approvalBlockedReason(_response, reason) { return reason; }
function scheduleApprovalResume() {}
async function daemonWorkspaceReadiness(cwd) {
  setupCalls++;
  events.push('setup:' + cwd);
  await new Promise(resolve => setTimeout(resolve, 30));
  events.push('prepared:' + cwd);
  return {ready, daemonStateId: connection.stateId, reasonCode: 'native_policy_not_ready'};
}
async function runGuard(payload, cwd) {
  events.push('review:' + cwd + ':' + payload.prompt);
  return payload.prompt === 'protected' ? {decision: 'deny', reason: 'protected'} : {decision: 'allow'};
}
"""
        + source[cache_start:cache_end]
        + source[input_start:input_end]
        + """
const ctx = {cwd: '/fixture', ui: {notify(reason) { notices.push(reason); }}};
async function prompt(text, source = 'interactive') {
  return callbacks.input({text, source}, ctx);
}
const coldPending = prompt('cold');
const inFlightTool = await ensureGuardWorkspaceReady(ctx.cwd, false);
const cold = await coldPending;
const warm = await prompt('warm');
const protectedResult = await prompt('protected');
const extension = await prompt('synthetic', 'extension');
const callsAfterWarm = setupCalls;
connection = {stateId: 'daemon-b'};
ready = false;
const failed = await prompt('failed');
const beforeTool = setupCalls;
const tool = await ensureGuardWorkspaceReady(ctx.cwd, false);
const callsAfterTool = setupCalls;
ready = true;
const retry = await prompt('retry');
ctx.cwd = '/other';
const other = await prompt('other');
console.log(JSON.stringify({cold, inFlightTool, warm, protectedResult, extension, callsAfterWarm, failed,
  beforeTool, tool, callsAfterTool, retry, other, setupCalls, events, notices}));
"""
    )
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the generated input handler")
    completed = subprocess.run(
        [node, "--input-type=module", "-e", javascript],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    result = json.loads(completed.stdout)
    for key in ("cold", "warm", "extension", "retry", "other"):
        assert result[key] == {"action": "continue"}
    for key in ("failed", "protectedResult"):
        assert result[key] == {"action": "handled", "handled": True}
    assert result["callsAfterWarm"] == 1
    assert result["inFlightTool"]["ready"] is True
    assert result["setupCalls"] == 4
    assert result["tool"]["ready"] is False
    assert result["beforeTool"] == result["callsAfterTool"] == 2
    assert result["events"] == [
        "setup:/fixture",
        "prepared:/fixture",
        "review:/fixture:cold",
        "review:/fixture:warm",
        "review:/fixture:protected",
        "setup:/fixture",
        "prepared:/fixture",
        "setup:/fixture",
        "prepared:/fixture",
        "review:/fixture:retry",
        "setup:/other",
        "prepared:/other",
        "review:/other:other",
    ]
    assert result["notices"] == [
        "protected",
        "HOL Guard could not prepare protection for this prompt. "
        "Retry the prompt to reconnect (native_policy_not_ready).",
    ]
