//! Whether the direct lane is ready for a native MCP relay session.
//!
//! The relay asks once, before it reads the host's input or starts the MCP
//! server, and launches the Python proxy instead when the lane is not ready:
//! otherwise every `tools/call` of the session would defer and be refused.
//! The answer is only `ready` or `not_ready` with the lane's defer code. It
//! carries no verdict, no binding state and no key, and it never stands in
//! for a decision: each call is still admitted by `mcp_relay_decide`, which
//! repeats every check made here and refuses whatever it does not decide.

use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::policy_store::PolicySnapshotStore;

pub(crate) const MCP_RELAY_READY_SCHEMA: &str = "guard-mcp-relay-ready-result.v1";
/// The schema of the MCP relay view the publisher binds.
const VIEW_SCHEMA: &str = "guard-mcp-relay-view.v1";
const RUNTIME_SUPERSEDED: &str = "mcp_relay_runtime_superseded";
const WORKSPACE_INVALID: &str = "mcp_relay_workspace_invalid";
const EVIDENCE_UNDRAINED: &str = "mcp_relay_evidence_undrained";
const BINDING_INCOMPLETE: &str = "mcp_relay_binding_incomplete";
const VIEW_MISSING: &str = "mcp_relay_view_missing";
const HARNESS_UNBOUND: &str = "mcp_relay_harness_unbound";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpRelayReadyRequestV1 {
    pub(crate) guard_home: String,
    /// The workspace the session's decisions are admitted under.
    pub(crate) workspace: String,
    pub(crate) harness: String,
}

pub(crate) fn evaluate(
    request: &McpRelayReadyRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let body = match readiness(request, policy_store) {
        Ok(()) => json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": true}),
        Err(reason) => json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": false, "reason": reason}),
    };
    serde_json::to_vec(&body).map_err(|_| "mcp_relay_ready_result_encoding_failed".to_owned())
}

fn readiness(
    request: &McpRelayReadyRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<(), &'static str> {
    if !crate::hook_direct::runtime_current() {
        return Err(RUNTIME_SUPERSEDED);
    }
    let workspace = settled_directory(&request.workspace)?;
    let (_snapshot, binding) = policy_store
        .admit_direct_hook(&workspace)
        .map_err(|defer| defer.code())?;
    if binding.evidence_drain != Some(true) {
        return Err(EVIDENCE_UNDRAINED);
    }
    if binding.exact_action_control_digest.is_none() {
        return Err(BINDING_INCOMPLETE);
    }
    harness_bound(binding.mcp_relay.as_ref(), &request.harness)
}

/// The view binds `harness`. Its contents are checked by each decision.
fn harness_bound(view: Option<&Value>, harness: &str) -> Result<(), &'static str> {
    let view = view.ok_or(VIEW_MISSING)?;
    if view.get("schema").and_then(Value::as_str) != Some(VIEW_SCHEMA) {
        return Err(VIEW_MISSING);
    }
    let bound = view
        .get("harnesses")
        .and_then(Value::as_object)
        .and_then(|harnesses| harnesses.get(harness))
        .is_some_and(Value::is_object);
    bound.then_some(()).ok_or(HARNESS_UNBOUND)
}

/// `Path.resolve(strict=True)` of a directory, as the lane settles it.
fn settled_directory(candidate: &str) -> Result<String, &'static str> {
    let resolved = std::fs::canonicalize(Path::new(candidate)).map_err(|_| WORKSPACE_INVALID)?;
    if !resolved.is_dir() {
        return Err(WORKSPACE_INVALID);
    }
    resolved
        .into_os_string()
        .into_string()
        .map_err(|_| WORKSPACE_INVALID)
}

#[cfg(all(test, unix))]
#[path = "mcp_relay_ready_tests.rs"]
mod tests;
