//! Answer a hook in the resident when the daemon would return the edge
//! verdict unchanged.
//!
//! The daemon path derives the workspace, checks daemon state the snapshot
//! does not carry, builds the edge envelope and, for an allow, returns the
//! edge's harness response verbatim. This operation repeats that path for the
//! one shape where the daemon adds nothing: a Codex `PreToolUse` allow outside
//! Watch, in a workspace the current snapshot settled, while the publisher's
//! ACK still holds. Every other request, and every verdict other than allow,
//! defers so the caller takes the daemon path, which is unchanged.

use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{
    GuardExecutionEnvironmentV1, GuardHookEnvelopeV2, GuardHookSourceMetadataV2,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::Path;

pub(crate) const HOOK_DIRECT_FEATURE: &str = "hook-direct-v1";
const HOOK_DIRECT_RESULT_SCHEMA: &str = "guard-hook-direct-result.v1";
const DIRECT_HARNESS: &str = "codex";
const TRANSITION_PROBE_FIELD: &str = "guard_transition_probe";
const EXECUTION_ENVIRONMENT_FIELD: &str = "guard_execution_environment";
const PAYLOAD_REFERENCE_FIELDS: [&str; 2] = ["guard_payload_ref", "guard_source_ref"];
const EVENT_NAME_FIELDS: [&str; 6] = [
    "event",
    "eventName",
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
];
const PRE_TOOL_EVENT_NAMES: [&str; 7] = [
    "pretool",
    "pretooluse",
    "pretoolcall",
    "beforeshellexecution",
    "beforereadfile",
    "beforewritefile",
    "beforemcpexecution",
];
/// The daemon's budget when the caller sends none, and its upper bound.
const DEFAULT_DEADLINE_BUDGET_MS: u64 = 750;
const MAX_DEADLINE_BUDGET_MS: u64 = 9_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookDirectRequestV1 {
    pub(crate) harness: String,
    pub(crate) guard_home: String,
    pub(crate) home_dir: String,
    /// The `workspace` query parameter the daemon path would receive.
    #[serde(default)]
    pub(crate) workspace: Option<String>,
    #[serde(default)]
    pub(crate) deadline_budget_ms: Option<u64>,
    pub(crate) payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookDirectDefer {
    HarnessUnsupported,
    HarnessUnmanaged,
    EventUnsupported,
    PayloadUnsupported,
    TransitionProbe,
    WorkspaceMissing,
    WorkspaceInvalid,
    Lane(DirectLaneDefer),
    BindingIncomplete,
    HomeMismatch,
    LocalCliRules,
    RecordingOnly,
    ExecutionEnvironmentInvalid,
    EdgeFailed,
    NotAllow,
}

impl HookDirectDefer {
    fn code(self) -> &'static str {
        match self {
            Self::HarnessUnsupported => "direct_hook_harness_unsupported",
            Self::HarnessUnmanaged => "direct_hook_harness_unmanaged",
            Self::EventUnsupported => "direct_hook_event_unsupported",
            Self::PayloadUnsupported => "direct_hook_payload_unsupported",
            Self::TransitionProbe => "direct_hook_transition_probe",
            Self::WorkspaceMissing => "direct_hook_workspace_missing",
            Self::WorkspaceInvalid => "direct_hook_workspace_invalid",
            Self::Lane(defer) => defer.code(),
            Self::BindingIncomplete => "direct_hook_binding_incomplete",
            Self::HomeMismatch => "direct_hook_home_mismatch",
            Self::LocalCliRules => "direct_hook_local_cli_rules",
            Self::RecordingOnly => "direct_hook_recording_only",
            Self::ExecutionEnvironmentInvalid => "direct_hook_execution_environment_invalid",
            Self::EdgeFailed => "direct_hook_edge_failed",
            Self::NotAllow => "direct_hook_not_allow",
        }
    }
}

pub(crate) fn evaluate(
    request: HookDirectRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let body = match answer(request, policy_store) {
        Ok(edge) => json!({
            "schema": HOOK_DIRECT_RESULT_SCHEMA,
            "outcome": "answer",
            "edge": edge,
        }),
        Err(defer) => json!({
            "schema": HOOK_DIRECT_RESULT_SCHEMA,
            "outcome": "defer",
            "reason": defer.code(),
        }),
    };
    serde_json::to_vec(&body).map_err(|_| "direct_hook_result_encoding_failed".to_owned())
}

fn answer(
    request: HookDirectRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    if request.harness != DIRECT_HARNESS {
        return Err(HookDirectDefer::HarnessUnsupported);
    }
    let Value::Object(mut payload) = request.payload else {
        return Err(HookDirectDefer::PayloadUnsupported);
    };
    if !is_pre_tool_event(&payload)? {
        return Err(HookDirectDefer::EventUnsupported);
    }
    if payload.contains_key(TRANSITION_PROBE_FIELD) {
        // A probe carries a request identity only the daemon assigns.
        return Err(HookDirectDefer::TransitionProbe);
    }
    if PAYLOAD_REFERENCE_FIELDS
        .iter()
        .any(|field| payload.contains_key(*field))
    {
        return Err(HookDirectDefer::PayloadUnsupported);
    }
    payload.remove("hook_env");
    let execution_environment = match payload.remove(EXECUTION_ENVIRONMENT_FIELD) {
        None | Some(Value::Null) => None,
        Some(value @ Value::Object(_)) => Some(
            serde_json::from_value::<GuardExecutionEnvironmentV1>(value)
                .map_err(|_| HookDirectDefer::ExecutionEnvironmentInvalid)?,
        ),
        Some(_) => return Err(HookDirectDefer::ExecutionEnvironmentInvalid),
    };

    let candidate = workspace_candidate(&payload, request.workspace.as_deref(), &request.home_dir)?
        .ok_or(HookDirectDefer::WorkspaceMissing)?;
    let workspace = settled_directory(&candidate)?;
    let (snapshot, binding) = policy_store
        .admit_direct_hook(&workspace)
        .map_err(HookDirectDefer::Lane)?;

    let home_dir = binding
        .home_dir
        .as_deref()
        .ok_or(HookDirectDefer::BindingIncomplete)?;
    if home_dir != request.home_dir {
        return Err(HookDirectDefer::HomeMismatch);
    }
    match binding.local_cli_block_rules {
        None => return Err(HookDirectDefer::BindingIncomplete),
        // The daemon checks these rules before the edge; only it applies them.
        Some(true) => return Err(HookDirectDefer::LocalCliRules),
        Some(false) => {}
    }
    // The binding is only as fresh as its last publish, while the daemon reads
    // the rules and the managed installs from the store before every hook.
    // A change saved since then lives only in the store, so read it there
    // too. An unreadable store counts as holding rules, as a failed daemon
    // probe does.
    let store =
        crate::local_store_read::hook_store_probe(Path::new(&request.guard_home), DIRECT_HARNESS)
            .map_err(|_| HookDirectDefer::LocalCliRules)?;
    if store.harness_unmanaged {
        // The daemon passes such a hook through and leaves the harness its
        // own permission flow; an allow answer would replace that flow.
        return Err(HookDirectDefer::HarnessUnmanaged);
    }
    if store.local_cli_block_rules {
        return Err(HookDirectDefer::LocalCliRules);
    }
    let postures = binding
        .harness_postures
        .as_ref()
        .ok_or(HookDirectDefer::BindingIncomplete)?;
    // A per-harness override wins over the snapshot mode in both directions.
    let recording_only = match postures.get(DIRECT_HARNESS) {
        Some(posture) => posture == "watch",
        None => snapshot.mode == "observe",
    };
    if recording_only {
        // Watch needs the daemon's would-have-stopped evidence.
        return Err(HookDirectDefer::RecordingOnly);
    }

    let envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: None,
        harness: DIRECT_HARNESS.to_owned(),
        event: "PreToolUse".to_owned(),
        raw_payload: Value::Object(payload),
        deadline_budget_ms: Some(
            request
                .deadline_budget_ms
                .unwrap_or(DEFAULT_DEADLINE_BUDGET_MS)
                .clamp(1, MAX_DEADLINE_BUDGET_MS),
        ),
        policy_generation: snapshot.generation,
        policy_snapshot: json!({
            "generation": snapshot.generation,
            "policy_digest": snapshot.policy_digest,
            "runtime_identity": snapshot.runtime_identity,
        }),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(workspace),
            home_dir: request.home_dir,
            guard_home: request.guard_home,
            source_ref_external_allowed: false,
            execution_environment,
        },
        recording_only: false,
    };
    let edge = crate::edge::evaluate_envelope_with_store(envelope, policy_store)
        .map_err(|_| HookDirectDefer::EdgeFailed)?;
    allow_answer(&edge)
}

/// The edge result to return as is, when it is an allow the daemon would
/// pass through unchanged.
fn allow_answer(edge: &[u8]) -> Result<Value, HookDirectDefer> {
    let parsed: Value = serde_json::from_slice(edge).map_err(|_| HookDirectDefer::EdgeFailed)?;
    if parsed.get("event_name").and_then(Value::as_str) != Some("PreToolUse")
        || !parsed.get("harness_response").is_some_and(Value::is_object)
    {
        return Err(HookDirectDefer::EdgeFailed);
    }
    let result = parsed.get("result");
    let field = |name: &str| {
        result
            .and_then(|result| result.get(name))
            .and_then(Value::as_str)
    };
    if field("decision") != Some("allow") || field("minimum_action") != Some("allow") {
        return Err(HookDirectDefer::NotAllow);
    }
    Ok(parsed)
}

/// The daemon's event name rule: the first non-blank name field decides, and
/// a payload without one is a `PreToolUse`.
fn is_pre_tool_event(payload: &Map<String, Value>) -> Result<bool, HookDirectDefer> {
    for field in EVENT_NAME_FIELDS {
        let Some(value) = payload.get(field).and_then(Value::as_str) else {
            continue;
        };
        let Some(stripped) = python_strip(value)? else {
            continue;
        };
        let compact: String = stripped
            .chars()
            .filter(|character| !matches!(character, '_' | '-'))
            .collect();
        if !compact.is_ascii() {
            return Ok(false);
        }
        return Ok(PRE_TOOL_EVENT_NAMES.contains(&compact.to_ascii_lowercase().as_str()));
    }
    Ok(true)
}

/// The daemon's workspace choice: an `exec_command` workdir, then the payload
/// `cwd`, then the `workspace` query parameter. Where the daemon would skip a
/// temporary root and fall through, this defers instead.
fn workspace_candidate(
    payload: &Map<String, Value>,
    workspace_query: Option<&str>,
    home_dir: &str,
) -> Result<Option<String>, HookDirectDefer> {
    if let Some(workdir) = exec_command_workdir(payload, home_dir)? {
        return Ok(Some(workdir));
    }
    if let Some(cwd) = normalized_workspace(payload.get("cwd").and_then(Value::as_str), home_dir)? {
        return Ok(Some(cwd));
    }
    normalized_workspace(workspace_query, home_dir)
}

fn exec_command_workdir(
    payload: &Map<String, Value>,
    home_dir: &str,
) -> Result<Option<String>, HookDirectDefer> {
    let Some(tool_name) = payload.get("tool_name").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !python_strip(tool_name)?.is_some_and(|name| name.eq_ignore_ascii_case("exec_command")) {
        return Ok(None);
    }
    let Some(workdir) = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .and_then(|tool_input| tool_input.get("workdir"))
    else {
        return Ok(None);
    };
    // A workdir that is present but unusable rejects the daemon's workspace.
    let workdir = workdir.as_str().ok_or(HookDirectDefer::WorkspaceInvalid)?;
    let stripped = python_strip(workdir)?.ok_or(HookDirectDefer::WorkspaceInvalid)?;
    if is_null_sentinel(stripped) {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    let candidate = normpath(&expanduser(stripped, home_dir)?)?;
    if is_temporary_root(&candidate) {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    Ok(Some(candidate))
}

fn normalized_workspace(
    value: Option<&str>,
    home_dir: &str,
) -> Result<Option<String>, HookDirectDefer> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(stripped) = python_strip(value)? else {
        return Ok(None);
    };
    if is_null_sentinel(stripped) {
        return Ok(None);
    }
    let mut candidate = expanduser(stripped, home_dir)?;
    // Callers still send `<dir>/None` as the "no workspace" sentinel. This is
    // `os.path.dirname`, which keeps a head made only of slashes.
    if candidate == "None" {
        return Ok(None);
    }
    if let Some(head) = candidate
        .strip_suffix("None")
        .filter(|head| head.ends_with('/'))
    {
        let trimmed = head.trim_end_matches('/');
        candidate = if trimmed.is_empty() { head } else { trimmed }.to_owned();
    }
    let candidate = normpath(&candidate)?;
    if is_temporary_root(&candidate) {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    Ok(Some(candidate))
}

/// Python's `str.strip()`, or a defer for the separators it strips and Rust
/// does not. `None` when nothing is left.
fn python_strip(value: &str) -> Result<Option<&str>, HookDirectDefer> {
    if value
        .chars()
        .any(|character| ('\u{1c}'..='\u{1f}').contains(&character))
    {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    let stripped = value.trim();
    Ok((!stripped.is_empty()).then_some(stripped))
}

fn is_null_sentinel(value: &str) -> bool {
    value.eq_ignore_ascii_case("none") || value.eq_ignore_ascii_case("null")
}

/// `os.path.expanduser` for the daemon's own home; another user's home defers.
fn expanduser(value: &str, home_dir: &str) -> Result<String, HookDirectDefer> {
    if value == "~" {
        return Ok(home_dir.to_owned());
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return Ok(format!("{}/{rest}", home_dir.trim_end_matches('/')));
    }
    if value.starts_with('~') {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    Ok(value.to_owned())
}

/// Lexical `os.path.normpath` for absolute POSIX paths. Relative paths and the
/// implementation-defined `//` prefix defer.
fn normpath(value: &str) -> Result<String, HookDirectDefer> {
    if !value.starts_with('/') || (value.starts_with("//") && !value.starts_with("///")) {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

/// Whether `candidate` resolves to a temporary directory root the daemon
/// refuses as a workspace. This covers at least the daemon's roots.
fn is_temporary_root(candidate: &str) -> bool {
    let Ok(resolved) = std::fs::canonicalize(candidate) else {
        return false;
    };
    let mut roots = vec![std::env::temp_dir()];
    roots.extend(
        ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"]
            .iter()
            .map(std::path::PathBuf::from),
    );
    if roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .any(|root| root == resolved)
    {
        return true;
    }
    // The per-user Darwin root, `/private/var/folders/<xx>/<id>/T`.
    let components: Vec<_> = resolved.components().collect();
    components.len() == 7
        && resolved.starts_with("/private/var/folders")
        && resolved.file_name().is_some_and(|name| name == "T")
}

/// The realpath the daemon validates, which is what the publisher settled.
fn settled_directory(candidate: &str) -> Result<String, HookDirectDefer> {
    let resolved = std::fs::canonicalize(Path::new(candidate))
        .map_err(|_| HookDirectDefer::WorkspaceInvalid)?;
    if !resolved.is_dir() {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    resolved
        .into_os_string()
        .into_string()
        .map_err(|_| HookDirectDefer::WorkspaceInvalid)
}

#[cfg(all(test, unix))]
#[path = "hook_direct_tests.rs"]
mod tests;
