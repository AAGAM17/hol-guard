//! Lifecycle hooks the resident answers as the daemon does.
//!
//! The edge reviews tool, prompt and permission hooks only. For any other
//! event, such as Claude Code's `Stop`, Kimi's `SessionStart` or Cline's
//! `TaskStart`, the daemon asks its resident, receives the edge's refusal,
//! and returns `fail_closed_response`: a constant that carries no verdict
//! and depends only on the harness and the event name. This module returns
//! that same constant without the daemon round trip. It never answers a
//! hook the daemon handles itself or answers with a deny.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::workspace::python_strip;
use super::{
    HookDirectDefer, CLAUDE_CODE, CURSOR, EVENT_NAME_FIELDS, GROK, PAYLOAD_REFERENCE_FIELDS,
    TRANSITION_PROBE_FIELD,
};
use crate::policy_store::PolicySnapshotStore;

/// The daemon's `reason_code` when the edge does not review an event.
const UNAVAILABLE_REASON_CODE: &str = "native_hook_event_unavailable";
/// `_DECISION_HARNESSES` among the harnesses the resident answers.
const DECISION_HARNESSES: [&str; 2] = ["hermes", "openclaw"];
/// Events `fail_closed_response` answers with a deny, or the daemon handles
/// itself. Claude Code shows Guard's pending approval on a permission
/// `Notification`, so the daemon keeps every Claude Code notification.
const DAEMON_EVENTS: [&str; 3] = [
    "permissionrequest",
    "permissionrequestv2",
    "copilotpermissionrequest",
];
const NOTIFICATION: &str = "notification";
/// A longer or unusual name is left to the daemon.
const MAX_EVENT_NAME_BYTES: usize = 64;

/// `runtime_hook_event_name` for an event `direct_event` does not review:
/// the first non-blank event field, stripped.
fn event_name(payload: &Map<String, Value>) -> Result<&str, HookDirectDefer> {
    for field in EVENT_NAME_FIELDS {
        let Some(value) = payload.get(field).and_then(Value::as_str) else {
            continue;
        };
        let stripped = python_strip(value).map_err(|_| HookDirectDefer::EventUnsupported)?;
        if let Some(name) = stripped {
            return Ok(name);
        }
    }
    Err(HookDirectDefer::EventUnsupported)
}

/// The harness response `fail_closed_response` returns for `event`.
fn constant_response(harness: &str, event: &str) -> Value {
    // `fail_closed_response` answers every Grok lifecycle hook with `{}`.
    if harness == GROK {
        return json!({});
    }
    if DECISION_HARNESSES.contains(&harness) {
        return json!({
            "decision": "allow",
            "policy_action": "allow",
            "reason_code": UNAVAILABLE_REASON_CODE,
        });
    }
    json!({
        "continue": true,
        "policy_action": "allow",
        "reason_code": UNAVAILABLE_REASON_CODE,
        "hookSpecificOutput": { "hookEventName": event },
    })
}

/// The answer for a hook whose event the edge does not review, when the
/// daemon would return its constant for it.
pub(super) fn answer(
    harness: &str,
    guard_home: &str,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    // The Cursor client renders lifecycle hooks through Guard's Python.
    if harness == CURSOR {
        return Err(HookDirectDefer::EventUnsupported);
    }
    let event = event_name(payload)?;
    if event.len() > MAX_EVENT_NAME_BYTES
        || !event
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
    {
        return Err(HookDirectDefer::EventUnsupported);
    }
    let compact = event.replace(['_', '-'], "").to_ascii_lowercase();
    if DAEMON_EVENTS.contains(&compact.as_str())
        || compact.starts_with("before")
        || (harness == CLAUDE_CODE && compact == NOTIFICATION)
    {
        return Err(HookDirectDefer::EventUnsupported);
    }
    if payload.contains_key(TRANSITION_PROBE_FIELD) {
        return Err(HookDirectDefer::TransitionProbe);
    }
    if PAYLOAD_REFERENCE_FIELDS
        .iter()
        .any(|field| payload.contains_key(*field))
    {
        return Err(HookDirectDefer::PayloadUnsupported);
    }
    // A daemon that has published no direct-lane binding answers itself.
    policy_store
        .direct_lane_home_dir()
        .ok_or(HookDirectDefer::BindingIncomplete)?;
    // The daemon passes a hook through for a harness Guard does not manage.
    let store = crate::local_store_read::hook_store_probe(Path::new(guard_home), harness)
        .map_err(|_| HookDirectDefer::HarnessUnmanaged)?;
    if store.harness_unmanaged {
        return Err(HookDirectDefer::HarnessUnmanaged);
    }
    Ok(json!({ "harness_response": constant_response(harness, event) }))
}
