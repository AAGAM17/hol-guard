//! The Cursor client's own answer for a resident's harness response.
//!
//! This reproduces `_emit_cursor_response` and `_cursor_reason` for the
//! allows and terminal denials a resident answers, byte for byte as the
//! client's `print(json.dumps(response))` writes them.

use guard_command::hook_adapter_value::{OMap, OValue};
use guard_contracts::write_json_string;

use crate::claude_hook_bridge_render::py_strip;

/// `print(json.dumps({"permission": "allow"}))`.
pub(crate) const ALLOW_STDOUT: &str = "{\"permission\": \"allow\"}\n";
/// `_cursor_reason` when the response names no reason and no review link.
const DEFAULT_BLOCK_REASON: &str = "HOL Guard blocked this Cursor action.";
const REVIEW_URL_KEYS: [&str; 3] = ["primary_approval_url", "approval_url", "guardApprovalUrl"];
const REASON_KEYS: [&str; 7] = [
    "reason",
    "stopReason",
    "systemMessage",
    "review_hint",
    "risk_summary",
    "why_now",
    "risk_headline",
];
const DECISION_REASON_KEYS: [&str; 4] = [
    "harness_message",
    "retry_instruction",
    "user_body",
    "user_title",
];

/// `value.strip()` for a non-blank string value.
fn stripped(value: Option<&OValue>) -> Option<&str> {
    let text = py_strip(value?.as_str()?);
    (!text.is_empty()).then_some(text)
}

/// Whether `_cursor_review_url` finds a link, which the client rewrites
/// through Guard's Python before showing it.
fn has_review_url(response: &OMap) -> bool {
    if REVIEW_URL_KEYS
        .iter()
        .any(|key| stripped(response.get(key)).is_some())
    {
        return true;
    }
    response
        .get("approval_requests")
        .and_then(OValue::as_list)
        .is_some_and(|queued| {
            queued.iter().any(|item| {
                item.as_map()
                    .is_some_and(|item| stripped(item.get("approval_url")).is_some())
            })
        })
}

/// `_cursor_reason` for a response without a review link.
fn reason(response: &OMap) -> &str {
    let hook_output = response.get("hookSpecificOutput").and_then(OValue::as_map);
    let decision = response.get("decision_v2_json").and_then(OValue::as_map);
    REASON_KEYS
        .iter()
        .map(|key| response.get(key))
        .chain(hook_output.map(|output| output.get("permissionDecisionReason")))
        .chain(
            DECISION_REASON_KEYS
                .iter()
                .filter_map(|key| decision.map(|decision| decision.get(key))),
        )
        .find_map(stripped)
        .unwrap_or(DEFAULT_BLOCK_REASON)
}

/// `print(json.dumps(response))` for the client's string-valued answer.
fn printed(fields: &[(&str, &str)]) -> String {
    let mut out = vec![b'{'];
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(b", ");
        }
        write_json_string(name, &mut out);
        out.extend_from_slice(b": ");
        write_json_string(value, &mut out);
    }
    out.extend_from_slice(b"}\n");
    String::from_utf8(out).expect("ensure_ascii output is ASCII")
}

/// The client's stdout and exit code for `response`, the harness response
/// the daemon would return for a hook the client names `event`, or `None`
/// when the bridge cannot reproduce the client's answer.
pub(crate) fn rendered(event: &str, response: &OMap) -> Option<(String, i32)> {
    match response.get_str("policy_action")? {
        "allow" | "warn" => Some((ALLOW_STDOUT.to_owned(), 0)),
        "block" | "sandbox-required" => {
            if has_review_url(response) {
                return None;
            }
            let reason = reason(response);
            let mut fields = vec![("permission", "deny"), ("user_message", reason)];
            if py_strip(event).to_lowercase() != "beforereadfile" {
                fields.push(("agent_message", reason));
            }
            Some((printed(&fields), 2))
        }
        _ => None,
    }
}
