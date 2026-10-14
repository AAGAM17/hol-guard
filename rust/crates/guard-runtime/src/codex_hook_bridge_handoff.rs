//! Which daemon answers the native Codex bridge leaves to Python's
//! `native_handoff_main`, which runs `_bridge_output` on them.
//!
//! For a `PreToolUse` deny, `_bridge_output` changes the answer only in two
//! ways: `route_codex_containment` rewrites a sandbox requirement, and
//! `apply_browser_approval_wait` holds a deny that names a pending browser
//! approval. A deny that does neither comes out of `_bridge_output` as
//! `codex_hook_response(response)`, which the native bridge renders
//! identically, so it is answered here without starting Python.

use crate::codex_hook_response::PRE_TOOL_USE;
use crate::pyjson::PyVal;

/// `GUARD_APPROVAL_REQUEST_ID_KEY` in `codex_daemon_hook_resume.py`.
const APPROVAL_REQUEST_ID_KEY: &str = "guardApprovalRequestId";
/// The fixed path segment of `_REQUEST_URL_RE`.
const REQUEST_LINK_SEGMENT: &str = "/requests/";

/// Whether `_bridge_output` may answer differently from the native render.
pub(super) fn needs_python(response: &PyVal, event_name: &str) -> bool {
    if matches!(
        response.get("guard_transition_observation"),
        Some(PyVal::Dict(_))
    ) {
        return true;
    }
    if event_name != PRE_TOOL_USE {
        return false;
    }
    // `route_codex_containment` acts only on this exact policy action.
    if matches!(response.get("policy_action"), Some(PyVal::Str(text)) if text == "sandbox-required")
    {
        return true;
    }
    let output = response.get("hookSpecificOutput");
    // `pending_pretool_approval` compares the decision exactly.
    matches!(
        output.and_then(|output| output.get("permissionDecision")),
        Some(PyVal::Str(text)) if text == "deny"
    ) && may_name_pending_approval(response, output)
}

/// Whether `pending_pretool_approval` can find a request id in a deny. It
/// reads one only from `guardApprovalRequestId` or from a link that
/// `_REQUEST_URL_RE` matches in the reason, and every such link contains
/// `/requests/`. A present key, whatever its value, is left to Python.
fn may_name_pending_approval(response: &PyVal, output: Option<&PyVal>) -> bool {
    if response.get(APPROVAL_REQUEST_ID_KEY).is_some() {
        return true;
    }
    match output.and_then(|output| output.get("permissionDecisionReason")) {
        Some(PyVal::Str(reason)) => names_request_link(reason),
        _ => false,
    }
}

/// Whether `reason` contains `/requests/` as `_REQUEST_URL_RE` matches it
/// under `re.IGNORECASE`, where the long s (`U+017F`) is the only character
/// besides ASCII capitals that folds onto one of its letters.
fn names_request_link(reason: &str) -> bool {
    let folded: String = reason
        .chars()
        .map(|character| match character {
            '\u{017f}' => 's',
            other => other.to_ascii_lowercase(),
        })
        .collect();
    folded.contains(REQUEST_LINK_SEGMENT)
}

#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_handoff_tests.rs"]
mod tests;
