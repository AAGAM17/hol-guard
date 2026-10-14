use super::names_request_link;
use crate::codex_hook_bridge::{route_response, Route};
use crate::codex_hook_response::PRE_TOOL_USE;

/// Daemon answers and what Python's `native_handoff_main` wrote for each,
/// recorded from `codex_daemon_hook_bridge.py`.
const PLAIN_DENIES: [(&str, &str); 6] = [
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"HOL Guard blocked this command. Open http://127.0.0.1:4781/dashboard for details."},"policy_action":"block","decision":"deny","reason_code":"native_command_block","receipt":{"id":"r"}}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"HOL Guard blocked this command. Open http://127.0.0.1:4781/dashboard for details."}}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"blocked \u00e9 \ud800"},"policy_action":"deny","systemMessage":"m"}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"blocked \u00e9 \ud800"},"systemMessage":"m"}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":""},"continue":true}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"},"continue":true}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":7}}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"see /request/abcdefgh"}}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"see /request/abcdefgh"}}"#,
    ),
];

#[test]
fn a_deny_naming_no_approval_renders_as_the_python_handoff_does() {
    for (answer, python) in PLAIN_DENIES {
        assert_eq!(
            route_response(answer, PRE_TOOL_USE),
            Route::Respond(python.to_owned()),
            "{answer}"
        );
    }
}

#[test]
fn a_deny_that_may_name_an_approval_or_a_sandbox_is_handed_off() {
    for answer in [
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Approve at http://127.0.0.1:4781/requests/req_12345678 then retry"}}"#,
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"HTTP://h/REQUEſTS/abcdefgh"}}"#,
        // Any request key, even one Python would reject, stays with Python.
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":"req_12345678"}"#,
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":null}"#,
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":7}"#,
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"policy_action":"sandbox-required"}"#,
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guard_transition_observation":{}}"#,
    ] {
        assert_eq!(
            route_response(answer, PRE_TOOL_USE),
            Route::Handoff(answer.to_owned()),
            "{answer}"
        );
    }
}

#[test]
fn a_request_link_is_found_as_the_case_insensitive_pattern_finds_it() {
    for reason in [
        "x/requests/y",
        "x/REQUESTS/y",
        "x/ReQuEsTs/y",
        "x/reque\u{17f}t\u{17f}/y",
    ] {
        assert!(names_request_link(reason), "{reason}");
    }
    for reason in [
        "",
        "x/request/y",
        "x/requests y",
        "x/requestsy",
        "x\\requests\\y",
    ] {
        assert!(!names_request_link(reason), "{reason}");
    }
}
