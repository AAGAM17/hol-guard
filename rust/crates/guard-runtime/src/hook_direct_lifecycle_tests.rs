use super::{deferred, drain, lane, run, run_as, HOME};
use serde_json::{json, Value};

fn lifecycle(name: &str) -> Value {
    json!({ "hook_event_name": name, "session_id": "synthetic" })
}

#[test]
fn a_claude_code_stop_is_answered_with_the_daemon_constant() {
    let lane = lane("lifecycle-stop", json!({}));
    let result = run_as(&lane, "claude-code", Some(HOME), lifecycle(" Stop "));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(
        result["edge"],
        json!({
            "harness_response": {
                "continue": true,
                "policy_action": "allow",
                "reason_code": "native_hook_event_unavailable",
                "hookSpecificOutput": { "hookEventName": "Stop" },
            }
        })
    );
    // The daemon records nothing for such a hook, and neither does the lane.
    assert_eq!(drain(&lane, None)["records"], json!([]));
}

#[test]
fn a_decision_harness_lifecycle_hook_gets_the_decision_constant() {
    let lane = lane("lifecycle-decision", json!({}));
    for harness in ["hermes", "openclaw"] {
        let result = run_as(&lane, harness, Some(HOME), lifecycle("SessionStart"));
        assert_eq!(
            result["edge"]["harness_response"],
            json!({
                "decision": "allow",
                "policy_action": "allow",
                "reason_code": "native_hook_event_unavailable",
            }),
            "{harness}: {result}"
        );
    }
    let kimi = run_as(&lane, "kimi", Some(HOME), lifecycle("SessionStart"));
    assert_eq!(
        kimi["edge"]["harness_response"]["hookSpecificOutput"]["hookEventName"],
        "SessionStart"
    );
}

#[test]
fn hooks_the_daemon_handles_itself_defer() {
    let lane = lane("lifecycle-daemon", json!({}));
    let unsupported = "direct_hook_event_unsupported";
    for name in [
        "PermissionRequest",
        "permission_request_v2",
        "copilotPermissionRequest",
        "beforeSubmitPrompt",
        "Session Start",
        "Stop\u{e9}",
    ] {
        assert_eq!(
            deferred(&run(&lane, lifecycle(name))),
            unsupported,
            "{name}"
        );
    }
    let long = "x".repeat(65);
    assert_eq!(deferred(&run(&lane, lifecycle(&long))), unsupported);
    // Claude Code shows Guard's pending approval on a notification.
    assert_eq!(
        deferred(&run_as(
            &lane,
            "claude-code",
            Some(HOME),
            lifecycle("Notification")
        )),
        unsupported
    );
    assert_eq!(run(&lane, lifecycle("Notification"))["outcome"], "answer");
    // The Cursor client renders its own lifecycle hooks.
    assert_eq!(
        deferred(&run_as(&lane, "cursor", Some(HOME), lifecycle("stop"))),
        unsupported
    );
    let mut probe = lifecycle("Stop");
    probe["guard_transition_probe"] = json!({});
    assert_eq!(deferred(&run(&lane, probe)), "direct_hook_transition_probe");
    let mut reference = lifecycle("Stop");
    reference["guard_source_ref"] = json!("ref");
    assert_eq!(
        deferred(&run(&lane, reference)),
        "direct_hook_payload_unsupported"
    );
}

#[test]
fn a_lifecycle_hook_for_an_app_guard_does_not_protect_defers() {
    let lane = lane("lifecycle-unmanaged", json!({}));
    let connection = rusqlite::Connection::open(lane.fixture.root.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table managed_installs (
                 harness text primary key, active integer not null, workspace text,
                 manifest_json text not null, updated_at text not null
             );
             insert into managed_installs values ('codex', 1, null, '{}', 'now');",
        )
        .unwrap();
    assert_eq!(run(&lane, lifecycle("Stop"))["outcome"], "answer");
    assert_eq!(
        deferred(&run_as(&lane, "claude-code", Some(HOME), lifecycle("Stop"))),
        "direct_hook_harness_unmanaged"
    );
}
