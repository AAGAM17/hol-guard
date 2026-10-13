use super::{
    allow_answer, evaluate, expanduser, is_pre_tool_event, normalized_workspace, normpath,
    workspace_candidate, HookDirectDefer, HookDirectRequestV1,
};
use crate::policy_store::policy_store_direct_lane::tests::{
    binding, fixture, push, write_current_ack, Fixture,
};
use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use serde_json::{json, Map, Value};
use std::fs;

const HOME: &str = "/home/guard";

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn event_name_follows_the_daemon_rule() {
    assert_eq!(is_pre_tool_event(&object(json!({}))), Ok(true));
    for name in [
        "PreToolUse",
        " pre_tool_use ",
        "pre-tool-call",
        "beforeShellExecution",
    ] {
        assert_eq!(
            is_pre_tool_event(&object(json!({ "hook_event_name": name }))),
            Ok(true),
            "{name}"
        );
    }
    assert_eq!(
        is_pre_tool_event(&object(json!({ "hook_event_name": "PostToolUse" }))),
        Ok(false)
    );
    // A blank or non-string field is skipped; the next named field decides.
    assert_eq!(
        is_pre_tool_event(&object(
            json!({ "event": "  ", "eventName": 3, "hookName": "Stop" })
        )),
        Ok(false)
    );
    assert_eq!(
        is_pre_tool_event(&object(json!({ "event": "pretool", "hookName": "Stop" }))),
        Ok(true)
    );
    assert_eq!(
        is_pre_tool_event(&object(json!({ "event": "prétool" }))),
        Ok(false)
    );
}

#[test]
fn workspace_strings_normalize_like_the_daemon() {
    let normalized = |value: &str| normalized_workspace(Some(value), HOME);
    assert_eq!(
        normalized(" /work/./repo/ "),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/a/../repo"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("~/repo"),
        Ok(Some("/home/guard/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/repo/None"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/repo//None"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(normalized("/None"), Ok(Some("/".to_owned())));
    for absent in ["", "  ", "none", "NULL", "None"] {
        assert_eq!(normalized(absent), Ok(None), "{absent:?}");
    }
    assert_eq!(normalized_workspace(None, HOME), Ok(None));
    for invalid in [
        "relative/repo",
        "~other/repo",
        "//work/repo",
        "/work\u{1f}repo",
    ] {
        assert_eq!(
            normalized(invalid),
            Err(HookDirectDefer::WorkspaceInvalid),
            "{invalid:?}"
        );
    }
    assert_eq!(normpath("///work//repo"), Ok("/work/repo".to_owned()));
    assert_eq!(expanduser("~", HOME), Ok(HOME.to_owned()));
}

#[test]
fn temporary_roots_defer_instead_of_falling_through() {
    assert_eq!(
        normalized_workspace(Some("/tmp"), HOME),
        Err(HookDirectDefer::WorkspaceInvalid)
    );
    let temporary = std::env::temp_dir();
    assert_eq!(
        normalized_workspace(temporary.to_str(), HOME),
        Err(HookDirectDefer::WorkspaceInvalid)
    );
}

#[test]
fn workspace_prefers_exec_command_workdir_then_cwd_then_query() {
    let payload = object(json!({
        "tool_name": " Exec_Command ",
        "tool_input": { "workdir": "/work/action" },
        "cwd": "/work/cwd",
    }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/action".to_owned()))
    );
    let payload = object(json!({ "tool_name": "read_file", "cwd": "/work/cwd" }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/cwd".to_owned()))
    );
    let payload = object(json!({ "cwd": "None" }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/query".to_owned()))
    );
    assert_eq!(
        workspace_candidate(&object(json!({})), None, HOME),
        Ok(None)
    );
    // The daemon rejects a present but unusable workdir instead of skipping it.
    for workdir in [json!(null), json!(""), json!("none"), json!(7)] {
        let payload = object(json!({
            "tool_name": "exec_command",
            "tool_input": { "workdir": workdir },
            "cwd": "/work/cwd",
        }));
        assert_eq!(
            workspace_candidate(&payload, None, HOME),
            Err(HookDirectDefer::WorkspaceInvalid)
        );
    }
}

fn edge(decision: &str, minimum_action: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "guard-hook-edge-result.v2",
        "event_name": "PreToolUse",
        "result": { "decision": decision, "minimum_action": minimum_action },
        "harness_response": {},
    }))
    .unwrap()
}

#[test]
fn only_an_unconditional_allow_is_answered() {
    let answered = allow_answer(&edge("allow", "allow")).unwrap();
    assert_eq!(answered["result"]["decision"], "allow");
    assert_eq!(
        allow_answer(&edge("allow", "warn")),
        Err(HookDirectDefer::NotAllow)
    );
    assert_eq!(
        allow_answer(&edge("block", "block")),
        Err(HookDirectDefer::NotAllow)
    );
    let mut missing_response: Value = serde_json::from_slice(&edge("allow", "allow")).unwrap();
    missing_response
        .as_object_mut()
        .unwrap()
        .remove("harness_response");
    assert_eq!(
        allow_answer(&serde_json::to_vec(&missing_response).unwrap()),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(allow_answer(b"not json"), Err(HookDirectDefer::EdgeFailed));
}

struct Lane {
    fixture: Fixture,
    workspace: String,
}

fn lane(label: &str, extra: Value) -> Lane {
    let fixture = fixture(&format!("hook-direct-{label}"));
    let directory = fixture.root.join("repo");
    fs::create_dir_all(&directory).unwrap();
    let workspace = fs::canonicalize(&directory)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut bound = binding(&fixture, &workspace);
    bound["home_dir"] = json!(HOME);
    bound["harness_postures"] = json!({});
    bound["local_cli_block_rules"] = json!(false);
    for (key, value) in extra.as_object().unwrap() {
        bound[key] = value.clone();
    }
    push(&fixture, Some(bound)).unwrap();
    write_current_ack(&fixture);
    Lane { fixture, workspace }
}

fn run(lane: &Lane, payload: Value) -> Value {
    let request = HookDirectRequestV1 {
        harness: "codex".to_owned(),
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        home_dir: HOME.to_owned(),
        workspace: None,
        deadline_budget_ms: None,
        payload,
    };
    serde_json::from_slice(&evaluate(request, &lane.fixture.store).unwrap()).unwrap()
}

fn read_payload(lane: &Lane) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "read_file",
        "tool_input": { "path": "README.md" },
        "cwd": lane.workspace,
    })
}

fn deferred(result: &Value) -> &str {
    assert_eq!(result["schema"], "guard-hook-direct-result.v1");
    assert_eq!(result["outcome"], "defer", "{result}");
    result["reason"].as_str().unwrap()
}

#[test]
fn request_shapes_the_daemon_must_handle_defer() {
    let lane = lane("shapes", json!({}));
    let mut probe = read_payload(&lane);
    probe["guard_transition_probe"] = json!({});
    assert_eq!(deferred(&run(&lane, probe)), "direct_hook_transition_probe");
    let mut reference = read_payload(&lane);
    reference["guard_payload_ref"] = json!("ref");
    assert_eq!(
        deferred(&run(&lane, reference)),
        "direct_hook_payload_unsupported"
    );
    let mut post = read_payload(&lane);
    post["hook_event_name"] = json!("PostToolUse");
    assert_eq!(deferred(&run(&lane, post)), "direct_hook_event_unsupported");
    let mut environment = read_payload(&lane);
    environment["guard_execution_environment"] = json!("PATH=/bin");
    assert_eq!(
        deferred(&run(&lane, environment)),
        "direct_hook_execution_environment_invalid"
    );
    let mut homeless = read_payload(&lane);
    homeless.as_object_mut().unwrap().remove("cwd");
    assert_eq!(
        deferred(&run(&lane, homeless)),
        "direct_hook_workspace_missing"
    );
    let mut elsewhere = read_payload(&lane);
    elsewhere["cwd"] = json!(lane.fixture.root.to_str().unwrap());
    assert_eq!(
        deferred(&run(&lane, elsewhere)),
        DirectLaneDefer::WorkspaceUnknown.code()
    );
    assert_eq!(
        deferred(&run(&lane, json!(["not", "an", "object"]))),
        "direct_hook_payload_unsupported"
    );
}

#[test]
fn other_harnesses_and_homes_defer() {
    let lane = lane("harness", json!({}));
    let mut request = HookDirectRequestV1 {
        harness: "claude-code".to_owned(),
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        home_dir: HOME.to_owned(),
        workspace: None,
        deadline_budget_ms: None,
        payload: read_payload(&lane),
    };
    let result: Value =
        serde_json::from_slice(&evaluate(request.clone(), &lane.fixture.store).unwrap()).unwrap();
    assert_eq!(deferred(&result), "direct_hook_harness_unsupported");
    request.harness = "codex".to_owned();
    request.home_dir = "/home/other".to_owned();
    let result: Value =
        serde_json::from_slice(&evaluate(request, &lane.fixture.store).unwrap()).unwrap();
    assert_eq!(deferred(&result), "direct_hook_home_mismatch");
}

#[test]
fn daemon_only_state_in_the_binding_defers() {
    let rules = lane("rules", json!({ "local_cli_block_rules": true }));
    assert_eq!(
        deferred(&run(&rules, read_payload(&rules))),
        "direct_hook_local_cli_rules"
    );
    let watch = lane("watch", json!({ "harness_postures": { "codex": "watch" } }));
    assert_eq!(
        deferred(&run(&watch, read_payload(&watch))),
        "direct_hook_recording_only"
    );
    for (label, missing) in [
        ("no-home", "home_dir"),
        ("no-postures", "harness_postures"),
        ("no-rules", "local_cli_block_rules"),
    ] {
        let lane = lane(label, json!({}));
        let mut bound = binding(&lane.fixture, &lane.workspace);
        bound["home_dir"] = json!(HOME);
        bound["harness_postures"] = json!({});
        bound["local_cli_block_rules"] = json!(false);
        bound.as_object_mut().unwrap().remove(missing);
        push(&lane.fixture, Some(bound)).unwrap();
        assert_eq!(
            deferred(&run(&lane, read_payload(&lane))),
            "direct_hook_binding_incomplete",
            "{missing}"
        );
    }
}

#[test]
fn a_block_rule_saved_after_the_publish_defers() {
    let lane = lane("stored-rules", json!({}));
    let store = lane.fixture.root.join("guard.db");
    let connection = rusqlite::Connection::open(&store).unwrap();
    connection
        .execute_batch(
            "create table local_cli_grant (cli_id text primary key, state text not null);
             create table local_cli_command_grant (
                 cli_id text not null, command_id text not null, state text not null
             );
             insert into local_cli_grant values ('cli', 'allowed');
             insert into local_cli_command_grant values ('cli', 'run', 'allow');",
        )
        .unwrap();
    assert_ne!(
        deferred(&run(&lane, read_payload(&lane))),
        "direct_hook_local_cli_rules"
    );
    for statement in [
        "update local_cli_command_grant set state = 'block'",
        "update local_cli_command_grant set state = 'allow'; \
         update local_cli_grant set state = 'blocked'",
    ] {
        connection.execute_batch(statement).unwrap();
        assert_eq!(
            deferred(&run(&lane, read_payload(&lane))),
            "direct_hook_local_cli_rules",
            "{statement}"
        );
    }
    drop(connection);
    // A store the resident cannot read counts as holding rules.
    fs::write(&store, b"not a database").unwrap();
    assert_eq!(
        deferred(&run(&lane, read_payload(&lane))),
        "direct_hook_local_cli_rules"
    );
}

#[test]
fn a_hook_for_an_app_guard_does_not_protect_defers() {
    let lane = lane("unmanaged", json!({}));
    let connection = rusqlite::Connection::open(lane.fixture.root.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table managed_installs (
                 harness text primary key, active integer not null, workspace text,
                 manifest_json text not null, updated_at text not null
             );",
        )
        .unwrap();
    let unmanaged = "direct_hook_harness_unmanaged";
    // No install recorded anywhere: the daemon reviews the hook.
    assert_ne!(run(&lane, read_payload(&lane))["reason"], unmanaged);
    for (statement, expected_unmanaged) in [
        // Only another app is protected, so Codex hooks are leftovers.
        (
            "insert into managed_installs values ('claude-code', 1, null, '{}', 'now')",
            true,
        ),
        (
            "insert into managed_installs values ('codex', 1, null, '{}', 'now')",
            false,
        ),
        (
            "update managed_installs set active = 0 where harness = 'codex'",
            true,
        ),
        // Its own inactive row decides even with no other app protected.
        (
            "update managed_installs set active = 0 where harness = 'claude-code'",
            true,
        ),
    ] {
        connection.execute_batch(statement).unwrap();
        let result = run(&lane, read_payload(&lane));
        assert_eq!(
            result["reason"] == unmanaged,
            expected_unmanaged,
            "{statement}: {result}"
        );
    }
}

#[test]
fn an_edge_verdict_other_than_allow_takes_the_daemon_path() {
    // A sensitive read needs review, so the resident evaluates it and still
    // hands it to the daemon.
    let lane = lane("verdict", json!({}));
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "toolName": "read_file",
        "toolInput": { "file_path": ".env.synthetic" },
        "cwd": lane.workspace,
    });
    assert_eq!(deferred(&run(&lane, payload)), "direct_hook_not_allow");
}
