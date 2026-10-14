use super::*;
use crate::claim_reuse_then_tests::{case, claim, LOCAL_POLICY, ONE_SHOT};
use crate::store_vectors_support_tests::dump_store;
use serde_json::json;

/// A decide request for `tool` with `arguments` in the relay's wire form.
fn request(tool: &str, arguments: Value) -> McpRelayDecideRequestV1 {
    serde_json::from_value(json!({
        "guard_home": "/guard",
        "hash_workspace": "/work",
        "build": {
            "harness": "codex",
            "server_name": "files",
            "tool_name": tool,
            "source_scope": "project",
            "config_path": "/work/.codex/config.toml",
            "transport": "stdio",
            "server_id": null,
            "server_fingerprint": null,
            "server_identity": null,
            "provider_catalog_hash": null,
            "tool": {"kind": "catalog", "entry": null},
        },
        "arguments": arguments,
        "path": "/usr/bin:/bin",
        "launcher_home": "/home/user",
        "catalog_state": "present",
        "params": {"name": tool},
    }))
    .unwrap()
}

fn mapping(entries: Value) -> Value {
    json!({"format": "mapping", "entries": entries})
}

#[test]
fn a_call_without_a_package_intent_goes_on() {
    for (tool, arguments) in [
        ("bash", mapping(json!([["command", "ls -la"]]))),
        ("bash", mapping(json!([["command", "   "]]))),
        ("Shell", json!({"format": "json", "text": "git status"})),
        ("read", mapping(json!([["path", "package.json"]]))),
        // Only a shell tool's other argument keys are read as commands.
        (
            "search",
            mapping(json!([["query", "npm install left-pad"]])),
        ),
        ("read", json!({"format": "other", "value": null})),
    ] {
        assert_eq!(
            package_gate(&request(tool, arguments.clone())),
            Ok(()),
            "{tool} {arguments}"
        );
    }
}

#[test]
fn a_package_intent_defers() {
    for (tool, arguments) in [
        (
            "bash",
            mapping(json!([["command", "npm install left-pad"]])),
        ),
        (
            "RUN_COMMAND",
            mapping(json!([["argv", ["pip", "install", "requests"]]])),
        ),
        (
            "bash",
            json!({"format": "json", "text": " npm install left-pad "}),
        ),
        // `_command_argument` reads any tool's command keys.
        ("read", mapping(json!([["cmd", "pip install requests"]]))),
        (
            "files",
            mapping(json!([["shellCommand", "  pnpm add left-pad "]])),
        ),
    ] {
        assert_eq!(
            package_gate(&request(tool, arguments.clone())),
            Err(PACKAGE_INTENT),
            "{tool} {arguments}"
        );
    }
}

#[test]
fn a_command_the_two_strips_read_differently_defers() {
    let separated = mapping(json!([["command", "\u{1c}npm install left-pad"]]));
    assert_eq!(
        package_gate(&request("read", separated)),
        Err(PACKAGE_AMBIGUOUS)
    );
    let nested = mapping(json!([["steps", [{"run": "ls\u{1f}"}]]]));
    assert_eq!(
        package_gate(&request("bash", nested)),
        Err(PACKAGE_AMBIGUOUS)
    );
    let tool = mapping(json!([["command", "ls"]]));
    assert_eq!(
        package_gate(&request("\u{1d}bash", tool)),
        Err(PACKAGE_AMBIGUOUS)
    );
    // Separators inside a command are no stripping matter.
    let inner = mapping(json!([["command", "ls\u{1c}-la"]]));
    assert_eq!(package_gate(&request("read", inner)), Ok(()));
}

#[test]
fn only_a_resolved_workspace_reaches_the_parser() {
    let call = || request("bash", mapping(json!([["command", "ls"]])));
    for workspace in ["/", "/work", "/work/a.b", "/work/..a"] {
        let mut request = call();
        request.workspace = Some(workspace.to_owned());
        assert_eq!(package_gate(&request), Ok(()), "{workspace}");
    }
    for workspace in [
        "//work",
        "/work//a",
        "/work/",
        "/work/./a",
        "/work/.",
        "/work/../a",
        "/work/..",
        "work",
        "",
        "/wo\0rk",
    ] {
        let mut request = call();
        request.workspace = Some(workspace.to_owned());
        assert_eq!(
            package_gate(&request),
            Err(WORKSPACE_UNNORMALIZED),
            "{workspace:?}"
        );
    }
}

#[test]
fn a_package_intent_after_the_claim_rolls_it_back() {
    let intent = request(
        "bash",
        mapping(json!([["command", "npm install left-pad"]])),
    );
    for id in [ONE_SHOT, LOCAL_POLICY] {
        let case = case(id);
        let before = dump_store(&case.connection);
        // As `after_claim` maps the fresh resolve's refusal.
        let mut refused = None;
        let answer = claim::<()>(&case, &mut |_| match package_gate(&intent) {
            Ok(()) => Ok(Some(())),
            Err(reason) => {
                refused = Some(reason);
                Ok(None)
            }
        });
        assert_eq!(answer.unwrap(), None, "{id}");
        assert_eq!(refused, Some(PACKAGE_INTENT), "{id}");
        assert_eq!(dump_store(&case.connection), before, "{id}: nothing spent");
        assert!(case.connection.is_autocommit(), "{id}: no open transaction");
    }
}
