//! The Cursor bridge's daemon lane: a hook no resident answered, posted to
//! a scripted loopback daemon and answered as the client would answer the
//! daemon's body, or left to the client.

use std::io::BufReader;
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::*;
use crate::claude_hook_bridge_fixture::{
    closed_port, read_request, write_private, write_response, GuardHome, Request as DaemonRequest,
};
use crate::cursor_hook_bridge_response::ALLOW_STDOUT;

const TOKEN: &str = "cursor-daemon-token-fixture";
const SHELL: &[u8] =
    br#"{"hook_event_name":"beforeShellExecution","command":"ls","cwd":"/nonexistent-cursor-cwd"}"#;
const MCP: &[u8] = br#"{"hook_event_name":"beforeMCPExecution","tool_name":"fetch","tool_input":{"q":"x"},"cwd":"/nonexistent-cursor-cwd"}"#;
const READ_FILE: &[u8] = br#"{"hook_event_name":"beforeReadFile","file_path":"/tmp/a.txt","cwd":"/nonexistent-cursor-cwd"}"#;
const PRE_TOOL: &[u8] = br#"{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"ls"},"cwd":"/nonexistent-cursor-cwd"}"#;
const PROMPT: &[u8] = br#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#;
const AFTER_SHELL: &[u8] = br#"{"hook_event_name":"afterShellExecution","command":"ls","output":"a","cwd":"/nonexistent-cursor-cwd"}"#;

/// A case label, the hook input, the daemon body, and the expected answer.
type Case<'a> = (&'a str, &'a [u8], &'a str, (String, i32));

/// A Guard home whose daemon state names `host:port`, with the daemon auth
/// token or without it.
fn daemon_home(label: &str, host: &str, port: u16, token: bool) -> GuardHome {
    let home = GuardHome::new(&format!("cursor-daemon-{label}"));
    write_private(
        &home.state_path,
        &json!({"host": host, "port": port}).to_string(),
    );
    if token {
        write_private(&home.home.join("daemon-auth-token"), TOKEN);
    }
    home
}

fn client_for(home: &GuardHome, budget: Duration) -> Client {
    Client {
        guard_home: home.home_text().to_owned(),
        home: Some("/h".to_owned()),
        deadline: Instant::now() + budget,
    }
}

fn serve_once(
    listener: TcpListener,
    status: u16,
    body: String,
) -> JoinHandle<Option<DaemonRequest>> {
    // A hook that never reaches the daemon fails the test instead of
    // leaving this thread waiting.
    listener.set_nonblocking(true).unwrap();
    let give_up = Instant::now() + Duration::from_secs(10);
    std::thread::spawn(move || {
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(_) if Instant::now() < give_up => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return None,
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut writer = stream.try_clone().unwrap();
        let request = read_request(&mut BufReader::new(stream))?;
        write_response(&mut writer, status, &body, true);
        Some(request)
    })
}

/// The bridge's answer for `raw` from a daemon that answers one hook with
/// `status` and `body`, and the request the daemon got.
fn ask(
    label: &str,
    raw: &[u8],
    status: u16,
    body: &str,
) -> (Option<(String, i32)>, DaemonRequest, GuardHome) {
    exchange(label, raw, status, body, respond)
}

/// The bridge's reply to a hook the scripted daemon answers with `body`.
fn ask_reply(label: &str, raw: &[u8], status: u16, body: &str) -> Reply {
    exchange(label, raw, status, body, reply).0
}

fn exchange<T>(
    label: &str,
    raw: &[u8],
    status: u16,
    body: &str,
    bridge: fn(&Client, &[u8]) -> T,
) -> (T, DaemonRequest, GuardHome) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let daemon = serve_once(listener, status, body.to_owned());
    let home = daemon_home(label, "127.0.0.1", port, true);
    let client = client_for(&home, Duration::from_secs(20));
    assert!(prepared_request(&client, raw).is_some(), "{label}");
    let answered = bridge(&client, raw);
    let request = daemon.join().unwrap().expect("the daemon was asked");
    (answered, request, home)
}

fn printed(fields: &[(&str, &str)]) -> String {
    let body = fields
        .iter()
        .map(|(name, value)| format!("{}: {}", json!(name), json!(value)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{body}}}\n")
}

/// The stamped payload as the daemon reads it, without the environment
/// the stamp adds.
fn sent_payload(data: &[u8]) -> Value {
    let mut sent: Value = serde_json::from_slice(data).unwrap();
    sent.as_object_mut()
        .unwrap()
        .remove("guard_execution_environment");
    sent
}

#[test]
fn the_daemon_is_sent_the_clients_request() {
    let (answered, request, home) = ask("request", SHELL, 200, r#"{"policy_action":"allow"}"#);
    assert_eq!(answered, Some((ALLOW_STDOUT.to_owned(), 0)));
    let query = hook_query(home.home_text(), None, Some("/h"));
    assert_eq!(request.target, format!("/v1/hooks/cursor?{query}"));
    assert_eq!(request.header("X-Guard-Token"), Some(TOKEN));
    assert_eq!(request.header("Content-Type"), Some("application/json"));
    let client = client_for(&home, Duration::from_secs(5));
    let expected = prepared_request(&client, SHELL).unwrap();
    assert_eq!(
        sent_payload(&request.body),
        sent_payload(expected.data.as_bytes())
    );
    let sent = sent_payload(&request.body);
    assert_eq!(sent["hook_event_name"], "PreToolUse");
    assert_eq!(sent["cursor_source_hook_event"], "beforeShellExecution");
    assert!(sent.get("hook_env").is_none());
}

#[test]
fn every_installed_event_is_answered_from_the_daemon() {
    let deny = |reason: &str| {
        printed(&[
            ("permission", "deny"),
            ("user_message", reason),
            ("agent_message", reason),
        ])
    };
    let ask_out = |reason: &str| {
        printed(&[
            ("permission", "ask"),
            ("user_message", reason),
            ("agent_message", reason),
        ])
    };
    let cases: [Case<'_>; 9] = [
        (
            "shell-allow",
            SHELL,
            " \n{\"policy_action\": \"allow\"}\n",
            (ALLOW_STDOUT.to_owned(), 0),
        ),
        (
            "mcp-warn",
            MCP,
            r#"{"policy_action":"warn","reason":"noted"}"#,
            (ALLOW_STDOUT.to_owned(), 0),
        ),
        (
            "shell-block",
            SHELL,
            r#"{"policy_action":"block","reason":" Blocked by policy. "}"#,
            (deny("Blocked by policy."), 2),
        ),
        (
            "mcp-sandbox",
            MCP,
            r#"{"policy_action":"sandbox-required"}"#,
            (deny("HOL Guard blocked this Cursor action."), 2),
        ),
        (
            "shell-review",
            SHELL,
            r#"{"policy_action":"review","reason":"Needs a look."}"#,
            (ask_out("Needs a look."), 0),
        ),
        (
            "read-review",
            READ_FILE,
            r#"{"policy_action":"require-reapproval","reason":"Changed."}"#,
            (
                printed(&[("permission", "deny"), ("user_message", "Changed.")]),
                2,
            ),
        ),
        (
            "pretool-review",
            PRE_TOOL,
            r#"{"policy_action":"review","reason":"Needs a look."}"#,
            (deny("Needs a look."), 2),
        ),
        (
            "prompt-review",
            PROMPT,
            r#"{"policy_action":"review","reason":"Prompt held."}"#,
            (ask_out("Prompt held."), 0),
        ),
        (
            "after-shell",
            AFTER_SHELL,
            r#"{"recorded": true}"#,
            ("{}\n".to_owned(), 0),
        ),
    ];
    for (label, raw, body, expected) in cases {
        let (answered, request, _home) = ask(label, raw, 200, body);
        assert_eq!(answered, Some(expected), "{label}");
        assert!(
            request.target.starts_with("/v1/hooks/cursor?guard-home="),
            "{label}"
        );
    }
}

#[test]
fn a_daemon_answer_the_bridge_cannot_reproduce_is_left_to_the_client() {
    let replies: [(&str, u16, &str); 11] = [
        ("server-error", 500, r#"{"policy_action":"allow"}"#),
        ("overload", 429, r#"{"error":"overload"}"#),
        ("busy", 503, r#"{"error":"busy"}"#),
        ("empty", 200, ""),
        ("malformed", 200, "{"),
        ("list", 200, "[]"),
        ("unknown-action", 200, r#"{"policy_action":"maybe"}"#),
        ("no-action", 200, "{}"),
        ("bom", 200, "\u{feff}{\"policy_action\":\"allow\"}"),
        (
            "signed-link",
            200,
            r#"{"policy_action":"review","approval_url":"http://127.0.0.1:4781/approvals/req-1"}"#,
        ),
        (
            "signed-request-link",
            200,
            r#"{"policy_action":"review","approval_requests":[{"approval_url":"http://localhost:4781/approvals/req-2"}]}"#,
        ),
    ];
    for (label, status, body) in replies {
        let (answered, _request, _home) = ask(label, SHELL, status, body);
        assert_eq!(answered, None, "{label}");
    }
    // An observer's body must still be a JSON object.
    let (answered, _request, _home) = ask("after-list", AFTER_SHELL, 200, "[]");
    assert_eq!(answered, None);
}

#[test]
fn a_restrictive_daemon_answer_the_bridge_cannot_render_is_handed_to_the_client() {
    // The client renders these from the bridge's copy instead of posting
    // the hook again, so the daemon reviews it once.
    let handed: [(&str, &str); 3] = [
        (
            "review-link",
            r#"{"policy_action":"review","approval_url":"http://127.0.0.1:4781/approvals/req-1"}"#,
        ),
        (
            "review-request-link",
            r#"{"policy_action":"review","approval_requests":[{"approval_url":"http://localhost:4781/approvals/req-2"}]}"#,
        ),
        (
            "block-link",
            r#"{"policy_action":"block","approval_url":"http://127.0.0.1:4781/approvals/req-3"}"#,
        ),
    ];
    for (label, body) in handed {
        assert_eq!(
            ask_reply(label, SHELL, 200, body),
            Reply::Handoff(body.to_owned()),
            "{label}"
        );
    }
    let oversized = format!(
        r#"{{"policy_action":"review","reason":"{}","approval_url":"http://127.0.0.1:4781/approvals/req-4"}}"#,
        "r".repeat(MAX_HANDOFF_REPLY_BYTES)
    );
    let kept: [(&str, u16, &str); 4] = [
        ("unknown-action", 200, r#"{"policy_action":"maybe"}"#),
        ("server-error", 500, r#"{"policy_action":"review"}"#),
        ("list", 200, "[]"),
        ("oversized", 200, oversized.as_str()),
    ];
    for (label, status, body) in kept {
        assert_eq!(
            ask_reply(label, SHELL, status, body),
            Reply::Client,
            "{label}"
        );
    }
    // An observer always renders, so it is never handed over.
    assert_eq!(handoff(Kind::After, r#"{"policy_action":"block"}"#), None);
}

#[test]
fn a_daemon_the_bridge_cannot_ask_is_left_to_the_client() {
    let no_state = GuardHome::new("cursor-daemon-no-state");
    write_private(&no_state.home.join("daemon-auth-token"), TOKEN);
    let no_token = daemon_home("no-token", "127.0.0.1", closed_port(), false);
    let remote = daemon_home("remote", "10.0.0.1", closed_port(), true);
    let unreachable = daemon_home("unreachable", "127.0.0.1", closed_port(), true);
    let spaced = daemon_home("spaced-token", "127.0.0.1", closed_port(), false);
    write_private(&spaced.home.join("daemon-auth-token"), "tok\n");
    for home in [&no_state, &no_token, &remote, &unreachable, &spaced] {
        let client = client_for(home, Duration::from_secs(20));
        assert_eq!(respond(&client, SHELL), None, "{}", home.home_text());
    }
}

#[test]
fn a_daemon_that_does_not_answer_in_time_leaves_the_client_time() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let daemon = std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let _ = read_request(&mut BufReader::new(stream.try_clone().unwrap()));
        std::thread::sleep(Duration::from_secs(3));
        drop(stream);
    });
    let home = daemon_home("timeout", "127.0.0.1", port, true);
    let client = client_for(&home, Duration::from_secs(2));
    assert_eq!(respond(&client, SHELL), None);
    assert!(Instant::now() < client.deadline);
    daemon.join().unwrap();
}

#[test]
fn hooks_the_client_keeps_never_reach_the_daemon() {
    let home = daemon_home("kept", "127.0.0.1", closed_port(), true);
    let client = client_for(&home, Duration::from_secs(20));
    for raw in [
        &br#"{"hook_event_name":"beforeSubmitPrompt","prompt":"hi"}"#[..],
        br#"{"hook_event_name":"afterFileEdit","file_path":"/tmp/a"}"#,
        br#"{"hook_event_name":"stop"}"#,
        b"[]",
    ] {
        assert_eq!(prepared_request(&client, raw), None);
        assert_eq!(respond(&client, raw), None);
    }
}
