//! Native answers for Cursor's managed hook client.
//!
//! Guard installs Cursor's hooks as `guard-runtime cursor-hook-bridge
//! <python> -I <script> --cursor-hook-event <event>`. For a `PreToolUse`
//! hook (Cursor's `preToolUse`, `beforeShellExecution`,
//! `beforeMCPExecution` and `beforeReadFile`) or a prompt the daemon reviews
//! as a `UserPromptSubmit` that a live resident allows, denies or pauses for
//! review, the bridge prints the client's own answer without starting
//! Python; a review whose loopback link the client may sign with Guard's
//! Python is the client's to answer. For Cursor's `afterShellExecution` and
//! `afterMCPExecution` observers, which the daemon records as a `PostToolUse`
//! and the client always answers with `{}`, the bridge prints `{}` once the
//! resident has answered (and so queued the record). The client's other
//! hooks, every other verdict and anything the bridge cannot reproduce
//! exactly run the Python client unchanged, with the hook it already read
//! and the time it already spent.
//!
//! When no live resident answers, the bridge posts the request to the
//! loopback daemon itself, over the transport, auth token and deadlines the
//! bounded bridge uses, and renders the daemon's answer the same way. A
//! daemon that is unreachable, refuses the hook, runs out of time or
//! answers anything the bridge cannot reproduce leaves the hook to the
//! Python client, which asks the daemon again on its own terms.
//!
//! The client also sends an `after*` observer proof and approval binding in
//! `hook_env`; the daemon drops `hook_env` before it reviews a hook, so only
//! the client's CLI fallback reads them, and the bridge reads no key.
//!
//! The bridge reproduces the client's steps up to its daemon request:
//! `_read_hook_input`, `json.loads`, `_prepare_cursor_hook_payload`,
//! `_workspace_from_cursor_input`, `stamp_hook_input_text` and the query
//! `_daemon_hook_result` sends. The resident answers the request the
//! daemon would have forwarded, so a verdict is never decided here.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_command::hook_adapter_prepare::{cursor_client_event, first_truthy, prepare_payload};
use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue};

use crate::bounded_hook_bridge::{
    daemon_target, post_hook_text, read_hook_input, run_python, transport_deadline, write_stdout,
    Input, DAEMON_BUDGET, MAX_HOOK_INPUT_BYTES, PROMPT_DAEMON_BUDGET,
};
use crate::claude_hook_bridge_http::remaining;
use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_bridge_direct::{direct_answer, CURSOR};
use crate::codex_hook_response::{POST_TOOL_USE, PRE_TOOL_USE};
use crate::cursor_hook_bridge_response::rendered;
use crate::cursor_hook_bridge_script::read_ported_script;
use crate::hook_env_stamp::{current_environment, stamp_hook_input_text, Stamp};

pub(crate) const BRIDGE_COMMAND: &str = "cursor-hook-bridge";
pub(crate) const BRIDGE_FEATURE: &str = "cursor-hook-bridge-v1";
const EVENT_FLAG: &str = "--cursor-hook-event";
/// `_NATIVE_DAEMON_REPLY_FLAG`: hands the client a daemon reply the bridge
/// received and could not render, so the client never asks again.
const DAEMON_REPLY_FLAG: &str = "--cursor-native-daemon-reply";
/// `_NATIVE_DAEMON_REPLY_ACTIONS`: the replies the client takes over.
const HANDOFF_ACTIONS: [&str; 4] = ["review", "require-reapproval", "sandbox-required", "block"];
/// A longer reply is not put on the client's command line, which Windows
/// caps at 32,767 characters; the client then asks the daemon again.
const MAX_HANDOFF_REPLY_BYTES: usize = 16 * 1024;
/// The harness name of the client's daemon route, `/v1/hooks/cursor`.
const DAEMON_HARNESS: &str = "cursor";
const PROJECT_DIR_ENV: &str = "CURSOR_PROJECT_DIR";
const AFTER_EVENTS: [&str; 2] = ["aftershellexecution", "aftermcpexecution"];
/// The names `_prepare_cursor_hook_payload` gives the `after*` observers.
const PREPARED_AFTER_EVENTS: [&str; 2] = ["afterShellExecution", "afterMCPExecution"];
/// The client's answer to an `after*` observer the daemon reviewed.
const AFTER_STDOUT: &str = "{}\n";
/// The event the bridge names a prompt for the resident.
const USER_PROMPT_SUBMIT: &str = "UserPromptSubmit";
/// The keys the daemon reads a hook's event from before `hook_event_name`.
const EARLIER_EVENT_KEYS: [&str; 2] = ["event", "eventName"];
/// The prompt names the daemon reviews as a `UserPromptSubmit`, compacted.
const PROMPT_EVENTS: [&str; 3] = ["prompt", "userpromptsubmit", "userpromptsubmitted"];
const UNAVAILABLE_STDOUT: &str = "{\"permission\": \"deny\", \"user_message\": \"HOL Guard could not complete the native hook decision safely.\"}\n";

/// `_cursor_unavailable_response` for a hook whose input could not be read
/// before the deadline: its stdout and exit code.
fn unavailable_output(event: &str) -> (&'static str, i32) {
    let compact: String = py_strip(event)
        .to_lowercase()
        .chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .collect();
    if AFTER_EVENTS.contains(&compact.as_str()) {
        return ("{}\n", 0);
    }
    (UNAVAILABLE_STDOUT, 2)
}

fn unavailable(event: &str) -> i32 {
    let (stdout, code) = unavailable_output(event);
    write_stdout(stdout);
    code
}

/// `urllib.parse.urlencode` for one value: unreserved bytes kept, a space
/// as `+`, everything else percent-encoded.
fn quote_plus(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// The query `_daemon_hook_result` sends.
pub(crate) fn hook_query(guard_home: &str, workspace: Option<&str>, home: Option<&str>) -> String {
    let mut fields = vec![("guard-home", guard_home)];
    fields.extend(workspace.map(|workspace| ("workspace", workspace)));
    fields.extend(home.map(|home| ("home", home)));
    fields
        .iter()
        .map(|(name, value)| format!("{name}={}", quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A stripped, non-blank candidate that `Path(candidate).is_dir()`.
fn directory_candidate(value: &str) -> Option<String> {
    let candidate = py_strip(value);
    (!candidate.is_empty() && Path::new(candidate).is_dir()).then(|| candidate.to_owned())
}

/// `_workspace_from_cursor_input`. `Err` when `CURSOR_PROJECT_DIR` is not
/// text the bridge can read as Python does.
pub(crate) fn workspace(
    payload: &OMap,
    project_dir: Option<std::ffi::OsString>,
) -> Result<Option<String>, ()> {
    if let Some(project_dir) = project_dir {
        let project_dir = project_dir.into_string().map_err(|_| ())?;
        if let Some(candidate) = directory_candidate(&project_dir) {
            return Ok(Some(candidate));
        }
    }
    let roots = first_truthy(
        payload.get("workspace_roots"),
        payload.get("workspaceRoots"),
    );
    if let Some(roots) = roots.and_then(OValue::as_list) {
        for root in roots {
            if let Some(candidate) = root.as_str().and_then(directory_candidate) {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(payload.get_str("cwd").and_then(directory_candidate))
}

/// What the bridge needs of the ported client.
struct Client {
    guard_home: String,
    home: Option<String>,
    deadline: Instant,
}

/// Which of the client's answers a request gets.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Kind {
    /// Rendered by `_emit_cursor_response`.
    PreToolUse,
    /// A prompt the daemon reviews as a `UserPromptSubmit`, rendered by
    /// `_emit_cursor_response` as a tool hook is.
    Prompt,
    /// An `after*` observer: `{}` once the daemon reviewed it.
    After,
}

/// A hook the bridge can send as the client would.
#[derive(Debug, PartialEq)]
struct Request {
    /// The stamped payload.
    data: String,
    query: String,
    /// The event the client names its answer for.
    event: String,
    kind: Kind,
}

/// The client's `hook_event_name.strip().lower()` check for an observer,
/// for ASCII names; any other name runs the client.
fn client_after_event(event: &str) -> bool {
    let stripped = py_strip(event);
    stripped.is_ascii() && AFTER_EVENTS.contains(&stripped.to_ascii_lowercase().as_str())
}

/// Whether a prepared hook name is one the daemon reviews as a
/// `UserPromptSubmit`: stripped, without `_` and `-`, and lowercased.
fn prompt_event(name: &str) -> bool {
    let compact: String = py_strip(name)
        .chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .collect();
    compact.is_ascii() && PROMPT_EVENTS.contains(&compact.to_ascii_lowercase().as_str())
}

/// The request the client would send for a `PreToolUse` hook, a prompt or
/// an `after*` observer, or `None` to run the client.
fn prepared_request(client: &Client, raw: &[u8]) -> Option<Request> {
    if raw.len() > MAX_HOOK_INPUT_BYTES {
        return None;
    }
    let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let text = std::str::from_utf8(body).ok()?;
    if py_strip(text).is_empty() {
        return None;
    }
    // `json.loads` skips only JSON whitespace around the document.
    let document = text.trim_matches([' ', '\t', '\n', '\r']);
    let OValue::Map(payload) = parse_python_json(document).ok()? else {
        return None;
    };
    // Cursor's `after*` hooks prepare as themselves; one is sent only where
    // the client would also answer it as an observer.
    let event = cursor_client_event(&payload)?;
    let prepared = prepare_payload("cursor", &payload, None).ok()?;
    let kind = match prepared.get_str("hook_event_name") {
        Some(PRE_TOOL_USE) => Kind::PreToolUse,
        // The daemon reads `event` and `eventName` before this name.
        Some(name)
            if prompt_event(name)
                && !EARLIER_EVENT_KEYS
                    .iter()
                    .any(|key| prepared.contains_key(key)) =>
        {
            Kind::Prompt
        }
        Some(name) if PREPARED_AFTER_EVENTS.contains(&name) && client_after_event(&event) => {
            Kind::After
        }
        _ => return None,
    };
    let workspace = workspace(&prepared, std::env::var_os(PROJECT_DIR_ENV)).ok()?;
    let serialized = OValue::Map(prepared).compact_json();
    let Stamp::Text(data) = stamp_hook_input_text(&serialized, &current_environment()) else {
        return None;
    };
    let query = hook_query(
        &client.guard_home,
        workspace.as_deref(),
        client.home.as_deref(),
    );
    Some(Request {
        data,
        query,
        event,
        kind,
    })
}

/// The client's answer for a resident's harness response: `json.loads` of
/// the body the daemon would return, rendered by `_emit_cursor_response`
/// with `guard_home` the client's `GUARD_HOME`; for an observer, `{}` once
/// `_daemon_hook_result` accepts the body as a JSON object, whatever it
/// holds.
fn answer(kind: Kind, event: &str, response: &str, guard_home: &Path) -> Option<(String, i32)> {
    let body = match kind {
        Kind::PreToolUse | Kind::Prompt => response,
        Kind::After => py_strip(response),
    };
    let OValue::Map(response) = parse_python_json(body).ok()? else {
        return None;
    };
    match kind {
        Kind::PreToolUse | Kind::Prompt => rendered(event, &response, guard_home),
        Kind::After => Some((AFTER_STDOUT.to_owned(), 0)),
    }
}

/// The body `_daemon_hook_result` accepts from the daemon for `request`,
/// stripped as the client strips it, or `None` when the daemon cannot be
/// asked or does not answer within the bridge's share of the deadline. The
/// client also sends `hook_env`, which the daemon drops unread.
fn daemon_answer(client: &Client, request: &Request) -> Option<String> {
    let left = remaining(client.deadline);
    let target = daemon_target(Path::new(&client.guard_home), DAEMON_HARNESS)?;
    let budget = match request.kind {
        Kind::Prompt => PROMPT_DAEMON_BUDGET,
        Kind::PreToolUse | Kind::After => DAEMON_BUDGET,
    };
    let deadline = transport_deadline(client.deadline, left, budget)?;
    let path = format!("/v1/hooks/{DAEMON_HARNESS}?{}", request.query);
    let body = post_hook_text(&target, &path, &request.data, deadline)?;
    Some(py_strip(&body).to_owned())
}

/// What the bridge does with one hook.
#[derive(Debug, PartialEq)]
enum Reply {
    /// The client's stdout and exit code.
    Answered(String, i32),
    /// A daemon reply the client renders without posting the hook again.
    Handoff(String),
    /// Run the client.
    Client,
}

/// The reply the client takes over once the bridge posted the hook and
/// cannot render the daemon's answer, so the daemon never reviews the hook
/// twice: a JSON object whose `policy_action` restricts the action, which
/// is what `_native_daemon_reply_from_argv` accepts. An observer always
/// renders, so it is never handed over.
fn handoff(kind: Kind, body: &str) -> Option<String> {
    if kind == Kind::After || body.len() > MAX_HANDOFF_REPLY_BYTES {
        return None;
    }
    let OValue::Map(response) = parse_python_json(body).ok()? else {
        return None;
    };
    let action = response.get_str("policy_action")?;
    HANDOFF_ACTIONS.contains(&action).then(|| body.to_owned())
}

/// The client's stdout and exit code for the hook, answered by a live
/// resident or else by the daemon, or `None` to run the client.
#[cfg(test)]
fn respond(client: &Client, raw: &[u8]) -> Option<(String, i32)> {
    match reply(client, raw) {
        Reply::Answered(stdout, code) => Some((stdout, code)),
        Reply::Handoff(_) | Reply::Client => None,
    }
}

/// The bridge's reply to the hook: a live resident's answer, else the
/// daemon's. A resident answer the bridge cannot render runs the client
/// without the daemon; a daemon answer it cannot render is handed to the
/// client when the client can take it over.
fn reply(client: &Client, raw: &[u8]) -> Reply {
    let Some(request) = prepared_request(client, raw) else {
        return Reply::Client;
    };
    let event_name = match request.kind {
        Kind::PreToolUse => PRE_TOOL_USE,
        Kind::Prompt => USER_PROMPT_SUBMIT,
        Kind::After => POST_TOOL_USE,
    };
    let guard_home = Path::new(&client.guard_home);
    let resident = direct_answer(
        CURSOR,
        guard_home,
        &request.query,
        event_name,
        &request.data,
        client.deadline,
    );
    if let Some(answered) = resident {
        return answer(request.kind, &request.event, &answered, guard_home)
            .map_or(Reply::Client, |(stdout, code)| {
                Reply::Answered(stdout, code)
            });
    }
    let Some(body) = daemon_answer(client, &request) else {
        return Reply::Client;
    };
    match answer(request.kind, &request.event, &body, guard_home) {
        Some((stdout, code)) => Reply::Answered(stdout, code),
        None => handoff(request.kind, &body).map_or(Reply::Client, Reply::Handoff),
    }
}

/// The ported client the installer's argv runs, or `None` for any other
/// argv or script.
fn client(python_argv: &[String], started: Instant) -> Option<Client> {
    let [_, isolated, script, flag, _event] = python_argv else {
        return None;
    };
    if isolated != "-I" || flag != EVENT_FLAG {
        return None;
    }
    let constants = read_ported_script(Path::new(script))?;
    let budget = Duration::from_secs(constants.timeout_seconds);
    Some(Client {
        guard_home: constants.guard_home,
        home: constants.home,
        deadline: started.checked_add(budget)?,
    })
}

/// Answer one Cursor hook. `python_argv` is the client's command.
pub(crate) fn run(python_argv: &[String]) -> i32 {
    let started = Instant::now();
    let event = python_argv
        .iter()
        .position(|argument| argument == EVENT_FLAG)
        .and_then(|index| python_argv.get(index + 1))
        .map_or("", |event| py_strip(event));
    let Some(client) = client(python_argv, started) else {
        return run_python(python_argv, None, started.elapsed(), false)
            .unwrap_or_else(|| unavailable(event));
    };
    let raw = match read_hook_input(client.deadline) {
        Input::Read(raw) => raw,
        Input::Failed if Instant::now() >= client.deadline => return unavailable(event),
        // The client reads an empty hook and answers its unparseable input.
        Input::Failed => Vec::new(),
    };
    match reply(&client, &raw) {
        Reply::Answered(stdout, code) => {
            write_stdout(&stdout);
            return code;
        }
        Reply::Handoff(body) => {
            let mut argv = python_argv.to_vec();
            argv.push(DAEMON_REPLY_FLAG.to_owned());
            argv.push(body);
            // The daemon already has this hook: a client that cannot start
            // must not fall back to one that posts it again.
            return run_python(&argv, Some(&raw), started.elapsed(), false)
                .unwrap_or_else(|| unavailable(event));
        }
        Reply::Client => {}
    }
    run_python(python_argv, Some(&raw), started.elapsed(), false)
        .unwrap_or_else(|| unavailable(event))
}

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_daemon_tests.rs"]
mod daemon_tests;
