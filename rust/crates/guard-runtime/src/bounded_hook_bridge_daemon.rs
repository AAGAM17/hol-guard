//! The loopback daemon transport the native hook bridges share: the
//! private daemon state and auth token `try_daemon_hook` reads, the
//! transport deadline it leaves the Python fallback, and the authenticated
//! `POST` of one hook. Every failure is `None`, which hands the hook to the
//! Python client the bridge was given; nothing here decides a verdict.

use std::path::Path;
use std::time::{Duration, Instant};

use super::{HOOK_DEADLINE, MAX_STATE_BYTES, MAX_TOKEN_BYTES, STATE_FILE, TOKEN_FILE};
use crate::claude_hook_bridge_auth::{private_file_text, LOOPBACK_HOSTS};
use crate::claude_hook_bridge_http::{LoopbackConnection, MAX_DAEMON_RESPONSE_BYTES};
use crate::claude_hook_bridge_url::assert_loopback_http_url;
use crate::pyjson::{self, PyVal};

/// The loopback daemon and the token a hook is sent with.
pub(crate) struct DaemonTarget {
    host: String,
    port: u16,
    token: String,
}

/// `_daemon_hook_endpoint`: the loopback host and port the daemon state
/// names, after the URL check `try_daemon_hook` applies.
fn daemon_endpoint(guard_home: &Path, harness: &str) -> Option<(String, u16)> {
    let path = guard_home.join(STATE_FILE);
    if std::fs::symlink_metadata(&path).ok()?.len() > MAX_STATE_BYTES {
        return None;
    }
    let text = private_file_text(&path, "Guard daemon state").ok()?;
    let parsed = pyjson::parse_mapping_lone_surrogates(&text).ok()?;
    if parsed.mapped {
        return None;
    }
    let host = parsed.value.get("host")?.as_str()?;
    let Some(PyVal::Int(digits)) = parsed.value.get("port") else {
        return None;
    };
    let port = digits.parse::<u16>().ok().filter(|port| *port >= 1)?;
    if !LOOPBACK_HOSTS.contains(&host) {
        return None;
    }
    let rendered_host = if host == "::1" {
        "[::1]".to_owned()
    } else {
        host.to_owned()
    };
    assert_loopback_http_url(&format!("http://{rendered_host}:{port}/v1/hooks/{harness}")).ok()?;
    Some((host.to_owned(), port))
}

/// `load_guard_daemon_auth_token`, limited to tokens urllib sends as is.
fn daemon_auth_token(guard_home: &Path) -> Option<String> {
    let path = guard_home.join(TOKEN_FILE);
    if std::fs::symlink_metadata(&path).ok()?.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let token = private_file_text(&path, "Guard daemon auth token").ok()?;
    let sendable = token
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte));
    (!token.is_empty() && sendable).then_some(token)
}

/// The daemon a `harness` hook is sent to, or `None` when its state or
/// token is missing, unreadable or not one the bridge sends to.
pub(crate) fn daemon_target(guard_home: &Path, harness: &str) -> Option<DaemonTarget> {
    let (host, port) = daemon_endpoint(guard_home, harness)?;
    let token = daemon_auth_token(guard_home)?;
    Some(DaemonTarget { host, port, token })
}

/// The deadline for one daemon request: at most `budget` and half of the
/// `left` the hook had, so the Python fallback keeps the rest. `None` when
/// no time is left for the request.
pub(crate) fn transport_deadline(
    deadline: Instant,
    left: Duration,
    budget: Duration,
) -> Option<Instant> {
    let now = Instant::now();
    let transport = deadline.min(now + (left / 2).min(budget));
    (transport > now).then_some(transport)
}

/// The daemon's `200` body for a hook posted to `path`, as UTF-8 text
/// without a BOM, or `None` for any transport or status failure.
pub(crate) fn post_hook_text(
    target: &DaemonTarget,
    path: &str,
    data: &str,
    deadline: Instant,
) -> Option<String> {
    let mut connection = LoopbackConnection::new(&target.host, target.port);
    let head = connection
        .post(
            path,
            &[
                ("Content-Type", "application/json"),
                ("Connection", "close"),
                ("X-Guard-Token", target.token.as_str()),
            ],
            data.as_bytes(),
            deadline,
        )
        .ok()?;
    if head.status != 200 {
        return None;
    }
    let body = connection
        .read_body(&head, deadline, HOOK_DEADLINE, HOOK_DEADLINE)
        .ok()?;
    if Instant::now() >= deadline || body.len() > MAX_DAEMON_RESPONSE_BYTES {
        return None;
    }
    if body.starts_with(b"\xef\xbb\xbf") {
        return None;
    }
    String::from_utf8(body).ok()
}

/// `post_hook_json`: the daemon's JSON object, or `None` for any failure.
pub(crate) fn post_hook(
    target: &DaemonTarget,
    harness: &str,
    data: &str,
    deadline: Instant,
) -> Option<Vec<(String, PyVal)>> {
    let text = post_hook_text(target, &format!("/v1/hooks/{harness}"), data, deadline)?;
    let parsed = pyjson::parse_mapping_lone_surrogates(&text).ok()?;
    match parsed.value {
        PyVal::Dict(entries) if !parsed.mapped => Some(entries),
        _ => None,
    }
}
