//! `McpStdioSession*` resident ops — persistent bounded MCP stdio data plane
//! (RTM-022/023). Owns the live child via
//! `guard_command::mcp_stdio_session::LiveMcpSession` (scrubbed spawn, drain
//! pump, process-group teardown) plus the cross-correlation buffers the Python
//! proxy implements in `_drain_child_messages`/`_buffer_*_response`.
//!
//! Policy authority stays in Python: a `tools/call` (or reverse request) is
//! surfaced to the control plane as `event_kind:"child_request"`; the verdict
//! is relayed back as a `send` op. These ops never decide allow/deny.
//!
//! `#[cfg(unix)]`: the session owner is unix-only.

use guard_contracts::{
    McpStdioSessionCloseRequestV1, McpStdioSessionOpenRequestV1, McpStdioSessionRecvRequestV1,
    McpStdioSessionResultV1, McpStdioSessionSendRequestV1,
};
use serde_json::Value;
#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Child;
#[cfg(unix)]
use std::sync::atomic::AtomicBool;
#[cfg(unix)]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use guard_command::mcp_stdio_session::{LiveMcpSession, SessionEvent};

#[cfg(unix)]
const MAX_SESSIONS: usize = 64;
#[cfg(unix)]
const MAX_SESSION_ID: usize = 128;

/// A live session: the framing owner plus the spawned child for teardown.
#[cfg(unix)]
struct SessionEntry {
    session: LiveMcpSession,
    child: Child,
}

#[cfg(unix)]
type SessionRegistryGuard<'a> =
    std::sync::MutexGuard<'a, HashMap<String, Arc<Mutex<SessionEntry>>>>;

#[cfg(unix)]
static SESSIONS: OnceLock<Mutex<HashMap<String, Arc<Mutex<SessionEntry>>>>> = OnceLock::new();

#[cfg(unix)]
fn sessions() -> Result<SessionRegistryGuard<'static>, String> {
    SESSIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "mcp_session_registry_unavailable".to_owned())
}

/// Look up a session's `Arc` under the registry lock, then drop the guard so a
/// blocking `recv` doesn't serialize ops across other sessions.
#[cfg(unix)]
fn lookup(session_id: &str) -> Result<Arc<Mutex<SessionEntry>>, String> {
    validate_session_id(session_id)?;
    sessions()?
        .get(session_id)
        .cloned()
        .ok_or_else(|| "mcp_session_not_found".to_owned())
}

#[cfg(unix)]
fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty() || session_id.len() > MAX_SESSION_ID {
        return Err("invalid_mcp_session_id".to_owned());
    }
    Ok(())
}

fn encode(result: McpStdioSessionResultV1) -> Result<Vec<u8>, String> {
    crate::encode_response(&result)
}

fn err_result(code: &str) -> Result<Vec<u8>, String> {
    let mut r = McpStdioSessionResultV1::status("error");
    r.payload = Some(Value::String(code.to_owned()));
    encode(r)
}

#[cfg(unix)]
fn child_exit_code(child: &mut Child) -> Result<Option<i32>, String> {
    child
        .try_wait()
        .map(|status| {
            status.map(|status| {
                status
                    .code()
                    .or_else(|| status.signal().map(|signal| -signal))
                    .unwrap_or(-1)
            })
        })
        .map_err(|_| "mcp_child_status_unavailable".to_owned())
}

#[cfg(unix)]
fn exited_result(exit_code: i32) -> Result<Vec<u8>, String> {
    let mut r = McpStdioSessionResultV1::status("exited");
    r.exit_code = Some(exit_code);
    encode(r)
}

/// `mcp_stdio_session_open` — spawn + register a live session.
#[cfg(unix)]
pub(crate) fn session_open(request: &McpStdioSessionOpenRequestV1) -> Result<Vec<u8>, String> {
    if validate_session_id(&request.session_id).is_err() {
        return err_result("invalid_mcp_session_id");
    }
    let cancellation = Arc::new(AtomicBool::new(false));
    let home_dir = request
        .home_dir
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let cwd = request
        .cwd
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let spawned = LiveMcpSession::spawn(
        &request.argv,
        request.extra_env.as_ref(),
        home_dir.as_deref(),
        cwd.as_deref(),
        cancellation,
    );
    let (session, child) = match spawned {
        Ok(v) => v,
        Err(code) => return err_result(&code),
    };
    let mut registry = match sessions() {
        Ok(g) => g,
        Err(code) => {
            let mut s = session;
            let mut c = child;
            s.close(&mut c);
            return err_result(&code);
        }
    };
    if registry.contains_key(&request.session_id) {
        let mut s = session;
        let mut c = child;
        s.close(&mut c);
        return err_result("mcp_session_exists");
    }
    if registry.len() >= MAX_SESSIONS {
        let mut s = session;
        let mut c = child;
        s.close(&mut c);
        return err_result("mcp_session_registry_full");
    }
    registry.insert(
        request.session_id.clone(),
        Arc::new(Mutex::new(SessionEntry { session, child })),
    );
    let mut r = McpStdioSessionResultV1::status("opened");
    r.payload = Some(Value::String(request.session_id.clone()));
    encode(r)
}

/// `mcp_stdio_session_send` — frame a client→child message onto stdin.
#[cfg(unix)]
pub(crate) fn session_send(request: &McpStdioSessionSendRequestV1) -> Result<Vec<u8>, String> {
    let entry = match lookup(&request.session_id) {
        Ok(e) => e,
        Err(code) => return err_result(&code),
    };
    let mut guard = match entry.lock() {
        Ok(g) => g,
        Err(_) => return err_result("mcp_session_unavailable"),
    };
    match guard.session.write(&request.message) {
        Ok(()) => encode(McpStdioSessionResultV1::status("sent")),
        Err(code) => err_result(&code),
    }
}

/// `mcp_stdio_session_recv` — drain the next inbound child frame, optionally
/// correlated to `await_request_id` (out-of-order frames are buffered).
#[cfg(unix)]
pub(crate) fn session_recv(request: &McpStdioSessionRecvRequestV1) -> Result<Vec<u8>, String> {
    let entry = match lookup(&request.session_id) {
        Ok(e) => e,
        Err(code) => return err_result(&code),
    };
    let mut guard = match entry.lock() {
        Ok(g) => g,
        Err(_) => return err_result("mcp_session_unavailable"),
    };
    let entry = &mut *guard;
    if request.poll_only {
        return match child_exit_code(&mut entry.child) {
            Ok(Some(exit_code)) => exited_result(exit_code),
            Ok(None) => encode(McpStdioSessionResultV1::status("running")),
            Err(code) => err_result(&code),
        };
    }
    let timeout = Duration::from_millis(request.timeout_ms.unwrap_or(30_000).min(120_000));

    // Awaited correlation: return a buffered match first.
    if let Some(await_id) = request.await_request_id.as_ref() {
        if let Some(payload) = entry.session.pop_buffered_child_response(await_id) {
            let mut r = McpStdioSessionResultV1::status("event");
            r.event_kind = Some("child_response".to_owned());
            r.payload = Some(payload);
            return encode(r);
        }
    }

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let now = std::time::Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        match entry.session.next_event(remaining) {
            Ok(None) => match child_exit_code(&mut entry.child) {
                Ok(Some(exit_code)) => return exited_result(exit_code),
                Ok(None) => {
                    let mut r = McpStdioSessionResultV1::status("timeout");
                    r.timed_out = Some(true);
                    return encode(r);
                }
                Err(code) => return err_result(&code),
            },
            Err(guard_command::mcp_stdio_session::SessionReadError::Eof) => {
                match child_exit_code(&mut entry.child) {
                    Ok(Some(exit_code)) => return exited_result(exit_code),
                    Ok(None) => return encode(McpStdioSessionResultV1::status("eof")),
                    Err(code) => return err_result(&code),
                }
            }
            Ok(Some(SessionEvent::ChildResponse(payload))) => {
                // If awaiting a specific id and this is not it, buffer + keep
                // draining (out-of-order responses are valid).
                if let Some(await_id) = request.await_request_id.as_ref() {
                    let matches = payload.get("id") == Some(await_id);
                    if !matches {
                        entry.session.buffer_child_response(payload);
                        continue;
                    }
                }
                let mut r = McpStdioSessionResultV1::status("event");
                r.event_kind = Some("child_response".to_owned());
                r.payload = Some(payload);
                return encode(r);
            }
            Ok(Some(SessionEvent::ChildRequest(payload))) => {
                let mut r = McpStdioSessionResultV1::status("event");
                r.event_kind = Some("child_request".to_owned());
                r.payload = Some(payload);
                return encode(r);
            }
            Ok(Some(SessionEvent::ChildNotification(payload))) => {
                let mut r = McpStdioSessionResultV1::status("event");
                r.event_kind = Some("child_notification".to_owned());
                r.payload = Some(payload);
                return encode(r);
            }
        }
    }
}

/// `mcp_stdio_session_close` — cancel + teardown + deregister.
#[cfg(unix)]
pub(crate) fn session_close(request: &McpStdioSessionCloseRequestV1) -> Result<Vec<u8>, String> {
    if validate_session_id(&request.session_id).is_err() {
        return err_result("invalid_mcp_session_id");
    }
    let mut registry = match sessions() {
        Ok(g) => g,
        Err(code) => return err_result(&code),
    };
    match registry.remove(&request.session_id) {
        Some(arc) => {
            if let Ok(mut guard) = arc.lock() {
                let SessionEntry { session, child } = &mut *guard;
                session.close(child);
            }
            encode(McpStdioSessionResultV1::status("closed"))
        }
        None => encode(McpStdioSessionResultV1::status("closed")),
    }
}

// Non-unix: the data plane is unsupported — fail closed with an explicit error
// rather than silently degrading (ADR 0006).
#[cfg(not(unix))]
pub(crate) fn session_open(_r: &McpStdioSessionOpenRequestV1) -> Result<Vec<u8>, String> {
    err_result("native_mcp_stdio_session_unsupported")
}
#[cfg(not(unix))]
pub(crate) fn session_send(_r: &McpStdioSessionSendRequestV1) -> Result<Vec<u8>, String> {
    err_result("native_mcp_stdio_session_unsupported")
}
#[cfg(not(unix))]
pub(crate) fn session_recv(_r: &McpStdioSessionRecvRequestV1) -> Result<Vec<u8>, String> {
    err_result("native_mcp_stdio_session_unsupported")
}
#[cfg(not(unix))]
pub(crate) fn session_close(_r: &McpStdioSessionCloseRequestV1) -> Result<Vec<u8>, String> {
    err_result("native_mcp_stdio_session_unsupported")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex as TestMutex;

    // Serialize tests that touch the shared SESSIONS registry.
    static LOCK: TestMutex<()> = TestMutex::new(());

    fn decode(bytes: Vec<u8>) -> Value {
        serde_json::from_slice(&bytes).expect("result json")
    }

    fn open_req(id: &str, argv: Vec<&str>) -> McpStdioSessionOpenRequestV1 {
        McpStdioSessionOpenRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_OPEN_REQUEST_SCHEMA.to_owned(),
            session_id: id.to_owned(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            extra_env: None,
            home_dir: None,
            cwd: None,
        }
    }

    fn close(id: &str) {
        let _ = session_close(&McpStdioSessionCloseRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.to_owned(),
        });
    }

    #[test]
    fn open_rejects_empty_and_overlong_session_id() {
        let _g = LOCK.lock().unwrap();
        for bad in ["", &"x".repeat(200)] {
            let r = decode(session_open(&open_req(bad, vec!["/bin/cat"])).unwrap());
            assert_eq!(r["status"], "error");
            assert_eq!(r["payload"], "invalid_mcp_session_id");
        }
    }

    #[test]
    fn send_recv_close_unknown_session_is_terminal() {
        let _g = LOCK.lock().unwrap();
        let send = session_send(&McpStdioSessionSendRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: "nope".into(),
            message: json!({"jsonrpc":"2.0","id":1,"result":{}}),
        })
        .unwrap();
        assert_eq!(decode(send)["payload"], "mcp_session_not_found");
    }

    #[test]
    fn duplicate_open_is_rejected() {
        let _g = LOCK.lock().unwrap();
        let id = "dup-sess";
        let _ = session_open(&open_req(id, vec!["/bin/cat"]));
        let second = decode(session_open(&open_req(id, vec!["/bin/cat"])).unwrap());
        assert_eq!(second["status"], "error");
        assert_eq!(second["payload"], "mcp_session_exists");
        close(id);
    }

    #[test]
    fn open_send_recv_close_roundtrip_via_cat_echo() {
        let _g = LOCK.lock().unwrap();
        let id = "echo-sess";
        let opened = decode(session_open(&open_req(id, vec!["/bin/cat"])).unwrap());
        assert_eq!(opened["status"], "opened", "open failed: {opened:?}");

        // cat echoes our framed line back; a response-shaped frame surfaces
        // as a child_response.
        let frame = json!({"jsonrpc":"2.0","id":7,"result":{"ok":true}});
        let sent = decode(
            session_send(&McpStdioSessionSendRequestV1 {
                schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
                session_id: id.into(),
                message: frame.clone(),
            })
            .unwrap(),
        );
        assert_eq!(sent["status"], "sent", "send failed: {sent:?}");

        let recv = decode(
            session_recv(&McpStdioSessionRecvRequestV1 {
                schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
                session_id: id.into(),
                timeout_ms: Some(5000),
                await_request_id: Some(json!(7)),
                poll_only: false,
            })
            .unwrap(),
        );
        assert_eq!(recv["status"], "event", "recv failed: {recv:?}");
        assert_eq!(recv["event_kind"], "child_response");
        assert_eq!(recv["payload"]["id"], 7);

        let closed = decode(
            session_close(&McpStdioSessionCloseRequestV1 {
                schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
                session_id: id.into(),
            })
            .unwrap(),
        );
        assert_eq!(closed["status"], "closed");
    }

    #[test]
    fn recv_times_out_when_child_silent() {
        let _g = LOCK.lock().unwrap();
        let id = "silent-sess";
        // `sleep` emits nothing; recv must return a bounded timeout, not hang.
        let opened = decode(session_open(&open_req(id, vec!["/bin/sleep", "30"])).unwrap());
        assert_eq!(opened["status"], "opened");
        let recv = decode(
            session_recv(&McpStdioSessionRecvRequestV1 {
                schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
                session_id: id.into(),
                timeout_ms: Some(150),
                await_request_id: None,
                poll_only: false,
            })
            .unwrap(),
        );
        assert_eq!(recv["status"], "timeout");
        assert_eq!(recv["timed_out"], true);
        close(id);
    }
}
