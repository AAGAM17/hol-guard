//! Persistent bounded MCP stdio session owner (RTM-022/023 data plane).
//!
//! Byte-parity port of the live transport in
//! `src/codex_plugin_scanner/guard/proxy/runtime_mcp.py` `serve()`: spawn a
//! scrubbed child, pump its stdout on a dedicated drain thread, and expose a
//! bidirectional JSON-RPC mediation surface to the resident.
//!
//! Unlike the one-shot `RpcSession` used by the catalog probe, this session is
//! retained across resident ops (`open` → `send`/`recv` → `close`) and adds the
//! correlation layer `runtime_mcp.py` implements per-id: response-key
//! normalization, buffered cross-correlated queues, request/notification
//! classification, and timeout-driven quarantine. Policy authority stays in
//! Python: each `tools/call` frame is surfaced to the control plane as an
//! opaque authority request and the verdict is applied here — this module
//! never decides allow/deny itself.
//!
//! `#[cfg(unix)]`: launch attributes and process-group teardown are unix-only,
//! matching `local_mcp_stdio.rs`.

use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::local_mcp_stdio::{drain_stream, is_rpc_message, kill_process_group, probe_env};

/// Output/queue caps live in `local_mcp_stdio` (`MCP_PROBE_OUTPUT_LIMIT`,
/// `_MAX_QUEUE`) via `drain_stream`/`pop_json_message` — the shared pump owns
/// byte and queue bounds.
///
/// Maximum cross-correlated buffered responses held per response key.
const MAX_BUFFERED_PER_KEY: usize = 8;
/// Default per-message wait when the caller does not supply one.
const DEFAULT_READ_TIMEOUT_MS: u64 = 500;

// ---------------------------------------------------------------------------
// JSON-RPC frame classification (`runtime_mcp.py` helpers).
// ---------------------------------------------------------------------------

/// `_is_request` — `{"method", "id"}` both present.
fn is_request(message: &Value) -> bool {
    match message {
        Value::Object(m) => m.contains_key("method") && m.contains_key("id"),
        _ => false,
    }
}

/// `_is_response` — an `id` and no `method`.
fn is_response(message: &Value) -> bool {
    match message {
        Value::Object(m) => m.contains_key("id") && !m.contains_key("method"),
        _ => false,
    }
}

/// `_is_notification` — a `method` and no `id`.
fn is_notification(message: &Value) -> bool {
    match message {
        Value::Object(m) => m.contains_key("method") && !m.contains_key("id"),
        _ => false,
    }
}

/// `_response_key` — `json.dumps(value, sort_keys=True, separators=(",",":"))`
/// canonical key used to correlate a response to its request id. `None` →
/// `None` (a non-object/id-less message is not correlated).
fn response_key(value: Option<&Value>) -> Option<String> {
    let value = value?;
    // serde_json serializes map keys in insertion order; canonicalize to match
    // Python's sort_keys compact dump for correlation keys.
    fn canon(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
                for (k, v) in m {
                    sorted.insert(k.clone(), canon(v));
                }
                // Rebuild preserving sort order via a Map keyed insert.
                let mut out = serde_json::Map::new();
                for (k, v) in sorted {
                    out.insert(k, v);
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&canon(value)).ok()
}

/// The direction a drained frame is bound, and the message to surface.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionEvent {
    /// A child→client response correlated to a client request id.
    ChildResponse(Value),
    /// A child→client request that must be proxied upstream (reverse request).
    ChildRequest(Value),
    /// A child→client notification to forward verbatim.
    ChildNotification(Value),
}

/// `LiveMcpSession` — a spawned, scrubbed MCP child whose stdio is owned by
/// the native runtime. The caller (resident op) drives `write`/`next_event`
/// while Python supplies policy verdicts out-of-band.
pub struct LiveMcpSession {
    stdin: std::process::ChildStdin,
    inbox: mpsc::Receiver<Value>,
    cancellation: Arc<AtomicBool>,
    _drain: Option<thread::JoinHandle<()>>,
    /// Buffered child responses keyed by `response_key(id)` that arrived while
    /// servicing a different request (out-of-order / interleaved).
    buffered_child: ResponseBuffers,
    /// Buffered client→server responses keyed by `response_key(id)` that
    /// arrived while awaiting a different correlation.
    buffered_client: ResponseBuffers,
    closed: bool,
}

/// Cross-correlated response buffer (`runtime_mcp.py`
/// `_buffered_child_responses`/`_buffered_client_responses`): a FIFO queue of
/// payloads per `response_key(id)`, capped per key.
#[derive(Default)]
struct ResponseBuffers {
    map: BTreeMap<String, Vec<Value>>,
}

impl ResponseBuffers {
    fn buffer(&mut self, payload: Value) {
        if let Some(key) = response_key(payload.get("id")) {
            let bucket = self.map.entry(key).or_default();
            if bucket.len() < MAX_BUFFERED_PER_KEY {
                bucket.push(payload);
            }
        }
    }

    fn pop(&mut self, request_id: &Value) -> Option<Value> {
        let key = response_key(Some(request_id))?;
        let pending = self.map.get_mut(&key)?;
        if pending.is_empty() {
            self.map.remove(&key);
            return None;
        }
        let payload = pending.remove(0);
        if pending.is_empty() {
            self.map.remove(&key);
        }
        Some(payload)
    }
}

impl LiveMcpSession {
    /// Spawn the child with the probe's scrubbed environment and a live
    /// drain pump. `argv` must be a resolved launch vector (the caller resolves
    /// via `resolve_launch_argv`/shim logic); empty/NUL-bearing argv fails.
    pub fn spawn(
        argv: &[String],
        extra_env: Option<&BTreeMap<String, String>>,
        home_dir: Option<&Path>,
        cancellation: Arc<AtomicBool>,
    ) -> Result<(Self, Child), String> {
        if argv.is_empty() || argv.iter().any(|p| p.is_empty() || p.contains('\0')) {
            return Err("invalid_launch".to_owned());
        }
        if cancellation.load(Ordering::Acquire) {
            return Err("cancelled".to_owned());
        }
        let tmp = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let env = probe_env(tmp.to_str().unwrap_or("/tmp"), extra_env, home_dir);
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .current_dir(&tmp)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd
            .process_group(0)
            .spawn()
            .map_err(|_| "transport_failed".to_owned())?;
        let stdin = child.stdin.take().ok_or("transport_failed")?;
        let stdout = child.stdout.take().ok_or("transport_failed")?;
        let (tx, rx) = mpsc::channel::<Value>();
        let cancel_tx = Arc::clone(&cancellation);
        let drain = thread::spawn(move || {
            let _ = &cancel_tx;
            drain_stream(stdout, tx);
        });
        Ok((
            LiveMcpSession {
                stdin,
                inbox: rx,
                cancellation,
                _drain: Some(drain),
                buffered_child: ResponseBuffers::default(),
                buffered_client: ResponseBuffers::default(),
                closed: false,
            },
            child,
        ))
    }

    /// Write a raw JSON-RPC frame (client→child), newline-framed. Bounded by
    /// the caller's serialized size checks upstream.
    pub fn write(&mut self, message: &Value) -> Result<(), String> {
        if self.closed {
            return Err("session_closed".to_owned());
        }
        let mut framed = serde_json::to_vec(message).unwrap_or_default();
        framed.push(b'\n');
        self.stdin
            .write_all(&framed)
            .and_then(|_| self.stdin.flush())
            .map_err(|_| "child_write_failed".to_owned())
    }

    /// Drain the next inbound child frame within `timeout`, classifying it.
    /// Non-RPC noise is skipped by the drain pump; here we distinguish
    /// response / reverse-request / notification so the control plane applies
    /// the right routing. `None` = timeout or pump EOF.
    pub fn next_event(&mut self, timeout: Duration) -> Option<SessionEvent> {
        let deadline = Instant::now() + timeout.max(Duration::from_millis(DEFAULT_READ_TIMEOUT_MS));
        loop {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            match self.inbox.recv_timeout(deadline - now) {
                Ok(msg) => {
                    if !is_rpc_message(&msg) {
                        continue;
                    }
                    if is_response(&msg) {
                        return Some(SessionEvent::ChildResponse(msg));
                    }
                    if is_request(&msg) {
                        return Some(SessionEvent::ChildRequest(msg));
                    }
                    if is_notification(&msg) {
                        return Some(SessionEvent::ChildNotification(msg));
                    }

                    // Unclassified object: treat as a notification-shaped frame
                    // and let the control plane decide.
                    return Some(SessionEvent::ChildNotification(msg));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => return None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// `_buffer_child_response` — stash a child response under its correlation
    /// key while servicing an interleaved request.
    pub fn buffer_child_response(&mut self, payload: Value) {
        self.buffered_child.buffer(payload);
    }

    /// `_pop_buffered_child_response` — remove the oldest buffered response for
    /// `request_id`'s correlation key.
    pub fn pop_buffered_child_response(&mut self, request_id: &Value) -> Option<Value> {
        self.buffered_child.pop(request_id)
    }

    /// `_buffer_client_response` — stash a client→server response while a
    /// different correlation is in flight.
    pub fn buffer_client_response(&mut self, payload: Value) {
        self.buffered_client.buffer(payload);
    }

    /// `_pop_buffered_client_response`.
    pub fn pop_buffered_client_response(&mut self, request_id: &Value) -> Option<Value> {
        self.buffered_client.pop(request_id)
    }

    /// Signal cooperative cancellation to the drain pump.
    pub fn cancel(&self) {
        self.cancellation.store(true, Ordering::Release);
    }

    /// `stop_child` — kill the process group then reap the child. Idempotent.
    pub fn close(&mut self, child: &mut Child) {
        if self.closed {
            return;
        }
        self.cancel();
        let pid = child.id() as i32;
        if pid > 0 {
            kill_process_group(pid);
        }
        let _ = child.kill();
        let _ = child.wait();
        self.closed = true;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_key_canonicalizes_sort_order() {
        // `{"a":1,"b":2}` id must correlate regardless of source key order.
        let a = json!({"a":1,"b":2});
        let b = json!({"b":2,"a":1});
        assert_eq!(response_key(Some(&a)), response_key(Some(&b)));
        assert_eq!(response_key(Some(&a)).unwrap(), "{\"a\":1,\"b\":2}");
        assert_eq!(response_key(Some(&json!(7))).unwrap(), "7");
        assert_eq!(response_key(Some(&json!("x"))).unwrap(), "\"x\"");
        assert_eq!(response_key(Some(&Value::Null)), Some("null".into()));
        assert_eq!(response_key(None), None);
    }

    #[test]
    fn frame_classification() {
        assert!(is_request(&json!({"method":"tools/call","id":1})));
        assert!(!is_request(&json!({"id":1,"result":{}})));
        assert!(is_response(&json!({"id":1,"result":{}})));
        assert!(!is_response(&json!({"method":"tools/call","id":1})));
        assert!(is_notification(
            &json!({"method":"notifications/cancelled"})
        ));
        assert!(!is_notification(&json!({"id":1})));
    }

    #[test]
    fn buffered_response_fifo_and_key() {
        let mut buf = ResponseBuffers::default();
        let r1 = json!({"id":1,"result":{"a":1}});
        let r2 = json!({"id":1,"result":{"a":2}});
        buf.buffer(r1.clone());
        buf.buffer(r2.clone());
        // FIFO within a correlation key.
        assert_eq!(buf.pop(&json!(1)), Some(r1));
        assert_eq!(buf.pop(&json!(1)), Some(r2));
        assert_eq!(buf.pop(&json!(1)), None);
        // An id-less message carries no correlation key and buffers nothing.
        buf.buffer(json!({"result":{}}));
        assert_eq!(buf.pop(&json!(2)), None);
        // Per-key isolation.
        buf.buffer(json!({"id":9,"result":{}}));
        assert_eq!(buf.pop(&json!(3)), None);
        assert_eq!(buf.pop(&json!(9)), Some(json!({"id":9,"result":{}})));
    }
}
