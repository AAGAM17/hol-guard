//! Fail-closed launch identity API for non-Unix targets.
//!
//! The full launch identity implementation relies on POSIX filesystem metadata
//! and executable semantics. Keep its API available to cross-platform callers,
//! but do not claim runtime identities can be verified on other targets.

use std::collections::HashSet;
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

// Mirror the Unix implementation's contract shape on non-Unix targets: every
// key a cross-platform consumer indexes must be present, but the identity
// stays non-reusable (`reuse_nonce`) and `unsupported_platform`, so saved
// approvals still fail closed and nothing claims a verified launch.

// `reuse_nonce` must never be reusable, so it must stay unique even when the
// OS RNG is unavailable. Hash entropy plus process id, a per-process counter,
// and wall-clock nanos so two identities — including across processes where
// the pid and counter may repeat — can never share a nonce a saved approval
// could match. This is uniqueness, not a cryptographic guarantee if getrandom
// fails; a constant zero nonce would let an attacker pin a stable identity.
// Every call site produces a 16-byte nonce.
fn token_hex() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut entropy = [0u8; 16];
    let _ = getrandom::fill(&mut entropy);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(entropy);
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    hasher.update(nanos.to_be_bytes());
    hex::encode(&hasher.finalize()[..16])
}

// `launch_identity.rs::launch_argv_digest` — sha256 over canonical JSON argv.
// Digests borrowed `&Value` material; no intermediate String/Vec copies.
fn launch_argv_digest(material: &Value) -> String {
    let mut bytes = Vec::with_capacity(64);
    if guard_contracts::write_canonical_json(material, &mut bytes).is_err() {
        bytes.clear();
    }
    hex::encode(Sha256::digest(&bytes))
}

// `launch_identity.rs::unreusable_executable_identity` — non-Unix executables
// are never verified, so reuse_nonce keeps the identity fail-closed.
fn unsupported_executable_identity(command: &Value) -> Value {
    let mut map = Map::new();
    map.insert(
        "command".to_string(),
        command
            .as_str()
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert("path".to_string(), Value::Null);
    map.insert(
        "status".to_string(),
        Value::String("unsupported_platform".to_string()),
    );
    map.insert("reuse_nonce".to_string(), Value::String(token_hex()));
    Value::Object(map)
}

// `launch_identity.rs::unproven_runtime_entrypoint` — non-Unix entrypoints are
// never bound, so the entrypoint stays unproven with a fresh reuse_nonce.
fn unsupported_entrypoint_identity() -> Value {
    let mut map = Map::new();
    map.insert(
        "kind".to_string(),
        Value::String("unknown-launch".to_string()),
    );
    map.insert(
        "reason".to_string(),
        Value::String("unsupported_platform".to_string()),
    );
    map.insert(
        "selector_sha256".to_string(),
        Value::String(launch_argv_digest(&Value::Array(Vec::new()))),
    );
    map.insert("status".to_string(), Value::String("unproven".to_string()));
    map.insert("reuse_nonce".to_string(), Value::String(token_hex()));
    Value::Object(map)
}

fn launch_cwd_text(cwd: Option<&Path>) -> String {
    cwd.map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn build_runtime_executable_identity(
    command: &Value,
    search_path: Option<&str>,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    _require_executable: bool,
) -> Value {
    let _ = (search_path, home_dir);
    let mut identity = unsupported_executable_identity(command);
    if let Some(obj) = identity.as_object_mut() {
        obj.insert(
            "launch_cwd".to_string(),
            Value::String(launch_cwd_text(cwd)),
        );
    }
    identity
}

pub fn runtime_launch_identity_is_reusable(_identity: &Value) -> bool {
    false
}

pub fn resolved_runtime_launch_executable(_identity: &Value) -> Option<String> {
    None
}

pub fn resolved_runtime_launch_argv(_identity: &Value, _args: &[String]) -> Option<Vec<String>> {
    None
}

#[allow(clippy::too_many_arguments)]
pub fn runtime_launch_identity_matches(
    _expected_identity: &Value,
    _command: &Value,
    _args: &[Value],
    _structured_command: bool,
    _direct_executable: bool,
    _search_path: Option<&str>,
    _cwd: Option<&Path>,
    _launch_env: Option<&Value>,
) -> bool {
    false
}

#[allow(clippy::too_many_arguments)]
pub fn build_runtime_launch_identity(
    command: &Value,
    args: &[Value],
    _structured_command: bool,
    _direct_executable: bool,
    search_path: Option<&str>,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    _launch_env: Option<&Value>,
) -> Value {
    // Digest the real argv vector so `argv_sha256` is present and content-bound,
    // even though the identity remains non-reusable on unsupported platforms.
    // One clone per element is the minimum Value ownership requires; borrow
    // the command/args strings and build the canonical array in place.
    let mut argv_values: Vec<Value> = Vec::with_capacity(1 + args.len());
    if let Some(cmd) = command.as_str() {
        if !cmd.trim().is_empty() {
            argv_values.push(Value::String(cmd.to_string()));
        }
    }
    for a in args {
        if let Some(s) = a.as_str() {
            argv_values.push(Value::String(s.to_string()));
        }
    }
    let argv_material = Value::Array(argv_values);
    json!({
        "argv_sha256": launch_argv_digest(&argv_material),
        "entrypoint": unsupported_entrypoint_identity(),
        "executable": build_runtime_executable_identity(
            command, search_path, cwd, home_dir, true,
        ),
        "launch_cwd": launch_cwd_text(cwd),
    })
}

fn python_str_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn python_str_strip(value: &str) -> &str {
    value.trim_matches(python_str_is_space)
}

pub fn package_advisory_ids(package: &Map<String, Value>) -> Vec<String> {
    let mut advisory_ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add_id = |value: Option<&Value>| {
        if let Some(text) = value.and_then(Value::as_str) {
            let trimmed = python_str_strip(text);
            if !trimmed.is_empty() && !seen.contains(trimmed) {
                seen.insert(trimmed.to_string());
                advisory_ids.push(trimmed.to_string());
            }
        }
    };
    for key in [
        "advisoryIds",
        "advisory_ids",
        "relatedAdvisoryIds",
        "related_advisory_ids",
    ] {
        if let Some(raw) = package.get(key).and_then(Value::as_array) {
            for entry in raw {
                add_id(Some(entry));
            }
        }
    }
    add_id(package.get("advisoryId"));
    add_id(package.get("advisory_id"));
    if let Some(reasons) = package.get("reasons").and_then(Value::as_array) {
        for reason in reasons {
            let Some(reason) = reason.as_object() else {
                continue;
            };
            add_id(reason.get("advisoryId"));
            add_id(reason.get("advisory_id"));
        }
    }
    advisory_ids
}

#[cfg(test)]
mod tests {
    use super::*;

    // Consumer-visible regression for the Windows KeyError 'argv_sha256' fix:
    // every key a cross-platform consumer hard-indexes must be present, and the
    // identity must stay non-reusable / non-matching so saved approvals fail
    // closed rather than ever pinning a stable launch on an unsupported target.
    #[test]
    fn unsupported_launch_identity_is_complete_and_never_reusable() {
        let cwd = Path::new("C:\\work");
        let command = Value::String("python".to_string());
        let args = vec![
            Value::String("-m".to_string()),
            Value::String("srv".to_string()),
        ];

        let first = build_runtime_launch_identity(
            &command,
            &args,
            false,
            false,
            None,
            Some(cwd),
            None,
            None,
        );
        let second = build_runtime_launch_identity(
            &command,
            &args,
            false,
            false,
            None,
            Some(cwd),
            None,
            None,
        );

        for identity in [&first, &second] {
            assert!(identity
                .get("argv_sha256")
                .and_then(Value::as_str)
                .is_some());
            assert!(identity.get("launch_cwd").and_then(Value::as_str).is_some());
            assert!(identity.get("executable").is_some());
            assert!(identity.get("entrypoint").is_some());
            // Fail closed: the identity is never reusable and never matches.
            assert!(!runtime_launch_identity_is_reusable(identity));
            assert!(resolved_runtime_launch_executable(identity).is_none());
        }
        // Two launches of the same vector produce distinct nonces, so a saved
        // approval can never pin a stable identity on this platform.
        assert_ne!(first, second);
        assert!(!runtime_launch_identity_matches(
            &first,
            &command,
            &args,
            false,
            false,
            None,
            Some(cwd),
            None,
        ));
    }
}
