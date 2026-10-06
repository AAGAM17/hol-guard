//! Launch-identity material shared by the Unix implementation and the
//! non-Unix stub: the same labeled `guard-context-unbound:launch-argv:` digest
//! and the same shell-tokenizer argv rules apply on both platforms, so a
//! launch digests identically regardless of target.

use std::path::Path;

use guard_contracts::write_canonical_json;
use serde_json::Value;
use sha2::{Digest, Sha256};

// `native_context.py` unbound degrade prefix (:441-453).
pub(crate) const UNBOUND_PREFIX: &str = "guard-context-unbound:";

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// `_canonical_material_bytes` (native_context.py :383-388) → canonical JSON
// UTF-8 bytes. `ensure_ascii=True` semantics are enforced inside
// `write_canonical_json` (the contract is byte-identical).
pub(crate) fn canonical_material_bytes(material: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    // JSON encode failure is unreachable for identity material (only strings,
    // numbers, arrays, maps); fail closed to an empty-payload digest rather
    // than panic, matching the unbound degrade semantics.
    if write_canonical_json(material, &mut out).is_err() {
        return Vec::new();
    }
    out
}

// `context_opaque_digest(material, unbound_label=<label>, strict=True)` —
// when the native resident is absent (always true for in-process Rust) the
// strict degrade is `guard-context-unbound:<label>:<sha256(canonical_json)>`
// (native_context.py :441-453 + :377-388).
pub(crate) fn context_opaque_digest_strict(material: &str, unbound_label: &str) -> String {
    let material_bytes = canonical_material_bytes(&Value::String(material.to_string()));
    format!(
        "{}{}:{}",
        UNBOUND_PREFIX,
        unbound_label,
        sha256_hex(&material_bytes)
    )
}

// `_launch_argv_digest` (:891-897) — `opaque_material_digest` over
// `json.dumps(list(argv), ensure_ascii=True, separators=(",",":"))`.
pub(crate) fn launch_argv_digest(argv: &[String]) -> String {
    let material = Value::Array(argv.iter().map(|s| Value::String(s.clone())).collect());
    let mut bytes = Vec::with_capacity(64);
    if write_canonical_json(&material, &mut bytes).is_err() {
        bytes.clear();
    }
    let text = String::from_utf8_lossy(&bytes);
    context_opaque_digest_strict(&text, "launch-argv")
}

// `_runtime_launch_identity` argv construction (:906-920), extracted so the
// Unix and non-Unix implementations resolve the launch vector through one
// code path.
//
// - `command` must be a non-blank string; anything else is `Invalid`.
// - A `structured_command` is already an executable name — the whole string
//   is one token even when it contains whitespace or quote characters; no
//   tokenization is attempted, so structured commands can never be malformed.
// - A shell command string is tokenized with the same parser the Unix path
//   uses (`crate::shell_tokens`, POSIX shlex-equivalent rules); an
//   unterminated quote or dangling escape is `Invalid`, as is a vector that
//   produces no token or carries a non-string `args` element.
// - `Valid` carries the full argv (`executable + command-derived tokens +
//   args`) used for `argv_sha256`; `Invalid` carries the command's first
//   token — or the raw command when tokenization failed — so the caller can
//   still name the executable in the fail-closed identity.
pub(crate) enum RuntimeLaunchArgv {
    Valid(Vec<String>),
    Invalid(Value),
}

pub(crate) fn runtime_launch_argv(
    command: &Value,
    args: &[Value],
    structured_command: bool,
) -> RuntimeLaunchArgv {
    let command_str = match command.as_str() {
        Some(s) if !s.trim().is_empty() => s,
        _ => return RuntimeLaunchArgv::Invalid(Value::Null),
    };
    let command_tokens: Vec<String>;
    if structured_command {
        command_tokens = vec![command_str.to_string()];
    } else {
        match crate::shell_tokens(command_str, false) {
            Ok(t) => command_tokens = t,
            Err(_) => {
                // Tokenization failed before a vector existed; name the raw
                // command so the fail-closed executable identity is usable.
                return RuntimeLaunchArgv::Invalid(command.clone());
            }
        }
    }
    let invalid = || {
        RuntimeLaunchArgv::Invalid(
            command_tokens
                .first()
                .map(|s| Value::String(s.clone()))
                .unwrap_or_else(|| command.clone()),
        )
    };
    if command_tokens.is_empty() || !args.iter().all(|a| a.is_string()) {
        return invalid();
    }
    let mut full_argv = command_tokens;
    full_argv.reserve(args.len());
    for a in args {
        if let Some(s) = a.as_str() {
            full_argv.push(s.to_string());
        }
    }
    RuntimeLaunchArgv::Valid(full_argv)
}

// `_normalized_launch_cwd` (:872-878) — expanduser + resolve(strict=False)
// with absolute() fallback. The stub reports the same string the Unix
// implementation computes so `launch_cwd` is identical across platforms for
// the same input. expanduser/resolve are cwd-only path operations that work
// on every supported target.
pub(crate) fn expand_user(path: &Path) -> std::path::PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home);
        }
        return path.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    path.to_path_buf()
}

pub(crate) fn normalized_launch_cwd(cwd: Option<&Path>) -> std::path::PathBuf {
    let candidate = cwd.map(expand_user).unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    });
    candidate.canonicalize().unwrap_or_else(|_| {
        if candidate.is_absolute() {
            candidate
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join(candidate)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn argv_of(command: &Value, args: &[Value], structured: bool) -> Result<Vec<String>, Value> {
        match runtime_launch_argv(command, args, structured) {
            RuntimeLaunchArgv::Valid(argv) => Ok(argv),
            RuntimeLaunchArgv::Invalid(executable_cmd) => Err(executable_cmd),
        }
    }

    // Review regression (PR3664): a shell command string and the equivalent
    // structured command must resolve to the same argv — the stub previously
    // hashed the raw string as one argv element, so `"git status"` digested
    // as `["git status"]` on Windows but `["git","status"]` on Unix.
    #[test]
    fn shell_command_and_structured_vector_agree() {
        let args = [json!("--porcelain")];
        let shell = argv_of(&json!("git status"), &args, false).unwrap();
        assert_eq!(shell, vec!["git", "status", "--porcelain"]);
        // The structured form carries the executable only; the digest of a
        // structured launch is byte-identical to the tokenized shell launch
        // for the same vector — and identical on every platform.
        let structured = argv_of(
            &json!("git"),
            &[json!("status"), json!("--porcelain")],
            true,
        )
        .unwrap();
        assert_eq!(shell, structured);
        assert_eq!(launch_argv_digest(&shell), launch_argv_digest(&structured));
    }

    #[test]
    fn structured_command_stays_single_token() {
        // A structured command is an executable name verbatim — whitespace
        // and quote characters are never tokenized, so it can never be
        // malformed the way a shell string can.
        let argv = argv_of(&json!("my tool --flag"), &[], true).unwrap();
        assert_eq!(argv, vec!["my tool --flag"]);
        let argv = argv_of(&json!("unterminated 'quote"), &[], true).unwrap();
        assert_eq!(argv, vec!["unterminated 'quote"]);
    }

    #[test]
    fn quoted_argument_boundaries_hold() {
        // Quoted groups join into single argv elements; quoting inside one
        // quoting style is preserved per shlex rules.
        let argv = argv_of(&json!("python -m \"my module\" 'other arg'"), &[], false).unwrap();
        assert_eq!(argv, vec!["python", "-m", "my module", "other arg"]);
        let argv = argv_of(&json!("say \"hi\""), &[], false).unwrap();
        assert_eq!(argv, vec!["say", "hi"]);
        let argv = argv_of(&json!("say 'a\\b'"), &[], false).unwrap();
        assert_eq!(argv, vec!["say", "a\\b"]);
    }

    #[test]
    fn malformed_command_and_non_string_args_are_invalid() {
        // Unterminated quote / dangling escape must invalidate the vector,
        // never partially tokenize (same fail-closed surface as Unix).
        assert!(argv_of(&json!("git 'unterminated"), &[], false).is_err());
        assert!(argv_of(&json!("git foo\\"), &[], false).is_err());
        assert!(argv_of(&json!(""), &[], false).is_err());
        assert!(argv_of(&json!("   "), &[], false).is_err());
        assert!(argv_of(&Value::Null, &[], false).is_err());
        assert!(argv_of(&json!(42), &[], false).is_err());
        // Non-string args poison the whole vector even when the command
        // tokenizes cleanly.
        assert!(argv_of(&json!("git"), &[json!(1)], false).is_err());
        assert!(argv_of(&json!("git"), &[json!(null)], true).is_err());
        assert!(argv_of(&json!("git"), &[json!("-m"), json!({"k": 1})], false).is_err());
    }

    #[test]
    fn launch_argv_digest_uses_unix_label_contract() {
        // The digest is the strict `guard-context-unbound:launch-argv:` degrade
        // (context_opaque_digest over the canonical JSON argv text), byte-for-
        // byte what the Unix implementation emits — NOT the plain canonical
        // `digest_json` hash. Oracles verified against Python
        // native_context.py semantics:
        //   sha256(json.dumps(json.dumps(["git","status"],separators=(",",":"),
        //   ensure_ascii=True), ensure_ascii=True))
        assert_eq!(
            launch_argv_digest(&["git".to_string(), "status".to_string()]),
            "guard-context-unbound:launch-argv:8731c2300a49f227285b1c5d205ce9232d4438adafb38cfbb1676b6ca8043c5d"
        );
        assert_eq!(
            launch_argv_digest(&[]),
            "guard-context-unbound:launch-argv:b3283bf184bb082f364b8537776bc6b15fce2ff9f9acb3fb11ae87da394bfd4b"
        );
    }
}
