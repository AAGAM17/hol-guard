use std::path::Path;

use crate::CanonicalCommandV1;

use super::{read_paths, PathContext};

const MAX_SCRIPT_BYTES: usize = 64 * 1024;

// This can only strengthen a script's execution floor. An absent, unreadable,
// oversized or unrecognized script never gains benign execution authority.
pub(super) fn contains_credential_post(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> bool {
    if !read_paths::verified_path_context(context.home_dir, context.cwd) {
        return false;
    }
    // The model does not bind a per-segment cwd. Never inspect a different
    // relative file after a directory-changing sibling command.
    if model.segments.iter().any(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(|value| matches!(value.rsplit('/').next(), Some("cd" | "pushd" | "popd")))
    }) {
        return false;
    }
    model.segments.iter().any(|segment| {
        if !crate::parser_wrappers::is_file_shell_invocation(
            segment.executable.as_deref(),
            &segment.arguments,
        ) {
            return false;
        }
        let arguments = segment.arguments.as_slice();
        let script = if arguments.first().is_some_and(|arg| arg == "--") {
            &arguments[1]
        } else {
            &arguments[0]
        };
        if !read_paths::bounded_file_read_target(script, context.home_dir, context.cwd) {
            return false;
        }
        let Ok(path) = guard_secure_fs::resolve_candidate(
            script,
            context.cwd.map(Path::new),
            Path::new(context.home_dir.unwrap_or_default()),
        ) else {
            return false;
        };
        let Ok(read) = guard_secure_fs::read_bounded(&path, MAX_SCRIPT_BYTES) else {
            return false;
        };
        let Ok(text) = std::str::from_utf8(&read.bytes) else {
            return false;
        };
        credential_post(text)
    })
}

fn credential_post(text: &str) -> bool {
    let active = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let lowered = active.to_ascii_lowercase();
    let code = mask_literals(&lowered);
    let credential_access = code.contains("os.environ[") || code.contains("os.environ.get(");
    let python_post = code.contains("urllib.request.urlopen(")
        && code
            .match_indices("urllib.request.request(")
            .any(|(start, call)| {
                let arguments_start = start + call.len();
                let mut depth = 1;
                let end = code.as_bytes()[arguments_start..].iter().position(|byte| {
                    match byte {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    depth == 0
                });
                end.is_some_and(|end| {
                    explicit_post_method(
                        &code[arguments_start..arguments_start + end],
                        &lowered[arguments_start..arguments_start + end],
                    )
                })
            });
    credential_access && python_post
}

fn explicit_post_method(code: &str, raw: &str) -> bool {
    let bytes = code.as_bytes();
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth != 0
            || !bytes[index..].starts_with(b"method")
            || (index > 0 && !bytes[index - 1].is_ascii_whitespace() && bytes[index - 1] != b',')
        {
            continue;
        }
        let mut cursor = index + 6;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        let raw_bytes = raw.as_bytes();
        while raw_bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if matches!(raw_bytes.get(cursor), Some(b'\'' | b'"'))
            && raw_bytes
                .get(cursor + 1..cursor + 5)
                .is_some_and(|value| value.starts_with(b"post"))
            && raw_bytes.get(cursor + 5) == raw_bytes.get(cursor)
        {
            return true;
        }
    }
    false
}

fn mask_literals(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output[index] = b' ';
                index += 1;
            }
            continue;
        }
        if !matches!(bytes[index], b'\'' | b'"') {
            index += 1;
            continue;
        }
        let quote = bytes[index];
        let width = if bytes.get(index..index + 3) == Some(&[quote, quote, quote]) {
            3
        } else {
            1
        };
        output[index..index + width].fill(b' ');
        index += width;
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                let end = (index + 2).min(bytes.len());
                output[index..end].fill(b' ');
                index = end;
                continue;
            }
            if bytes
                .get(index..index + width)
                .is_some_and(|slice| slice.iter().all(|byte| *byte == quote))
            {
                output[index..index + width].fill(b' ');
                index += width;
                break;
            }
            output[index] = b' ';
            index += 1;
        }
    }
    String::from_utf8(output).expect("masking preserves UTF-8 outside literals")
}

#[cfg(test)]
mod tests {
    use super::credential_post;
    use crate::pretool::generic::evaluate_pre_tool_envelope_with_context;
    use serde_json::json;

    #[test]
    fn credential_post_requires_active_environment_access_and_posting() {
        assert!(credential_post("value = os.environ[\"TOKEN\"]\nrequest = urllib.request.Request(url, data=value, method=\"POST\")\nurllib.request.urlopen(request)"));
        assert!(!credential_post("# os.environ[\"TOKEN\"]\n# urllib.request.Request(url, method=\"POST\")\n# urllib.request.urlopen(request)"));
        assert!(!credential_post(
            "value = os.environ[\"TOKEN\"]\nprint(value)"
        ));
        assert!(!credential_post(
            "urllib.request.Request(url, method=\"POST\")\nurllib.request.urlopen(request)"
        ));
        assert!(!credential_post("printf '%s' 'os.environ[\"TOKEN\"] urllib.request.Request(url, method=\"POST\") urllib.request.urlopen(request)'"));
        assert!(!credential_post("\"\"\"os.environ[\"TOKEN\"]\nurllib.request.Request(url, method=\"POST\")\nurllib.request.urlopen(request)\"\"\""));
        assert!(credential_post("body = os.environ[\"TOKEN\"]\nrequest = urllib.request.Request(url, data=body, method = 'POST')\nurllib.request.urlopen(request)"));
        assert!(!credential_post("body = os.environ[\"TOKEN\"]\nrequest = urllib.request.Request(url, data=\"method='POST'\")\nurllib.request.urlopen(request)"));
    }

    #[test]
    fn physical_script_inspection_blocks_posting_without_authorizing_other_scripts() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temporary_root = if cfg!(target_os = "macos") {
            std::path::PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let root = temporary_root.join(format!("guard-script-post-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::write(root.join("posting.sh"), "python3 - <<'PY'\nvalue = os.environ[\"TOKEN\"]\nrequest = urllib.request.Request(url, data=value, method=\"POST\")\nurllib.request.urlopen(request)\nPY\n").unwrap();
        std::fs::write(root.join("ordinary.sh"), "#!/bin/sh\nprintf fixture-safe\n").unwrap();
        std::fs::create_dir(root.join("nested")).unwrap();
        std::fs::write(
            root.join("nested/posting.sh"),
            "#!/bin/sh\nprintf fixture-safe\n",
        )
        .unwrap();
        for (command, expected) in [
            ("bash ./posting.sh", "block"),
            ("bash ./ordinary.sh", "review"),
            ("cd nested && bash ./posting.sh", "review"),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                "zcode",
                "PreToolUse",
                &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(result.minimum_action, expected);
            assert_eq!(result.decision, "deny");
            assert!(!result.explicitly_benign);
            if expected == "block" {
                assert_eq!(result.reason_code, "native_secret_exfiltration");
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
