#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn recursion_flags_on_explicit_files_do_not_authorize_directory_walks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("fixture-{}", std::process::id()));
    std::fs::create_dir_all(root.join("src")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("src/one.ts"), "ordinary source").unwrap();
    std::fs::write(root.join("src/two.ts"), "ordinary source").unwrap();
    std::fs::write(root.join(".env"), "synthetic secret").unwrap();
    std::os::unix::fs::symlink(root.join(".env"), root.join("src/alias.ts")).unwrap();
    for harness in ["omp", "zcode"] {
        for (command, expected) in [
            ("grep -rn ordinary src/one.ts src/two.ts".to_owned(), true),
            (
                format!(
                    "grep -rn ordinary {}/src/one.ts {}/src/two.ts",
                    root.display(),
                    root.display()
                ),
                true,
            ),
            ("grep -Rn ordinary src/one.ts".to_owned(), true),
            ("grep --recursive -n ordinary src/one.ts".to_owned(), true),
            (
                "grep --directories=recurse ordinary src/one.ts".to_owned(),
                true,
            ),
            ("grep -rn ordinary src".to_owned(), false),
            ("grep -rn ordinary".to_owned(), false),
            ("grep -rn ordinary src/missing.ts".to_owned(), false),
            ("grep -rn ordinary src/alias.ts".to_owned(), false),
            ("grep -rn ordinary src/one.ts .env".to_owned(), false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}"
            );
        }
    }
}
