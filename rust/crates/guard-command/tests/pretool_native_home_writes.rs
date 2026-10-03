#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn native_home_writes_keep_sensitive_targets_guarded() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/native-home-writes")
        .join(format!("fixture-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let workspace = home.join("project");
    let other = home.join("other-project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join(".env"), "SYNTHETIC_ONLY=fixture").unwrap();
    let alias = other.join("alias.txt");
    if !alias.exists() {
        std::os::unix::fs::symlink(other.join(".env"), &alias).unwrap();
    }
    for harness in ["omp", "zcode"] {
        for (path, allowed) in [
            (other.join("new.txt"), true),
            (other.join("source.ts"), true),
            (other.join(".env"), false),
            (alias.clone(), false),
            (other.join(".git/config"), false),
            (home.join(".ssh/authorized_keys"), false),
            (home.join(".hol-guard/config.json"), false),
            (home.join("Library/LaunchAgents/payload.plist"), false),
            (home.join(".config/autostart/payload.desktop"), false),
            (root.join("another-home/new.txt"), false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"write", "tool_input": {
                    "path":path.to_str().unwrap(), "content":"ordinary fixture\n"
                }}),
                None,
                None,
                home.to_str(),
                workspace.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {}",
                path.display()
            );
        }
    }
    for unverified_home in [None, Some("/")] {
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"write", "tool_input": {
                "path":other.join("new.txt"), "content":"ordinary fixture\n"
            }}),
            None,
            None,
            unverified_home,
            workspace.to_str(),
        );
        assert_ne!(
            result.minimum_action, "allow",
            "missing or root-wide home scope"
        );
    }
}
