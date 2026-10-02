use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn zcode_home_relative_edits_accept_only_registered_repository_worktrees() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/worktree-write-fixtures")
        .join(format!("run-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let home = std::fs::canonicalize(root).unwrap();
    let workspace = home.join("project");
    let linked = home.join("linked");
    let linked_path = linked.to_str().unwrap();
    let linked_path = linked_path.strip_prefix(r"\\?\").unwrap_or(linked_path);
    let hooks = home.join("empty-fixture-hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    let git = |arguments: &[&str]| {
        let output = std::process::Command::new("git")
            .current_dir(&workspace)
            .arg("-c")
            .arg(format!("core.hooksPath={}", hooks.display()))
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "--quiet"]);
    git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "fixture",
    ]);
    git(&["worktree", "add", "--quiet", "--detach", linked_path]);
    for directory in [&workspace, &linked, &home.join("unrelated")] {
        std::fs::create_dir_all(directory.join("src")).unwrap();
        std::fs::write(directory.join("src/example.ts"), "fixture").unwrap();
    }
    for (path, allowed) in [
        ("~/project/src/example.ts", true),
        ("~/linked/src/example.ts", true),
        ("~/linked/src/new.ts", true),
        ("~/linked/app/api/backfill/route.ts", true),
        ("~/linked/app/api/backfill/.env", false),
        ("~/linked/.ssh/new/id_rsa", false),
        ("~/linked/.env", false),
        ("~/linked/.git", false),
        ("~/unrelated/src/example.ts", false),
        ("~other/project/src/example.ts", false),
    ] {
        let result = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName": "Edit", "toolInput": {"file_path": path, "old_string": "fixture", "new_string": "updated"}}),
            None,
            None,
            home.to_str(),
            Some("~/project"),
        );
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{path}: {}",
            result.reason_code
        );
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            home.join("unrelated/src/example.ts"),
            linked.join("src/escape.ts"),
        )
        .unwrap();
        let result = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName": "Edit", "toolInput": {"file_path": "~/linked/src/escape.ts", "new_string": "updated"}}),
            None,
            None,
            home.to_str(),
            Some("~/project"),
        );
        assert_ne!(result.minimum_action, "allow");
    }
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn routine_workspace_writes_keep_sensitive_and_destructive_boundaries() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/workspace-write-fixtures")
        .join(format!("run-{}", std::process::id()));
    let workspace = root.join("project");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::create_dir_all(workspace.join(".ssh")).unwrap();
    std::fs::create_dir_all(workspace.join("Library/LaunchAgents")).unwrap();
    std::fs::write(workspace.join("src/example.py"), "fixture").unwrap();
    std::fs::write(root.join("outside.py"), "fixture").unwrap();
    let workspace = std::fs::canonicalize(workspace).unwrap();
    for (tool, path, allowed) in [
        ("edit", "src/example.py".to_owned(), true),
        ("write", "src/new.py".to_owned(), true),
        ("write", "app/api/backfill/route.ts".to_owned(), true),
        ("write", "src/example.py/nested/new.py".to_owned(), false),
        ("write", "app/api/backfill/.env".to_owned(), false),
        ("write", ".env".to_owned(), false),
        ("write", ".ssh/id_rsa".to_owned(), false),
        ("write", ".git/config".to_owned(), false),
        (
            "write",
            "Library/LaunchAgents/background.plist".to_owned(),
            false,
        ),
        ("write", "src/server.key".to_owned(), false),
        ("write", "src/krb5cc_1000".to_owned(), false),
        ("write", "../outside.py".to_owned(), false),
        (
            "write",
            root.join("outside.py").to_string_lossy().into_owned(),
            false,
        ),
        ("delete", "src/example.py".to_owned(), false),
        ("edit", "src".to_owned(), false),
    ] {
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": {"path": path, "content": "print(1 + 1)"}}),
            None,
            None,
            workspace.to_str(),
            workspace.to_str(),
        );
        assert_eq!(result.minimum_action == "allow", allowed, "{tool}: {path}");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            root.join("missing-directory"),
            workspace.join("dangling-parent"),
        )
        .unwrap();
        let dangling = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName":"Write", "toolInput":{"file_path":"dangling-parent/nested/new.py", "content":"fixture"}}),
            None,
            None,
            workspace.to_str(),
            workspace.to_str(),
        );
        assert_ne!(dangling.minimum_action, "allow");
        let link = workspace.join("src/escape.py");
        if link.symlink_metadata().is_err() {
            std::os::unix::fs::symlink(root.join("outside.py"), &link).unwrap();
        }
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "write", "tool_input": {"path": link, "content": "fixture"}}),
            None,
            None,
            workspace.to_str(),
            workspace.to_str(),
        );
        assert_ne!(result.minimum_action, "allow");
    }
}
