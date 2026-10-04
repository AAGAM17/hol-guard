use super::super::safe_reads::bounded_omp_directory_read_target;

fn fixture_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-directory-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
}

fn read_directory(
    harness: &str,
    target: &str,
    home: &std::path::Path,
    cwd: &std::path::Path,
) -> guard_contracts::PreToolResultV1 {
    super::super::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": target},
        }),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

#[test]
fn omp_directory_reads_allow_project_and_immediate_sibling_only() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let sibling = home.join("sibling-project");
    let unrelated = root.join("unrelated-project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();
    std::fs::create_dir_all(&unrelated).unwrap();

    let project_target = project.to_string_lossy().into_owned();
    let project_decision = read_directory("omp", &project_target, &home, &project);
    assert_eq!(project_decision.minimum_action, "allow");
    assert_eq!(
        project_decision.reason_code,
        "native_exact_safe_directory_read"
    );
    assert!(project_decision.explicitly_benign);

    let sibling_decision = read_directory("omp", "../sibling-project", &home, &project);
    assert_eq!(sibling_decision.minimum_action, "allow");
    assert_eq!(
        sibling_decision.reason_code,
        "native_exact_safe_directory_read"
    );

    let unrelated_target = unrelated.to_string_lossy().into_owned();
    let unrelated_decision = read_directory("omp", &unrelated_target, &home, &project);
    assert_ne!(unrelated_decision.minimum_action, "allow");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn directory_allow_does_not_allow_dotenv_or_credential_file_reads() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let ssh = home.join(".ssh");
    let aws = home.join(".aws");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::create_dir_all(&aws).unwrap();
    std::fs::write(project.join(".env"), "directory-listing-secret-canary").unwrap();
    std::fs::write(project.join("credentials.json"), "credential-canary").unwrap();

    let project_target = project.to_string_lossy().into_owned();
    let listing = read_directory("omp", &project_target, &home, &project);
    assert!(bounded_omp_directory_read_target(
        &project_target,
        home.to_str(),
        project.to_str(),
    ));
    assert_eq!(
        listing.minimum_action, "allow",
        "{}: {}",
        listing.reason_code, listing.reason
    );

    for target in [
        project.join(".env"),
        project.join("credentials.json"),
        home.join(".ssh"),
        home.join(".aws"),
    ] {
        let target = target.to_string_lossy().into_owned();
        let decision = read_directory("omp", &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{target}");
        assert!(!decision.explicitly_benign, "{target}");
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pi_unknown_and_recursive_harnesses_do_not_get_directory_allow() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let target = project.to_string_lossy().into_owned();
    for harness in ["pi", "unknown", "omp-recursive"] {
        let decision = read_directory(harness, &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{harness}");
        assert!(!decision.explicitly_benign, "{harness}");
    }
    let post_tool = super::super::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PostToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": target},
        }),
        None,
        None,
        home.to_str(),
        project.to_str(),
    );
    assert_ne!(post_tool.minimum_action, "allow");
    let missing_context = super::super::evaluate_pre_tool_envelope(
        "omp",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": target},
        }),
    );
    assert_ne!(missing_context.minimum_action, "allow");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn directory_symlink_escape_stays_reviewable() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let external = root.join("external");
    let link = project.join("linked-directory");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&external).unwrap();
    std::os::unix::fs::symlink(&external, &link).unwrap();

    for target in [link, project.join("../project/linked-directory")] {
        let target = target.to_string_lossy().into_owned();
        let decision = read_directory("omp", &target, &home, &project);
        assert_ne!(decision.minimum_action, "allow", "{target}");
        assert!(!decision.explicitly_benign, "{target}");
    }

    let _ = std::fs::remove_dir_all(root);
}
