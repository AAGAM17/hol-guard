use guard_command::pretool::generic::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn github_controls(
    state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":[
                {"target_kind":"permission", "target_id":"command.git.permission.status", "state":state},
                {"target_kind":"permission", "target_id":"command.git.permission.diff", "state":state},
                {"target_kind":"permission", "target_id":"command.github.permission.read-local", "state":state},
                {"target_kind":"permission", "target_id":"command.github.permission.read-remote", "state":state}
            ]
        }]
    })).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

#[test]
fn configured_fsmonitor_cannot_be_admitted_as_a_benign_read() {
    let root = std::env::temp_dir().join(format!("guard-git-config-{}", std::process::id()));
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let enabled = github_controls("enabled");
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["config", "core.fsmonitor", "./synthetic-never-execute"])
        .status()
        .unwrap()
        .success());
    for harness in ["omp", "zcode"] {
        for command in [
            "git status --short",
            "git diff --no-ext-diff --no-textconv",
            "echo ready && git status --short",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            assert_eq!(result.reason_code, "native_git_execution_context_review");
        }
    }
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["config", "core.fsmonitor", "false"])
        .status()
        .unwrap()
        .success());
    for harness in ["omp", "zcode"] {
        for command in [
            "git status --short",
            "git -c core.quotepath=false status --short",
            "git -c core.fsmonitor=false status --short",
            "echo ready && git status --short | head -1",
            "git status --short && gh api repos/owner/repo/compare/base...main | head -1",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(
                result.decision, "allow",
                "{harness}: {command}: safe configuration must stay quiet"
            );
        }
    }
    let disabled = github_controls("disabled");
    for harness in ["omp", "zcode"] {
        for command in [
            "echo ready && git status --short | head -1",
            "git status --short && gh api repos/owner/repo/compare/base...main",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&disabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(result.minimum_action, "block", "{harness}: {command}");
        }
        for command in [
            "git config core.fsmonitor ./synthetic-never-execute && git status --short",
            "GIT_CONFIG_GLOBAL=/tmp/synthetic-never-read git status --short",
            "GIT_EXTERNAL_DIFF=/tmp/synthetic-never-execute git status --short",
            "PAGER=/tmp/synthetic-never-execute git status --short",
            "gh api repos/owner/repo; cat .env",
            "git status --short; rm -rf src",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
    for key in [
        "filter.fixture.clean",
        "filter.fixture.process",
        "filter.fixture.smudge",
    ] {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["config", key, "./synthetic-never-execute"])
            .status()
            .unwrap()
            .success());
        for harness in ["omp", "zcode"] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(
                result.reason_code, "native_git_execution_context_review",
                "{harness}: {key}"
            );
        }
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["config", "--unset", key])
            .status()
            .unwrap()
            .success());
    }
    std::fs::remove_dir_all(root).unwrap();
}
