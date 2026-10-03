use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

#[test]
fn permits_only_standalone_plain_directory_changes() {
    assert!(!safe_directory_target(r"~/.ss\h"));
    for command in [
        "cd ~/CascadeProjects/project",
        "cd ./project",
        "cd /opt/project",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.minimum_action, "allow", "{command}");
    }
    for command in [
        "cd $(touch marker)",
        "cd `touch marker`",
        "cd ~/project && python script.py",
        "cd /opt/project | cat file.txt",
        "cd ~/.ssh",
        "cd /opt/user/.ssh",
        "cd ~/.s*",
        "cd .ssh*",
        "cd ./project?",
        "cd ./[project]",
        "cd -",
        "cd ~+",
        "cd ~-",
        "cd ~+/project",
        "cd ~-/project",
        "cd ~0",
        "cd ~1",
        "cd ~0/project",
        "cd ~12/project",
        "cd ~+1/project",
        "cd ~-1/project",
    ] {
        let result = evaluate_pre_tool(&request(command));
        assert!(
            result.is_err() || result.unwrap().minimum_action != "allow",
            "{command}"
        );
    }
}

#[test]
fn blocks_destructive_and_device_commands() {
    for command in [
        "rm -rf /",
        "rm -rf -- /",
        "shred ~/.ssh/id_ed25519",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
        "shutdown -h now",
        "reboot",
        "wipefs -a /dev/sda",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "deny", "{command}");
        assert_eq!(decision.minimum_action, "block", "{command}");
    }
}

#[test]
fn reviews_home_relative_secret_paths() {
    let decision = evaluate_pre_tool(&request("cat ~/.npmrc")).unwrap();
    assert_eq!(decision.decision, "deny");
    assert_eq!(decision.minimum_action, "review");
    assert_eq!(decision.reason_code, "native_sensitive_access_review");
}

#[test]
fn reviews_dotenv_family_shell_reads() {
    for command in [
        "cat .env",
        "cat .env.synthetic",
        "cat /workspace/.env.local",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "deny", "{command}");
        assert_eq!(decision.minimum_action, "review", "{command}");
        assert_eq!(
            decision.reason_code, "native_sensitive_access_review",
            "{command}"
        );
    }
}

#[test]
fn allows_bounded_exact_commands() {
    for command in [
        "pwd",
        "whoami",
        "uname -a",
        "git status --short",
        "git status --short --branch",
        "git remote -v",
        "git remote --verbose",
        "git remote -v --",
        "git remote --verbose --",
        "gh auth status",
        "gh auth status --help",
        "gh auth status -h",
        "git remote -v && gh auth status",
        "git rev-parse --show-toplevel",
        "git diff --no-ext-diff --no-textconv --check",
        "rg -n authority src",
        "rg -g*.ts authority src",
        "rg --glob '*.{ts,tsx}' authority src",
        "rg --line-number --color=never authority src",
        "grep -n authority README.md",
        "grep --line-number --color=never authority README.md",
        "grep -eerror README.md",
        "grep -e 'terraform.tfvars' README.md",
        "grep -d skip authority README.md",
        "stat README.md",
        "date",
        "date -u +%Y-%m-%dT%H:%M:00Z",
        "date --utc +%s",
        "date -R",
        "date -I",
        "date -d @0",
        "date --rfc-2822",
        "date --rfc-3339=seconds",
        "pwd; date +%H:%M:%S",
        "ls",
        "ls -la src",
        "cat README.md",
        "head -n 20 README.md",
        "tail -n 5 README.md",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "allow", "{command}");
        assert!(decision.explicitly_benign, "{command}");
    }
}

#[test]
fn allows_only_bounded_guard_doctor_diagnostics() {
    for command in [
        "hol-guard doctor",
        "hol-guard doctor --json",
        "hol-guard doctor 2>&1 | tail -45",
        "hol-guard doctor --json 2>&1 | tail -n 45",
        "hol-guard doctor 2>&1 && true",
        "timeout 120 hol-guard doctor 2>&1 | tail -45",
        "timeout 120 hol-guard doctor --json 2>&1 | tail -n 45",
        "timeout 120 hol-guard doctor 2>&1 | head -45",
        "timeout 120 hol-guard doctor 2>&1 | tail -45 | wc -l",
        "true && hol-guard doctor --json",
        "hol-guard doctor --json && true",
        "hol-guard doctor --json | tail -45",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.minimum_action, "allow", "{command}");
        assert_eq!(
            decision.reason_code, "native_exact_safe_command",
            "{command}"
        );
    }
    for command in [
        "./hol-guard doctor",
        "/usr/local/bin/hol-guard doctor",
        "/tmp/fake/bin/hol-guard doctor",
        "~/.local/bin/hol-guard doctor",
        "hol-guard doctor --run-cli",
        "hol-guard doctor --repair",
        "hol-guard doctor --json --repair",
        "hol-guard update",
        "sudo -n hol-guard doctor",
        "env FOO=bar hol-guard doctor",
        "timeout --kill-after=1 120 hol-guard doctor 2>&1 | tail -45",
        "cat .env && hol-guard doctor",
        "hol-guard doctor && cat .env",
        "hol-guard doctor && unknown-command",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_ne!(decision.minimum_action, "allow", "{command}");
    }
}

#[cfg(unix)]
#[test]
fn path_qualified_guard_doctor_requires_verified_outer_identity() {
    use guard_contracts::{GuardCliIdentityV1, GuardExecutionEnvironmentV1};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    let root =
        std::env::temp_dir().join(format!("hol-guard-doctor-identity-{}", std::process::id()));
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let invocation = bin.join("hol-guard");
    let body = b"#!/usr/bin/python3\nimport sys\nfrom codex_plugin_scanner.cli import main\nif __name__ == '__main__':\n    sys.argv[0] = sys.argv[0].removesuffix('.exe')\n    sys.exit(main())\n";
    std::fs::write(&invocation, body).unwrap();
    std::fs::set_permissions(&invocation, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = invocation.canonicalize().unwrap();
    let identity = GuardCliIdentityV1 {
        schema: guard_contracts::GUARD_CLI_IDENTITY_V1_SCHEMA.to_owned(),
        invocation_path: invocation.to_string_lossy().into_owned(),
        target_path: target.to_string_lossy().into_owned(),
        target_sha256: hex::encode(Sha256::digest(body)),
        invocation_link_target: None,
    };
    let environment = GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_names: Vec::new(),
        environment_digest: "a".repeat(64),
        home: Some(root.to_string_lossy().into_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        cli_identity: Some(identity),
    };
    let evaluate = |command: &str| {
        evaluate_pre_tool_with_execution_context(
            &request(command),
            environment.home.as_deref(),
            None,
            Some(&environment),
        )
        .unwrap()
    };
    for command in [
        format!("{} doctor", invocation.display()),
        "~/bin/hol-guard doctor".to_owned(),
        format!(
            "timeout 120 {} doctor 2>&1 | tail -45",
            invocation.display()
        ),
        format!(
            "{} doctor | grep -E 'Mode|Runtime|Approval' | head -12",
            invocation.display()
        ),
        format!(
            "timeout 120 {} doctor 2>&1 | grep -E 'Mode|Runtime|Approval' | head -12",
            invocation.display()
        ),
        format!("{} doctor && true", invocation.display()),
    ] {
        assert_eq!(evaluate(&command).minimum_action, "allow", "{command}");
    }
    for command in [
        format!("{} doctor --repair", invocation.display()),
        format!("{} doctor --run-cli", invocation.display()),
        format!("{} doctor", root.join("other/hol-guard").display()),
        format!("{} doctor 2>&1 | cat .env", invocation.display()),
        format!("{} doctor 2>&1 | unknown-consumer", invocation.display()),
    ] {
        assert_ne!(evaluate(&command).minimum_action, "allow", "{command}");
    }
    std::fs::write(&invocation, b"changed launcher\n").unwrap();
    assert_ne!(
        evaluate(&format!("{} doctor", invocation.display())).minimum_action,
        "allow"
    );
    let malicious_body = b"#!/usr/bin/python3\nimport sys\nfrom codex_plugin_scanner.cli import main\nprint('unexpected side effect')\nif __name__ == '__main__':\n    sys.exit(main())\n";
    std::fs::write(&invocation, malicious_body).unwrap();
    let mut forged_environment = environment.clone();
    forged_environment
        .cli_identity
        .as_mut()
        .unwrap()
        .target_sha256 = hex::encode(Sha256::digest(malicious_body));
    let forged_evaluate = |command: &str| {
        evaluate_pre_tool_with_execution_context(
            &request(command),
            forged_environment.home.as_deref(),
            None,
            Some(&forged_environment),
        )
        .unwrap()
    };
    assert_ne!(
        forged_evaluate(&format!("{} doctor", invocation.display())).minimum_action,
        "allow"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn allows_bounded_pipeline_consumers() {
    for command in [
        "git status --short | head -2",
        "git status --short | tail -n 2",
        "cat README.md | head -2 | tail -n 1",
        "git status --short | head",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.minimum_action, "allow", "{command}");
    }
    let decision = evaluate_pre_tool(&request(
        "git status --short | head -2 && git log --oneline -1",
    ))
    .unwrap();
    assert_eq!(decision.reason_code, "native_git_helper_context_review");
    for command in [
        "head -2",
        "git status --short && head -2",
        "git status --short |& head -2",
        "git status --short | head -2; tail -n 1",
        "git status --short | head -2 || tail -n 1",
        "cat ~/.ssh/id_ed25519 | head -2",
        "curl https://example.test | head -2",
        "git status --short | head -2 > out.txt",
        "git status --short | tail -f",
        "git status --short | head -n",
        "git status --short | head -n $(whoami)",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert!(!decision.explicitly_benign, "{command}");
    }
}

#[test]
fn allows_exact_destructive_tool_introspection() {
    for command in ["shutdown --help", "mkfs --version"] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "allow", "{command}");
        assert!(decision.explicitly_benign, "{command}");
    }
}

#[test]
fn reviews_date_mutations_and_unbounded_file_reads() {
    for command in [
        "date -s tomorrow",
        "date --set=tomorrow",
        "date +%s +%N",
        "date -f timestamps.txt",
        "date -d tomorrow",
        "git remote",
        "git remote add origin example",
        "git remote -v -- add origin example",
        "git remote -v -- remove origin",
        "git remote -v -- set-url origin example",
        "gh auth status --show-token",
        "cat .env",
        "head -f README.md",
        "tail -f README.md",
        "cat -",
        "cat /etc/passwd",
        "cat .aws/credentials",
        "cat /./proc/self/environ",
        "cat //etc/passwd",
        "cat /proc//self/environ",
        "cat /var/../etc/passwd",
        "cat README.md Cargo.toml",
        "head -n 10 README.md Cargo.toml",
        "ls /",
        "cat /root/secret",
        "cat /home/user/notes",
        "ls -R /",
        "ls --recursive src",
        "head -1000000 README.md",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.minimum_action, "review", "{command}");
        assert!(!decision.explicitly_benign, "{command}");
    }
}

#[test]
fn reviews_only_materially_risky_variants_of_safe_commands() {
    let inert_pattern = evaluate_pre_tool(&request("rg -e '.env.local' src")).unwrap();
    assert_eq!(inert_pattern.decision, "allow");
    assert_eq!(inert_pattern.minimum_action, "allow");
    for command in [
            "rg --pre /opt/guard-test/payload authority src",
            "rg --hostname-bin=/opt/guard-test/payload --hyperlink-format='file://{host}{path}' TOKEN src",
            "rg --hidden authority .",
            "rg -uuu authority .",
            "rg -L authority .",
            "rg --no-ignore-files authority .",
            "rg --glob '*.env' TOKEN .",
            "rg --glob '*.{env,ts}' TOKEN .",
            "rg --glob 'nested/*.env' TOKEN .",
            "rg --glob 'nested/[.]env' TOKEN .",
            r"rg --glob 'nested/[\.]env' TOKEN .",
            "rg --glob 'nested/{safe,.env}' TOKEN .",
            "rg TOKEN .env.local",
            "grep -r password .",
            "rg id_rsa /home",
            "rg --glob 'nested/[.]env.local' TOKEN .",
            "rg --glob 'nested/[.]env.production' TOKEN .",
            "rg --glob 'nested/[.]e[n]v.production' TOKEN .",
            "rg --glob 'nested/[.]e*v.production' TOKEN .",
            "rg --glob 'my-private-[k]ey-prod.pem' TOKEN .",
            "rg --glob 'my-private-[ak]ey-prod.pem' TOKEN .",
            "rg --glob 'my-pr[i]vate-[k]ey-prod.pem' TOKEN .",
            "rg --type-add 'secret:.env' -tsecret TOKEN .",
            "rg TOKEN .aws/config",
            "rg TOKEN terraform.tfvars",
            "rg TOKEN wallet.key",
            "rg TOKEN .gnupg/private-keys-v1.d/key",
            "rg authority .env",
            "grep authority .npmrc",
            "grep TOKEN .*",
            "grep TOKEN '.[a-z]*'",
            "grep TOKEN nested/.*",
            "grep -R authority .",
            "grep -d recurse TOKEN .",
            "grep --directories=recurse TOKEN .",
            "grep --recursiv TOKEN .",
            "grep --direct=recurse TOKEN .",
            "rg --hidd TOKEN .",
            "rg --globx '*.ts' TOKEN .",
            "/opt/guard-test/rg authority src",
            "FOO=bar git status --short",
            "GIT_EXTERNAL_DIFF=/opt/guard-test/payload git diff --ext-diff README.md",
            "git diff --output=/opt/guard-test/diff README.md",
            "git log -1 --output=/opt/guard-test/log",
            "git diff --check",
            "git log -1",
            "git show HEAD",
            "git show HEAD:.env",
            "git show HEAD:.git/config",
        ] {
            let decision = evaluate_pre_tool(&request(command)).unwrap();
            assert_eq!(decision.decision, "deny", "{command}");
            assert_eq!(decision.minimum_action, "review", "{command}");
            assert!(!decision.explicitly_benign, "{command}");
        }
}

#[test]
fn defers_only_exact_safe_git_helper_context() {
    let contextual = evaluate_pre_tool(&request("git diff --check")).unwrap();
    assert_eq!(contextual.reason_code, "native_git_helper_context_review");

    let unsafe_output =
        evaluate_pre_tool(&request("git diff --output=/tmp/diff README.md")).unwrap();
    assert_eq!(unsafe_output.reason_code, "native_command_review_required");

    let option_shaped_paths =
        evaluate_pre_tool(&request("git diff -- --no-ext-diff --no-textconv")).unwrap();
    assert_eq!(
        option_shaped_paths.reason_code,
        "native_git_helper_context_review"
    );
}

#[test]
fn denies_uncertain_or_networked_commands_but_allows_proven_constant_expression() {
    for (command, permitted) in [
        ("echo $(whoami)", false),
        ("pwd && rm -rf /", false),
        ("python -c 'print(1)'", true),
        ("git push origin main", false),
        ("PATH=/tmp:$PATH ls", false),
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision == "allow", permitted, "{command}");
        assert_eq!(decision.minimum_action == "allow", permitted, "{command}");
    }
}
