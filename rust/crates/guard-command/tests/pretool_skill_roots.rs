#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn zcode_reads_markdown_only_in_supported_skill_locations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-skill-roots")
        .join(format!("home-{}", std::process::id()));
    let roots = [
        ".agents/skills/example",
        ".claude/skills/example",
        ".codex/skills/example",
        ".codex/superpowers/skills/example",
        ".zcode/cli/plugins/cache/market/example/1.0.0/skills/example",
    ];
    for skill in roots {
        for leaf in [
            "SKILL.md",
            "reference/operate.md",
            "credentials.md",
            ".hidden.md",
            "run.py",
        ] {
            let path = root.join(skill).join(leaf);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "synthetic fixture\n").unwrap();
        }
    }
    for path in [
        ".zcode/cli/config.md",
        ".zcode/cli/plugins/cache/market/example/1.0.0/README.md",
        ".zcode/cli/plugins/cache/market/example/skills/example/SKILL.md",
        ".zcode/cli/plugins/cache/market/example/1.0.0/skills/SKILL.md",
        ".ssh/id_rsa",
    ] {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic fixture\n").unwrap();
    }
    let home = std::fs::canonicalize(&root).unwrap();
    let evaluate = |path: &str, tool: &str| {
        evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName": tool, "toolInput": {"file_path": path, "content": "replacement"}}),
            None,
            None,
            home.to_str(),
            home.to_str(),
        )
    };
    for skill in roots {
        for (leaf, allowed) in [
            ("SKILL.md", true),
            ("reference/operate.md", true),
            ("credentials.md", false),
            (".hidden.md", false),
            ("run.py", false),
        ] {
            let path = format!("~/{skill}/{leaf}");
            assert_eq!(
                evaluate(&path, "Read").minimum_action == "allow",
                allowed,
                "{path}"
            );
        }
        for (command, allowed) in [
            (format!("cat ~/{skill}/SKILL.md"), true),
            (
                format!("cat ~/{skill}/SKILL.md && cat ~/.ssh/id_rsa"),
                false,
            ),
            (format!("cat ~/{skill}/SKILL.md > ~/{skill}/copy.md"), false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                "zcode",
                "PreToolUse",
                &json!({"toolName": "Bash", "toolInput": {"command": command}}),
                None,
                None,
                home.to_str(),
                home.to_str(),
            );
            assert_eq!(result.minimum_action == "allow", allowed, "{command}");
        }
        assert_ne!(
            evaluate(&format!("~/{skill}/SKILL.md"), "Write").minimum_action,
            "allow"
        );
    }
    for path in [
        "~/.zcode/cli/config.md",
        "~/.zcode/cli/plugins/cache/market/example/1.0.0/README.md",
        "~/.zcode/cli/plugins/cache/market/example/skills/example/SKILL.md",
        "~/.zcode/cli/plugins/cache/market/example/1.0.0/skills/SKILL.md",
        "~/.ssh/id_rsa",
        "~/.codex/skills/example/../outside.md",
    ] {
        assert_ne!(evaluate(path, "Read").minimum_action, "allow", "{path}");
    }
    let link = home.join(".codex/skills/example/reference/escaped.md");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(home.join(".ssh/id_rsa"), &link).unwrap();
    assert_ne!(
        evaluate(link.to_str().unwrap(), "Read").minimum_action,
        "allow"
    );
}
