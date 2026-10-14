#![cfg(unix)]

//! Oh My Pi `grep` and `glob` over an ordinary workspace that, like most
//! projects, keeps a gitignored `.env` at its root.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-workspace-search")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    write(home.join(".ssh/id_rsa"), "synthetic fixture\n");
    write(home.join("notes.sh"), "synthetic fixture\n");
    for name in ["app", "tracked", "custom"] {
        let workspace = home.join(name);
        std::fs::create_dir_all(workspace.join(".git")).unwrap();
        for file in [
            "deploy.sh",
            "scripts/registry-cleanup.sh",
            "src/index.ts",
            "node_modules/pkg/index.js",
            ".env",
            "config/.env.local",
        ] {
            write(workspace.join(file), "synthetic fixture\n");
        }
    }
    write(home.join("app/.gitignore"), ".env\n.env.*\nnode_modules/\n");
    write(home.join("tracked/.gitignore"), "node_modules/\n");
    write(
        home.join("custom/.gitignore"),
        ".env\n.env.*\nnode_modules/\n",
    );
    write(home.join("custom/.ignore"), "!.env\n");
    Fixture { root, home }
}

fn omp(f: &Fixture, cwd: &str, tool: &str, input: Value) -> PreToolResultV1 {
    let cwd = if cwd == "~" {
        f.home.clone()
    } else {
        f.home.join(cwd)
    };
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        f.home.to_str(),
        cwd.to_str(),
    )
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn grep_honors_the_gitignore_the_host_honors() {
    let f = fixture();
    for input in [
        json!({"pattern": "deploy", "path": "."}),
        json!({"pattern": "deploy"}),
        json!({"pattern": "deploy", "path": ".", "case": false, "gitignore": true}),
        json!({"pattern": "deploy", "path": "src; scripts"}),
    ] {
        let result = omp(&f, "app", "grep", input.clone());
        assert!(allowed(&result), "{input}: {}", result.reason_code);
        assert_eq!(result.reason_code, "native_bounded_search_scope");
    }
    // The host then searches every file, so the `.env` is in reach.
    assert!(!allowed(&omp(
        &f,
        "app",
        "grep",
        json!({"pattern": "deploy", "path": ".", "gitignore": false})
    )));
    // A `glob` or `type` override can re-include the gitignored `.env`.
    for input in [
        json!({"pattern": "KEY", "path": ".", "glob": ".env"}),
        json!({"pattern": "KEY", "path": ".", "glob": "*.sh"}),
        json!({"pattern": "KEY", "type": "sh"}),
    ] {
        assert!(!allowed(&omp(&f, "app", "grep", input.clone())), "{input}");
    }
    // Naming a secret still reviews it, ignored or not.
    for path in [".env", "src/index.ts;.env", "config/.env.local", "~/.ssh"] {
        let input = json!({"pattern": "KEY", "path": path});
        assert!(!allowed(&omp(&f, "app", "grep", input)), "{path}");
    }
    // A tracked `.env`, or a `.ignore` that can re-include one, is in reach.
    for cwd in ["tracked", "custom"] {
        let input = json!({"pattern": "deploy", "path": "."});
        assert!(!allowed(&omp(&f, cwd, "grep", input)), "{cwd}");
    }
}

#[test]
fn globs_list_names_below_the_workspace() {
    let f = fixture();
    for cwd in ["app", "tracked"] {
        for path in [
            "**/*.sh",
            "*.sh",
            "**/*{registry,deploy,cleanup}*",
            "src/**/*.ts",
            ".",
        ] {
            let result = omp(&f, cwd, "glob", json!({"path": path}));
            assert!(allowed(&result), "{cwd} {path}: {}", result.reason_code);
            assert_eq!(result.reason_code, "native_omp_directory_listing");
        }
    }
    // A walk from home or a credential directory stays on review.
    for path in ["**/*.sh", "*.sh", "**/*{notes,deploy}*"] {
        assert!(
            !allowed(&omp(&f, "~", "glob", json!({"path": path}))),
            "{path}"
        );
    }
    for path in ["~/.ssh/*", "~/{app,.ssh}/*", "../*", "{src,../..}/*"] {
        assert!(
            !allowed(&omp(&f, "app", "glob", json!({"path": path}))),
            "{path}"
        );
    }
}
