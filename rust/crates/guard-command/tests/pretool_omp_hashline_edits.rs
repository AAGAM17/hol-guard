#![cfg(any(unix, windows))]

use serde_json::json;

use crate::git_helper_fixture as fixture;
use fixture::evaluate_pre_tool_envelope_with_context;

fn patch(sections: &[&str]) -> String {
    format!("*** Begin Patch\n{}*** End Patch\n", sections.concat())
}

#[test]
fn oh_my_pi_hashline_edits_get_the_file_write_proof() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/omp-hashline-fixtures")
        .join(format!(
            "case-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let _cleanup = fixture::FixtureCleanup(root.clone());
    let home = std::fs::canonicalize(&root).unwrap();
    let workspace = home.join("project");
    let sibling = home.join("project-fix");
    for directory in [&workspace, &sibling] {
        std::fs::create_dir_all(directory.join("src")).unwrap();
        std::fs::create_dir_all(directory.join(".git")).unwrap();
        std::fs::write(directory.join("src/a.ts"), "export const a = 1;\n").unwrap();
    }
    std::fs::write(workspace.join("src/b.ts"), "export const b = 2;\n").unwrap();
    std::fs::write(workspace.join(".env"), "TOKEN=synthetic\n").unwrap();
    std::fs::write(workspace.join("AGENTS.md"), "rules\n").unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n").unwrap();
    let in_sibling = format!(
        "[{}#0AC4]\nPUT 1.=1:\n+export const a = 3;\n",
        sibling.join("src/a.ts").display()
    );
    let absolute = format!(
        "[{}#0AC4]\nPUT >$:\n+// end\n",
        workspace.join("src/a.ts").display()
    );
    let put_a = "[src/a.ts#0AC4]\nPUT 1.=1:\n+export const a = 3;\n";
    let put_b = "[src/b.ts#1B2C]\nPUT <1:\n+import { a } from './a';\n";
    let missing = "[project-fix-typo/src/a.ts#0AC4]\nPUT 1.=1:\n+x\n";

    let evaluate = |harness: &str, input: &str| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "edit", "tool_input": {"input": input}}),
            None,
            None,
            home.to_str(),
            workspace.to_str(),
        )
    };
    for input in [
        patch(&[put_a]),
        patch(&[put_a, put_b]),
        patch(&[&absolute]),
        patch(&[&in_sibling, put_b]),
        patch(&["[src/new.ts]\nPUT >$:\n+export {};\n"]),
        patch(&[
            "[src/a.ts#0AC4]\nCUT 1.=1 @line\n",
            "[src/b.ts#1B2C]\nPUT >$ @line\n",
        ]),
    ] {
        let result = evaluate("omp", &input);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("allow", "native_exact_safe_file_write"),
            "{input}"
        );
    }
    // A file that does not exist cannot be edited; the agent fixes the path.
    for input in [patch(&[missing]), patch(&[put_a, missing])] {
        let result = evaluate("omp", &input);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("block", "native_missing_path"),
            "{input}"
        );
    }
    for input in [
        patch(&["[.env#0AC4]\nPUT 1.=1:\n+TOKEN=changed\n"]),
        patch(&[put_a, "[.env#0AC4]\nPUT >$:\n+EXTRA=1\n"]),
        patch(&["[missing/.env#0AC4]\nPUT >$:\n+TOKEN=x\n"]),
        patch(&["[AGENTS.md#0AC4]\nPUT >$:\n+more rules\n"]),
        patch(&["[.git/config#0AC4]\nPUT >$:\n+[alias]\n"]),
        patch(&["[.git/hooks/pre-commit]\nPUT >$:\n+exit 0\n"]),
        patch(&["[src/a.ts#0AC4]\nREM\n"]),
        patch(&["[src/a.ts#0AC4]\nMV ../outside.ts\n"]),
        patch(&["[~/.zshrc#0AC4]\nPUT >$:\n+export X=1\n"]),
        patch(&["[*** Update File: src/a.ts#0AC4]\nPUT 1.=1:\n+x\n"]),
        "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-export const a = 1;\n+export const a = 3;\n*** End Patch\n".to_owned(),
    ] {
        let result = evaluate("omp", &input);
        assert_eq!(result.minimum_action, "review", "{input}: {result:?}");
    }
    // Only Oh My Pi's edit tool takes a hashline patch.
    let result = evaluate("claude-code", &patch(&[put_a]));
    assert_ne!(result.minimum_action, "allow", "{result:?}");
}
