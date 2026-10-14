//! Replays Gemini and Antigravity detection vectors recorded from the
//! original Python implementation (see `testdata/gemini/record_adapter_vectors.py`).
//! Fixture trees and expected artifacts, paths and warnings come from Python,
//! never from Rust output. `<ROOT>` is the fixture root.

use serde_json::{json, Value};

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::pi_vectors_tests::{materialize, release, substitute};
use crate::runner_authority_op::KindResult;

const GEMINI: &str = include_str!("../testdata/gemini/vectors.json");
const ANTIGRAVITY: &str = include_str!("../testdata/antigravity/vectors.json");

fn check(case: &Value, name: &str, root_text: &str, result: KindResult) -> Result<(), String> {
    if case["refused"] == true {
        return match result {
            Err(_) => Ok(()),
            Ok(answer) => Err(format!(
                "{name}: expected a refusal, the resident answered {answer}"
            )),
        };
    }
    let answer = result.map_err(|code| format!("{name}: resident refused with {code}"))?;
    let mismatches: Vec<String> = ["artifacts", "found_paths", "warnings"]
        .into_iter()
        .filter_map(|field| {
            let expected = substitute(&case[field], root_text);
            (answer[field] != expected).then(|| {
                format!(
                    "{name}: {field}\n  resident: {}\n  python:   {expected}",
                    answer[field]
                )
            })
        })
        .collect();
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches.join("\n"))
    }
}

fn replay_all(vectors: &str, schema: &str, detect: fn(&Value) -> KindResult) {
    let vectors: Value = serde_json::from_str(vectors).unwrap();
    assert_eq!(vectors["schema"], schema);
    let mut replayed = 0;
    let mut failures = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let root = temp_home(&format!("ad-{name}").chars().take(60).collect::<String>());
        materialize(&root, case);
        let root_text = root.to_string_lossy().into_owned();
        let result = detect(&substitute(&case["args"], &root_text));
        if let Err(message) = check(case, name, &root_text, result) {
            failures.push(message);
        }
        release(&root);
        replayed += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(replayed >= 25, "only {replayed} cases recorded");
}

#[test]
fn replays_every_recorded_gemini_detection_case() {
    replay_all(
        GEMINI,
        "guard-gemini-vectors.v1",
        crate::gemini_detect::detect,
    );
}

#[test]
fn replays_every_recorded_antigravity_detection_case() {
    replay_all(
        ANTIGRAVITY,
        "guard-antigravity-vectors.v1",
        crate::antigravity_detect::detect,
    );
}

#[test]
fn malformed_requests_are_refused() {
    for (harness, detect) in [
        (
            "gemini",
            crate::gemini_detect::detect as fn(&Value) -> KindResult,
        ),
        ("antigravity", crate::antigravity_detect::detect),
    ] {
        let valid = json!({"harness": harness, "home": "/nonexistent/home", "workspace": null});
        assert!(detect(&valid).is_ok(), "{harness}");
        for (key, value) in [
            ("harness", json!("claude-code")),
            ("harness", json!(1)),
            ("home", json!(null)),
            ("home", json!("/x\u{0}y")),
            ("workspace", json!(1)),
            ("cwd", json!("relative")),
            ("cwd", json!(1)),
        ] {
            let mut args = valid.clone();
            args[key] = value.clone();
            assert!(detect(&args).is_err(), "{harness} {key}={value}");
        }
        let relative = json!({"harness": harness, "home": "home", "workspace": null});
        assert!(
            detect(&relative).is_err(),
            "{harness}: a relative home needs cwd"
        );
        assert!(detect(&json!([])).is_err());
    }
}
