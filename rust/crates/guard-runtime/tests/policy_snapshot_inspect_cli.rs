use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hol-guard-runtime"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn policy_snapshot_inspect_cli_routes_stdin_stdout_and_finite_refusals() {
    let request = json!({
        "schema":"guard-native-policy-build.v1", "version":1, "verifier_key":vec![7u8;32],
        "generation":4, "runtime_identity":"a".repeat(64), "rule_digest":"b".repeat(64),
        "mode":"enforce", "issued_at_ms":100, "expires_at_ms":1000,
        "scope_contract":{"schema":"guard-native-scope.v1","kind":"guard-home",
            "scope_digest":"c".repeat(64),"workspace_binding":"request-source"},
        "effective_policy":{
            "protection_posture":"protected","security_level":"balanced","default_action":"warn",
            "unknown_publisher_action":"review","changed_hash_action":"require-reapproval",
            "new_network_domain_action":"warn","subprocess_action":"warn","risk_actions":{},
            "harness_risk_actions":{},"harness_actions":{},"publisher_actions":{},"artifact_actions":{},
            "sandbox_analysis":"off","receipt_redaction_level":"full"},
        "business_policy":{"schema":"guard.native-business-policy.v1","version":1,
            "defaultAction":"block","rules":[]}
    });
    let built = run(
        &["policy-snapshot-build", "--stdin"],
        &serde_json::to_vec(&request).unwrap(),
    );
    assert!(built.status.success(), "{:?}", built.stderr);
    let snapshot: Value = serde_json::from_slice(&built.stdout).unwrap();
    let inspected = run(&["policy-snapshot-inspect", "--stdin"], &built.stdout);
    assert!(inspected.status.success(), "{:?}", inspected.stderr);
    assert!(inspected.stderr.is_empty());
    let result: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(result.as_object().unwrap().len(), 8);
    assert_eq!(
        result["schema"],
        "guard-native-policy-content-inspection.v1"
    );
    assert_eq!(result["authenticity"], "not_checked");
    assert_eq!(result["currentness"], "not_checked");
    assert_eq!(result["business_policy_present"], true);
    assert_eq!(result["config_digest"], snapshot["config_digest"]);
    assert_eq!(result["policy_digest"], snapshot["policy_digest"]);
    assert_eq!(
        result["snapshot_digest"],
        guard_policy_snapshot::digest_bytes(
            &guard_policy_snapshot::snapshot_bytes(&serde_json::from_value(snapshot).unwrap())
                .unwrap()
        )
    );

    let malformed = run(&["policy-snapshot-inspect", "--stdin"], b"private-canary");
    assert!(!malformed.status.success());
    assert!(malformed.stdout.is_empty());
    assert_eq!(
        String::from_utf8(malformed.stderr).unwrap().trim(),
        "native_policy_snapshot_inspect_invalid"
    );
    let usage = run(&["policy-snapshot-inspect"], b"");
    assert!(!usage.status.success());
    assert!(usage.stdout.is_empty());
    assert!(String::from_utf8(usage.stderr).unwrap().contains("--stdin"));
}
