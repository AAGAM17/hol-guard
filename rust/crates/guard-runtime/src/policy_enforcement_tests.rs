use super::*;
use guard_contracts::{
    NativePromptRiskClassV1, PreToolActionV1, PreToolOperationV1, NATIVE_PROTOCOL_VERSION,
    PRE_TOOL_ACTION_V1_SCHEMA,
};
use guard_policy_snapshot::{
    EffectiveNativePolicyV3, ScopeContractV3, SnapshotIntegrityV3,
    POLICY_SNAPSHOT_INTEGRITY_ALGORITHM, POLICY_SNAPSHOT_SCHEMA,
};
use serde_json::{json, Map};
use std::collections::BTreeMap;

fn apply_pre_tool_policy(
    snapshot: &PolicySnapshotV3,
    payload: &Value,
    result: PreToolResultV1,
) -> Result<PreToolResultV1, String> {
    super::apply_pre_tool_policy(
        &AdmittedPolicySnapshot::new(snapshot.clone())?,
        payload,
        result,
    )
}

fn apply_post_tool_policy(
    snapshot: &PolicySnapshotV3,
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
    response: HookReviewResponseV1,
) -> Result<HookReviewResponseV1, String> {
    super::apply_post_tool_policy(
        &AdmittedPolicySnapshot::new(snapshot.clone())?,
        request,
        payload_kind,
        response,
    )
}

fn policy(default_action: &str) -> EffectiveNativePolicyV3 {
    EffectiveNativePolicyV3 {
        protection_posture: "protected".into(),
        security_level: "balanced".into(),
        default_action: default_action.into(),
        unknown_publisher_action: "review".into(),
        changed_hash_action: "require-reapproval".into(),
        new_network_domain_action: "allow".into(),
        subprocess_action: "allow".into(),
        risk_actions: BTreeMap::new(),
        harness_risk_actions: BTreeMap::new(),
        harness_actions: BTreeMap::new(),
        publisher_actions: BTreeMap::new(),
        artifact_actions: BTreeMap::new(),
        sandbox_analysis: "off".into(),
        receipt_redaction_level: "full".into(),
    }
}

fn snapshot(policy: EffectiveNativePolicyV3) -> PolicySnapshotV3 {
    PolicySnapshotV3 {
        schema: POLICY_SNAPSHOT_SCHEMA.into(),
        version: 3,
        generation: 1,
        policy_digest: "a".repeat(64),
        config_digest: "b".repeat(64),
        rule_digest: "c".repeat(64),
        runtime_identity: "d".repeat(64),
        protocol_version: 1,
        mode: "enforce".into(),
        scope_contract: ScopeContractV3 {
            schema: "guard-native-scope.v1".into(),
            kind: "guard-home".into(),
            scope_digest: "e".repeat(64),
            workspace_binding: "request-source".into(),
        },
        effective_policy: policy,
        command_extensions: None,
        issued_at_ms: 1,
        expires_at_ms: 2,
        integrity: SnapshotIntegrityV3 {
            algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
            key_id: "f".repeat(64),
            mac: "0".repeat(64),
        },
    }
}

fn generic_result(minimum_action: &str) -> PreToolResultV1 {
    PreToolResultV1 {
        schema: "guard-pre-tool-result.v1".into(),
        version: 1,
        authority: "rust".into(),
        action: PreToolActionV1 {
            schema: PRE_TOOL_ACTION_V1_SCHEMA.into(),
            version: 1,
            harness: "claude-code".into(),
            event: "PreToolUse".into(),
            action_type: PreToolActionTypeV1::Command,
            operation: PreToolOperationV1::Execute,
            bounded: true,
            sensitive_target: false,
        },
        decision: if matches!(minimum_action, "allow" | "warn") {
            "allow"
        } else {
            "deny"
        }
        .into(),
        policy_action: minimum_action.into(),
        minimum_action: minimum_action.into(),
        reason_code: "native_test".into(),
        reason: "native test".into(),
        explicitly_benign: minimum_action == "allow",
        command_extensions: None,
        prompt_risk_classes: Vec::new(),
    }
}

#[test]
fn warning_policy_preserves_allow_with_warning() {
    let result = apply_pre_tool_policy(
        &snapshot(policy("warn")),
        &Value::Object(Map::new()),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(result.minimum_action, "warn");
    assert_eq!(result.policy_action, "warn");
    assert_eq!(result.decision, "allow");
    assert!(!result.explicitly_benign);
}

#[test]
fn benign_prompt_relaxes_only_the_default_review_floor() {
    let mut benign = generic_result("allow");
    benign.action.event = "UserPromptSubmit".into();
    benign.action.action_type = PreToolActionTypeV1::Prompt;
    benign.action.operation = PreToolOperationV1::Submit;
    benign.reason_code = "native_prompt_benign".into();
    let payload = json!({"hook_event_name": "UserPromptSubmit", "prompt": "Summarize the project architecture."});
    let result =
        apply_pre_tool_policy(&snapshot(policy("review")), &payload, benign.clone()).unwrap();
    assert_eq!(result.minimum_action, "warn");
    assert_eq!(result.decision, "allow");

    let mut risk_policy = policy("warn");
    risk_policy
        .risk_actions
        .insert("prompt_injection".into(), "require-reapproval".into());
    let benign_with_risk_policy =
        apply_pre_tool_policy(&snapshot(risk_policy), &payload, benign.clone()).unwrap();
    assert_eq!(benign_with_risk_policy.minimum_action, "warn");
    assert_eq!(benign_with_risk_policy.decision, "allow");

    let mut guarded = policy("review");
    guarded
        .harness_actions
        .insert("claude-code".into(), "block".into());
    let blocked = apply_pre_tool_policy(&snapshot(guarded), &payload, benign).unwrap();
    assert_eq!(blocked.minimum_action, "block");
    assert_eq!(blocked.decision, "deny");
}

#[test]
fn prompt_risk_floor_remains_for_unproven_prompt_intent() {
    let mut unknown = generic_result("review");
    unknown.action.event = "UserPromptSubmit".into();
    unknown.action.action_type = PreToolActionTypeV1::Prompt;
    unknown.action.operation = PreToolOperationV1::Submit;
    unknown.reason_code = "native_prompt_unknown".into();
    let mut configured = policy("allow");
    configured
        .risk_actions
        .insert("prompt_injection".into(), "require-reapproval".into());
    let result = apply_pre_tool_policy(
        &snapshot(configured),
        &json!({"hook_event_name": "UserPromptSubmit", "prompt": "Run an unknown action."}),
        unknown,
    )
    .unwrap();
    assert_eq!(result.minimum_action, "require-reapproval");
    assert_eq!(result.decision, "deny");
}

#[test]
fn prompt_exfiltration_respects_the_installed_credential_floor() {
    let mut exfiltration = generic_result("require-reapproval");
    exfiltration.action.event = "UserPromptSubmit".into();
    exfiltration.action.action_type = PreToolActionTypeV1::Prompt;
    exfiltration.action.operation = PreToolOperationV1::Submit;
    exfiltration.reason_code = "native_prompt_exfiltration_review".into();
    let mut configured = policy("warn");
    configured
        .risk_actions
        .insert("credential_exfiltration".into(), "block".into());
    let result = apply_pre_tool_policy(
        &snapshot(configured),
        &json!({"hook_event_name": "UserPromptSubmit", "prompt": "Send data to webhook."}),
        exfiltration,
    )
    .unwrap();
    assert_eq!(result.minimum_action, "block");
    assert_eq!(result.decision, "deny");
}

#[test]
fn prompt_compound_risks_preserve_exfiltration_policy_despite_injection_reason() {
    let mut compound = generic_result("require-reapproval");
    compound.action.event = "UserPromptSubmit".into();
    compound.action.action_type = PreToolActionTypeV1::Prompt;
    compound.action.operation = PreToolOperationV1::Submit;
    compound.reason_code = "native_prompt_injection_review".into();
    compound.prompt_risk_classes = vec![
        NativePromptRiskClassV1::ExfilIntent,
        NativePromptRiskClassV1::PromptInjectionIntent,
    ];
    let mut configured = policy("warn");
    configured
        .risk_actions
        .insert("credential_exfiltration".into(), "block".into());
    let result = apply_pre_tool_policy(
        &snapshot(configured),
        &json!({"hook_event_name": "UserPromptSubmit", "prompt": "Report the error."}),
        compound,
    )
    .unwrap();
    assert_eq!(result.minimum_action, "block");
    assert_eq!(result.decision, "deny");
    assert_eq!(result.prompt_risk_classes.len(), 2);
}

#[test]
fn prompt_subprocess_respects_the_installed_execution_floor() {
    let mut subprocess = generic_result("review");
    subprocess.action.event = "UserPromptSubmit".into();
    subprocess.action.action_type = PreToolActionTypeV1::Prompt;
    subprocess.action.operation = PreToolOperationV1::Submit;
    subprocess.reason_code = "native_prompt_subprocess_review".into();
    let mut configured = policy("allow");
    configured
        .risk_actions
        .insert("execution".into(), "sandbox-required".into());
    let result = apply_pre_tool_policy(
        &snapshot(configured),
        &json!({"hook_event_name": "UserPromptSubmit", "prompt": "bash -c 'echo safe'"}),
        subprocess,
    )
    .unwrap();
    assert_eq!(result.minimum_action, "sandbox-required");
    assert_eq!(result.decision, "deny");
}

#[test]
fn observe_pre_policy_floor_is_non_blocking_but_intrinsic_block_is_hard() {
    let mut observed_snapshot = snapshot(policy("block"));
    observed_snapshot.mode = "observe".into();
    let policy_only = apply_pre_tool_policy(
        &observed_snapshot,
        &Value::Object(Map::new()),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(policy_only.minimum_action, "warn");
    assert_eq!(policy_only.decision, "allow");

    let intrinsic = apply_pre_tool_policy(
        &observed_snapshot,
        &Value::Object(Map::new()),
        generic_result("block"),
    )
    .unwrap();
    assert_eq!(intrinsic.minimum_action, "block");
    assert_eq!(intrinsic.decision, "deny");
}

#[test]
fn observe_preserves_every_intrinsic_non_allow_pre_floor() {
    let mut observed_snapshot = snapshot(policy("allow"));
    observed_snapshot.mode = "observe".into();
    for action in ["review", "require-reapproval", "sandbox-required", "block"] {
        let intrinsic = apply_pre_tool_policy(
            &observed_snapshot,
            &Value::Object(Map::new()),
            generic_result(action),
        )
        .unwrap();
        assert_eq!(intrinsic.minimum_action, action);
        assert_eq!(intrinsic.decision, "deny");
        assert_eq!(intrinsic.reason_code, "native_test");
    }

    let mut malformed = generic_result("block");
    malformed.action.action_type = PreToolActionTypeV1::Unknown;
    malformed.reason_code = "native_pre_tool_malformed_payload".into();
    let malformed =
        apply_pre_tool_policy(&observed_snapshot, &Value::Object(Map::new()), malformed).unwrap();
    assert_eq!(malformed.minimum_action, "block");
    assert_eq!(malformed.decision, "deny");
    assert_eq!(malformed.reason_code, "native_pre_tool_malformed_payload");
}

#[test]
fn observe_policy_block_raises_existing_review_to_non_overridable_floor() {
    let mut observed_snapshot = snapshot(policy("block"));
    observed_snapshot.mode = "observe".into();
    let result = apply_pre_tool_policy(
        &observed_snapshot,
        &Value::Object(Map::new()),
        generic_result("review"),
    )
    .unwrap();
    assert_eq!(result.minimum_action, "block");
    assert_eq!(result.policy_action, "block");
    assert_eq!(result.decision, "deny");
}

#[test]
fn action_floor_matrix_rejects_inconsistent_decision_fields() {
    let mut policy_block = generic_result("review");
    policy_block.policy_action = "block".into();
    assert_eq!(
        validate_pre_tool_result_matrix(&policy_block).unwrap_err(),
        "native_policy_decision_inconsistent"
    );

    let mut allow_for_block = generic_result("block");
    allow_for_block.decision = "allow".into();
    assert_eq!(
        validate_pre_tool_result_matrix(&allow_for_block).unwrap_err(),
        "native_policy_decision_inconsistent"
    );

    let mut benign_warning = generic_result("warn");
    benign_warning.explicitly_benign = true;
    assert_eq!(
        validate_pre_tool_result_matrix(&benign_warning).unwrap_err(),
        "native_policy_decision_inconsistent"
    );

    for action in [
        "allow",
        "warn",
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    ] {
        let result = generic_result(action);
        assert!(validate_pre_tool_result_matrix(&result).is_ok(), "{action}");
    }
}

#[test]
fn prompt_risk_classes_reject_non_prompt_duplicate_and_unordered_evidence() {
    let mut invalid = generic_result("block");
    invalid.prompt_risk_classes = vec![NativePromptRiskClassV1::GuardBypassIntent];
    assert_eq!(
        validate_pre_tool_result_matrix(&invalid).unwrap_err(),
        "native_prompt_risk_classes_invalid"
    );
    invalid.action.event = "UserPromptSubmit".into();
    invalid.action.action_type = PreToolActionTypeV1::Prompt;
    invalid.action.operation = PreToolOperationV1::Submit;
    invalid.prompt_risk_classes = vec![
        NativePromptRiskClassV1::ExfilIntent,
        NativePromptRiskClassV1::LocalEnvRead,
    ];
    assert_eq!(
        validate_pre_tool_result_matrix(&invalid).unwrap_err(),
        "native_prompt_risk_classes_invalid"
    );
    invalid.prompt_risk_classes = vec![NativePromptRiskClassV1::ExfilIntent; 2];
    assert_eq!(
        validate_pre_tool_result_matrix(&invalid).unwrap_err(),
        "native_prompt_risk_classes_invalid"
    );
}

fn post_request(payload: Value) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        request_id: Some("policy-test".into()),
        harness: "claude-code".into(),
        event_name: "PostToolUse".into(),
        payload,
        cwd: None,
        home_dir: "/home/test".into(),
        guard_home: "/home/test/.hol-guard".into(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

#[test]
fn policy_allow_cannot_lower_intrinsic_review_or_block() {
    let snapshot = snapshot(policy("allow"));
    for action in ["review", "block"] {
        let result = apply_pre_tool_policy(
            &snapshot,
            &Value::Object(Map::new()),
            generic_result(action),
        )
        .unwrap();
        assert_eq!(result.minimum_action, action);
        assert_eq!(result.decision, "deny");
    }
}

#[test]
fn policy_block_raises_intrinsic_allow() {
    let snapshot = snapshot(policy("block"));
    let result = apply_pre_tool_policy(
        &snapshot,
        &Value::Object(Map::new()),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(result.minimum_action, "block");
    assert_eq!(result.reason_code, "native_policy_block");
}

#[test]
fn conflicting_harness_aliases_fail_closed() {
    let mut effective = policy("allow");
    effective
        .harness_actions
        .insert("claude".into(), "review".into());
    effective
        .harness_actions
        .insert("claude-code".into(), "block".into());
    let result = apply_pre_tool_policy(
        &snapshot(effective),
        &Value::Object(Map::new()),
        generic_result("allow"),
    );
    assert_eq!(
        result.unwrap_err(),
        "native_policy_harness_selector_conflict"
    );
}

#[test]
fn conflicting_harness_risk_aliases_fail_closed() {
    let mut effective = policy("allow");
    effective.harness_risk_actions.insert(
        "claude".into(),
        BTreeMap::from([(String::from("execution"), String::from("review"))]),
    );
    effective.harness_risk_actions.insert(
        "claude-code".into(),
        BTreeMap::from([(String::from("execution"), String::from("block"))]),
    );
    let result = apply_pre_tool_policy(
        &snapshot(effective),
        &Value::Object(Map::new()),
        generic_result("allow"),
    );
    assert_eq!(
        result.unwrap_err(),
        "native_policy_harness_selector_conflict"
    );
}

#[test]
fn post_intrinsic_block_cannot_be_lowered_by_allow_policy() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "safe-looking output"
    }));
    let response =
        HookReviewResponseV1::deny("source_secret_match", "native source content was blocked");
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        response,
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("block"));
    let encoded = serde_json::to_string(&result).unwrap();
    assert!(!encoded.contains("safe-looking"));
}

#[test]
fn post_warning_policy_preserves_allow_with_warning() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "safe-looking output"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("warn")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "allow");
    assert_eq!(result.policy_action.as_deref(), Some("warn"));
    assert_eq!(result.notice, "warning");
}

#[test]
fn post_policy_fields_raise_without_python_semantic_input() {
    let mut effective = policy("allow");
    effective.unknown_publisher_action = "review".into();
    effective.changed_hash_action = "block".into();
    effective
        .publisher_actions
        .insert("trusted".into(), "allow".into());
    effective
        .artifact_actions
        .insert("pkg-a".into(), "block".into());
    let request = post_request(json!({
        "tool_name": "npm_install",
        "publisher": "trusted",
        "artifact_id": "pkg-a",
        "changed": true,
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("block"));
}

#[test]
fn unknown_post_action_is_review_even_when_default_allows() {
    let request = post_request(json!({
        "tool_name": "future_tool_v9",
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("review"));
    assert_eq!(result.reason_code, "native_policy_review_required");
}

#[test]
fn unreadable_tool_remains_unknown_under_allow_policy() {
    let request = post_request(json!({
        "tool_name": "unreadable_tool",
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("review"));
    assert_eq!(result.reason_code, "native_policy_review_required");
}

#[test]
fn conflicting_request_selectors_fail_closed() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "publisher": "one",
        "publisherId": "two",
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    );
    assert_eq!(result.unwrap_err(), "native_policy_selector_conflict");
}

#[test]
fn observe_preserves_intrinsic_block_but_does_not_enforce_policy_only_floor() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "ok"
    }));
    let mut observed_snapshot = snapshot(policy("block"));
    observed_snapshot.mode = "observe".into();
    let policy_only = apply_post_tool_policy(
        &observed_snapshot,
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(policy_only.decision, "allow");
    assert_eq!(policy_only.policy_action.as_deref(), Some("block"));

    let intrinsic_observed =
        HookReviewResponseV1::deny("source_secret_match", "blocked").observed(None);
    let intrinsic = apply_post_tool_policy(
        &observed_snapshot,
        &request,
        GuardHookPayloadKindV2::Inline,
        intrinsic_observed,
    )
    .unwrap();
    assert_eq!(intrinsic.decision, "allow");
    assert_eq!(intrinsic.policy_action.as_deref(), Some("block"));
    assert_eq!(intrinsic.observed_policy_action.as_deref(), Some("block"));
    assert!(intrinsic.observe_mode);
}

fn observe_post_tool(payload: Value, response: HookReviewResponseV1) -> HookReviewResponseV1 {
    let mut observed_snapshot = snapshot(policy("allow"));
    observed_snapshot.mode = "observe".into();
    apply_post_tool_policy(
        &observed_snapshot,
        &post_request(payload),
        GuardHookPayloadKindV2::Inline,
        response,
    )
    .unwrap()
}

fn native_deny() -> HookReviewResponseV1 {
    let mut response = HookReviewResponseV1::deny("output_secret_match", "output requires review");
    response.policy_action = Some("block".to_owned());
    response
}

#[test]
fn test_complete_inline_recording_only_output_gets_matching_proof() {
    let content = "complete tool output";
    let payload = json!({"tool_response": [{"type": "text", "text": content}]});

    let result = observe_post_tool(payload, native_deny());

    assert_eq!(result.decision, "allow");
    assert_eq!(result.model_output_action, "allow_original");
    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(guard_hook_core::sha256_text(content).as_str())
    );
}

#[test]
fn test_source_ref_proof_is_copied_without_hashing_an_excerpt() {
    let digest = "a".repeat(64);
    let payload = json!({
        "guard_source_ref": {"output_sha256": digest},
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": true,
        },
    });

    let result = observe_post_tool(payload, native_deny());

    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(digest.as_str())
    );
}

#[test]
fn test_inherited_excerpt_digest_is_removed_during_allow_original_rewrite() {
    let payload = json!({
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": true,
        },
    });
    let mut native = native_deny();
    native.reviewed_output_sha256 = Some(guard_hook_core::sha256_text("bounded excerpt"));

    let result = observe_post_tool(payload, native);

    assert_eq!(result.decision, "allow");
    assert_eq!(result.model_output_action, "allow_original");
    assert!(result.reviewed_output_sha256.is_none());
}

#[test]
fn test_inherited_excerpt_digest_is_removed_from_existing_allow_response() {
    let payload = json!({
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": true,
        },
    });
    let mut native = HookReviewResponseV1::allow("output_scan_allow");
    native.policy_action = Some("warn".to_owned());
    native.reviewed_output_sha256 = Some(guard_hook_core::sha256_text("bounded excerpt"));

    let result = observe_post_tool(payload, native);

    assert_eq!(result.decision, "allow");
    assert_eq!(result.model_output_action, "allow_original");
    assert!(result.reviewed_output_sha256.is_none());
}

#[test]
fn test_stale_allow_original_uses_canonical_inline_proof() {
    let content = "canonical inline output";
    let mut native = HookReviewResponseV1::allow("output_scan_allow");
    native.policy_action = Some("warn".to_owned());
    native.reviewed_output_sha256 = Some("b".repeat(64));
    let payload = json!({"tool_response": [{"type": "text", "text": content}]});

    let result = observe_post_tool(payload, native);

    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(guard_hook_core::sha256_text(content).as_str())
    );
}

#[test]
fn test_summary_without_digest_falls_back_to_complete_inline_output() {
    let content = "complete inline output";
    let payload = json!({
        "tool_response_summary": {"text_excerpt": "bounded excerpt"},
        "tool_response": [{"type": "text", "text": content}],
    });

    let result = observe_post_tool(payload, native_deny());

    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(guard_hook_core::sha256_text(content).as_str())
    );
}

#[test]
fn test_truncated_or_excerpt_only_output_gets_no_fabricated_proof() {
    let payload = json!({
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": true,
        },
    });

    let result = observe_post_tool(payload, native_deny());

    assert!(result.reviewed_output_sha256.is_none());
    assert!(result.observe_mode);
}

#[test]
fn test_existing_observe_mode_is_preserved_during_rewrite() {
    let payload = json!({"stdout": "bounded excerpt"});
    let mut native = native_deny();
    native.observe_mode = true;

    let result = observe_post_tool(payload, native);

    assert!(result.observe_mode);
    assert!(result.reviewed_output_sha256.is_none());
}

#[test]
fn test_truncated_inline_output_gets_no_proof() {
    let payload = json!({"tool_response": vec!["x"; 25]});

    let result = observe_post_tool(payload, native_deny());

    assert!(result.reviewed_output_sha256.is_none());
    assert!(result.observe_mode);
}
