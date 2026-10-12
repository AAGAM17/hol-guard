use super::*;

#[test]
fn change_flags_inside_tool_arguments_or_output_are_data() {
    for payload in [
        json!({"tool_name": "Bash", "tool_input": {"command": "ls", "changed": true}}),
        json!({"toolName": "bash", "toolInput": {"command": "ls", "changed": "yes"}}),
        json!({"tool_input": {"previous_hash": "a", "current_hash": "b"}}),
        json!({"tool_response": {"hash_changed": true}}),
        json!({"tool_input": {"arguments": {"changed_capabilities": [1]}}}),
    ] {
        let result = apply_pre_tool_policy(
            &snapshot(policy("allow")),
            &payload,
            generic_result("allow"),
        )
        .unwrap();
        assert_eq!(result.minimum_action, "allow", "{payload}");
    }
    let result = apply_pre_tool_policy(
        &snapshot(policy("allow")),
        &json!({"changed": true, "tool_input": {"command": "ls"}}),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(result.minimum_action, "require-reapproval");
    assert_eq!(result.reason_code, "native_policy_reapproval_required");
}

#[test]
fn a_raised_result_names_the_setting_that_raised_it() {
    let result = apply_pre_tool_policy(
        &snapshot(policy("allow")),
        &json!({"changed": true, "tool_input": {"command": "ls"}}),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(
        result.reason,
        "HOL Guard requires fresh approval under the installed policy's changed artifact setting."
    );

    let mut risky = policy("allow");
    risky
        .risk_actions
        .insert("execution".into(), "require-reapproval".into());
    let result = apply_pre_tool_policy(
        &snapshot(risky),
        &json!({"tool_input": {"command": "ls"}}),
        generic_result("review"),
    )
    .unwrap();
    assert_eq!(result.reason_code, "native_policy_reapproval_required");
    assert_eq!(
        result.reason,
        "HOL Guard requires fresh approval under the installed policy's command execution setting."
    );

    // The first setting to reach the floor is named, not a later equal one.
    let mut subprocess = policy("allow");
    subprocess.subprocess_action = "review".into();
    subprocess
        .risk_actions
        .insert("execution".into(), "review".into());
    let result =
        apply_pre_tool_policy(&snapshot(subprocess), &json!({}), generic_result("allow")).unwrap();
    assert_eq!(
        result.reason,
        "HOL Guard requires review under the installed policy's subprocess setting."
    );
}
