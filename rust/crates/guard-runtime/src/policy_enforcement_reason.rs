use super::policy_enforcement_helpers::FloorCause;

/// The reason code and text for a result the installed policy raised, naming
/// the policy setting that raised it when it is known.
pub(super) fn policy_override_reason(
    action: &str,
    cause: Option<FloorCause>,
) -> (&'static str, String) {
    let (code, outcome) = match action {
        "block" => ("native_policy_block", "blocked this hook action"),
        "sandbox-required" => (
            "native_policy_sandbox_required",
            "requires sandbox enforcement",
        ),
        "require-reapproval" => (
            "native_policy_reapproval_required",
            "requires fresh approval",
        ),
        "review" => ("native_policy_review_required", "requires review"),
        _ => ("native_policy_warning", "raised this action"),
    };
    let Some(cause) = cause else {
        return (
            code,
            format!("HOL Guard {outcome} under the installed native policy."),
        );
    };
    let setting = match cause {
        FloorCause::Default => "default action".to_owned(),
        FloorCause::Harness => "setting for this harness".to_owned(),
        FloorCause::Subprocess => "subprocess setting".to_owned(),
        FloorCause::Network => "new network domain setting".to_owned(),
        FloorCause::Unknown => "rule for unrecognized tool operations".to_owned(),
        FloorCause::ChangedHash => "changed artifact setting".to_owned(),
        FloorCause::UnknownPublisher => "unknown publisher setting".to_owned(),
        FloorCause::Artifact => "rule for this artifact".to_owned(),
        FloorCause::Publisher => "rule for this publisher".to_owned(),
        FloorCause::Risk(risk) => format!("{} setting", risk_label(risk)),
    };
    (
        code,
        format!("HOL Guard {outcome} under the installed policy's {setting}."),
    )
}

fn risk_label(risk: &str) -> &'static str {
    match risk {
        "local_secret_read" => "secret read",
        "credential_exfiltration" => "credential export",
        "data_flow_exfiltration" => "data export",
        "destructive_shell" => "destructive command",
        "encoded_execution" => "encoded execution",
        "network_egress" => "network access",
        "prompt_injection" => "prompt injection",
        "mcp_dangerous_tool" => "unreviewed MCP tool",
        "malicious_skill" => "malicious skill",
        "package_script" => "package script",
        "persistence" => "persistence",
        "guard_bypass" => "Guard bypass",
        "cloud_advisory" => "cloud advisory",
        "encoded_exfiltration" => "encoded export",
        "execution" => "command execution",
        "supply_chain" => "supply chain",
        "policy_bypass" => "policy bypass",
        _ => "risk",
    }
}
