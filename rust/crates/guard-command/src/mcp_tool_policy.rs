//! Current recommendation precedence over raw config, independent of saved approvals.
use crate::local_supply_chain::{default_risk_action, DEFAULT_SECURITY_LEVEL};
use crate::mcp_tool_risk::evaluate_tool_risk;
use guard_contracts::{
    most_restrictive_of, write_canonical_json_with_limit, write_json_string, GuardAction,
    McpToolApprovalContextRequestV1, McpToolPolicyRequestV1, McpToolPolicyResultV1,
    CONTEXT_COMPONENT_MAX_BYTES,
};
use serde_json::{Map, Value};

fn string<'a>(config: &'a Map<String, Value>, key: &str) -> &'a str {
    config.get(key).and_then(Value::as_str).unwrap_or("")
}
fn action<'a>(config: &'a Map<String, Value>, map: &str, key: &str) -> Option<&'a Value> {
    config.get(map)?.as_object()?.get(key)
}
fn normalize(value: Option<&str>) -> GuardAction {
    match value {
        Some("ask") => GuardAction::Review,
        Some(value) => GuardAction::from_canonical(value).unwrap_or(GuardAction::Review),
        None => GuardAction::Review,
    }
}

fn routine_browser(categories: &[String]) -> bool {
    let mut routine = false;
    for category in categories {
        match category.as_str() {
            "browser_navigation" | "browser_inspection" => routine = true,
            "browser_external_domain" => {}
            _ => return false,
        }
    }
    routine
}

fn configured_override<'a>(
    config: &'a Map<String, Value>,
    harness: &str,
    artifact_id: &str,
    publisher: Option<&str>,
) -> Option<&'a Value> {
    action(config, "artifact_actions", artifact_id)
        .or_else(|| publisher.and_then(|publisher| action(config, "publisher_actions", publisher)))
        .filter(|value| !value.is_null())
        .or_else(|| action(config, "harness_actions", harness).filter(|value| !value.is_null()))
}

fn configured_risk<'a>(config: &'a Map<String, Value>, harness: &str) -> Option<&'a Value> {
    config
        .get("harness_risk_actions")
        .and_then(Value::as_object)
        .and_then(|map| map.get(harness))
        .and_then(Value::as_object)
        .and_then(|map| map.get("mcp_dangerous_tool"))
        .or_else(|| action(config, "risk_actions", "mcp_dangerous_tool"))
}

fn risk_default(config: &Map<String, Value>) -> Option<&'static str> {
    let managed_locks_level = config
        .get("managed_locked_settings")
        .and_then(Value::as_array)
        .is_some_and(|settings| {
            settings
                .iter()
                .any(|setting| setting.as_str() == Some("security_level"))
        });
    default_risk_action(
        string(config, "security_level"),
        string(config, "protection_posture"),
        config
            .get("protection_posture_explicit")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        managed_locks_level,
        "mcp_dangerous_tool",
    )
}

/// Render historical approval policy bytes from borrowed inputs, without a policy DTO clone.
pub fn write_tool_policy_context(
    request: &McpToolApprovalContextRequestV1,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    const FIELDS: &[&str] = &[
        "artifact_override",
        "default_action",
        "effective_risk_action",
        "evaluator_policy_version",
        "managed_locked_settings",
        "managed_policy_hash",
        "managed_policy_status",
        "mode",
        "protection_posture",
        "protection_posture_explicit",
        "security_level",
    ];
    let config = &request.config;
    let posture_explicit = config
        .get("protection_posture_explicit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    out.push(b'{');
    let mut first = true;
    for key in FIELDS {
        if key.starts_with("protection_posture") && !posture_explicit {
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        write_json_string(key, out);
        out.push(b':');
        let value = match *key {
            "artifact_override" => configured_override(
                config,
                &request.harness,
                &request.artifact_id,
                request.publisher.as_deref(),
            ),
            "effective_risk_action" => {
                if let Some(value) = configured_risk(config, &request.harness) {
                    Some(value)
                } else if let Some(action) = risk_default(config) {
                    write_json_string(action, out);
                    continue;
                } else {
                    None
                }
            }
            "evaluator_policy_version" => {
                write_json_string("mcp-tool-call-evaluation-v5", out);
                continue;
            }
            _ => config.get(*key),
        };
        write_canonical_json_with_limit(
            value.unwrap_or(&Value::Null),
            out,
            CONTEXT_COMPONENT_MAX_BYTES,
            "native_context_component_invalid",
        )?;
    }
    out.push(b'}');
    if out.len() > CONTEXT_COMPONENT_MAX_BYTES {
        return Err("native_context_component_invalid");
    }
    Ok(())
}

pub fn evaluate_tool_policy(
    request: &McpToolPolicyRequestV1,
) -> Result<McpToolPolicyResultV1, &'static str> {
    let config = &request.config;
    let categories = evaluate_tool_risk(&request.artifact, &request.arguments)?;
    let configured_action = configured_override(
        config,
        &request.harness,
        &request.artifact_id,
        request.publisher.as_deref(),
    )
    .or_else(|| config.get("default_action"));
    let risk_override = configured_risk(config, &request.harness);
    let explicit = risk_override.filter(|value| !value.is_null());
    let posture_explicit = config
        .get("protection_posture_explicit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (raw_action, mut source, mut summary_code) = if categories.is_empty() {
        (Some("allow"), "heuristic", "no_risk")
    } else if explicit.is_none() && routine_browser(&categories) {
        (Some("allow"), "browser-routine", "risk")
    } else {
        let risk_action = match risk_override {
            Some(value) if value.is_null() => None,
            Some(value) => Some(value.as_str()),
            None => risk_default(config).map(Some),
        };
        if let Some(risk_action) = risk_action {
            if explicit.is_none()
                && !posture_explicit
                && string(config, "mode") == "prompt"
                && string(config, "security_level") == DEFAULT_SECURITY_LEVEL
            {
                (Some("review"), "risk-policy", "risk")
            } else {
                (risk_action, "policy", "risk")
            }
        } else {
            (
                Some(if string(config, "mode") == "prompt" {
                    "review"
                } else {
                    "block"
                }),
                "heuristic",
                "risk",
            )
        }
    };
    let effective = most_restrictive_of(
        normalize(raw_action),
        normalize(configured_action.and_then(Value::as_str)),
    );
    if Some(effective.as_str()) != raw_action {
        source = "policy";
        summary_code = "configuration_stricter";
    }
    Ok(McpToolPolicyResultV1 {
        action: effective.as_str().to_owned(),
        source: source.to_owned(),
        summary_code: summary_code.to_owned(),
        risk_categories: categories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_risk_retains_reapproval_except_prompt_review() {
        for (mode, expected) in [("block", "require-reapproval"), ("prompt", "review")] {
            let request: McpToolPolicyRequestV1 = serde_json::from_value(serde_json::json!({
                "artifact": {"name": "workspace:summarize", "command": "summarize", "metadata": {}},
                "arguments": {"cmd": "echo hi"},
                "config": {"mode": mode, "security_level": "balanced", "default_action": "allow"},
                "harness": "codex", "artifact_id": "policy-proof", "publisher": null,
            }))
            .unwrap();
            assert_eq!(evaluate_tool_policy(&request).unwrap().action, expected);
        }
    }
}
