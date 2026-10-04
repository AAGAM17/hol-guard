//! Native business floors. Hook arguments are never authenticated business facts.

#[cfg(test)]
#[path = "policy_enforcement_business_tests.rs"]
mod tests;

use super::{ActionFloor, AdmittedPolicySnapshot};
use guard_contracts::{BusinessActionV1, PreToolActionTypeV1, PreToolResultV1};
use guard_policy_snapshot::business_policy::BusinessPolicyBindingV1;
use serde_json::Value;

#[derive(Debug)]
pub(super) struct CompiledBusinessPolicy {
    binding: BusinessPolicyBindingV1,
    default_action: ActionFloor,
    actions: Vec<ActionFloor>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct BusinessFloor {
    pub(super) action: ActionFloor,
    pub(super) matched_rule_ids: Vec<String>,
}

impl CompiledBusinessPolicy {
    pub(super) fn new(binding: &BusinessPolicyBindingV1) -> Result<Self, String> {
        binding
            .validate()
            .map_err(|_| "native_business_policy_invalid".to_owned())?;
        let actions = binding
            .rules
            .iter()
            .map(|rule| {
                ActionFloor::parse(&rule.action)
                    .ok_or_else(|| "native_business_policy_invalid".to_owned())
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            binding: binding.clone(),
            default_action: ActionFloor::parse(&binding.default_action)
                .ok_or_else(|| "native_business_policy_invalid".to_owned())?,
            actions,
        })
    }

    // Facts here must eventually come from an authenticated native producer.
    // The ordinary hook path below deliberately supplies None, even if the
    // caller provides a complete-looking business_action object.
    pub(super) fn floor(
        &self,
        intrinsic: ActionFloor,
        facts: Option<&BusinessActionV1>,
    ) -> BusinessFloor {
        let blocked = || BusinessFloor {
            action: ActionFloor::Block,
            matched_rule_ids: Vec::new(),
        };
        let Some(facts) = facts else {
            return blocked();
        };
        if facts.require_complete_facts().is_err() {
            return blocked();
        }
        let mut action = intrinsic;
        let mut matched_rule_ids = Vec::new();
        for (rule, rule_action) in self.binding.rules.iter().zip(&self.actions) {
            match rule.selector.matches(facts) {
                Ok(true) => {
                    action = action.max(*rule_action);
                    matched_rule_ids.push(rule.id.clone());
                }
                Ok(false) => {}
                Err(_) => return blocked(),
            }
        }
        if matched_rule_ids.is_empty() {
            action = action.max(self.default_action);
        }
        matched_rule_ids.sort_unstable();
        BusinessFloor {
            action,
            matched_rule_ids,
        }
    }
}

fn requires_business_context(
    payload: &Value,
    action_type: PreToolActionTypeV1,
) -> Result<bool, String> {
    let Some(root) = payload.as_object() else {
        return Ok(false);
    };
    let mut envelopes = vec![root];
    for key in ["tool_call", "toolCall", "preToolUse", "pre_tool_use"] {
        if let Some(record) = root.get(key).and_then(Value::as_object) {
            envelopes.push(record);
        }
    }
    for record in &envelopes {
        if record.contains_key("business_action") || record.contains_key("businessAction") {
            return Ok(true);
        }
    }
    if !matches!(
        action_type,
        PreToolActionTypeV1::Command
            | PreToolActionTypeV1::ProcessService
            | PreToolActionTypeV1::Network
            | PreToolActionTypeV1::Browser
            | PreToolActionTypeV1::Unknown
    ) {
        return Ok(false);
    }
    let mut command_records = envelopes.clone();
    for record in &envelopes {
        for key in [
            "tool_input",
            "toolInput",
            "input",
            "arguments",
            "parameters",
        ] {
            if let Some(input) = record.get(key).and_then(Value::as_object) {
                command_records.push(input);
            }
        }
    }
    for record in command_records {
        // Recognize only native parsed CLI programs, including parser-expanded
        // wrappers/segments. This is not a promise to cover renamed binaries,
        // arbitrary HTTP clients, opaque MCP traffic or remote connectors.
        for key in ["command", "command_line", "commandLine", "cmd"] {
            let Some(command) = record.get(key).and_then(Value::as_str) else {
                continue;
            };
            if command.len() > guard_command::MAX_COMMAND_BYTES {
                return Err("native_business_command_unavailable".to_owned());
            }
            let request = guard_command::CommandModelRequestV1 {
                command: command.to_owned(),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "native-business-context-v1".into(),
            };
            let parsed = guard_command::parse_command(&request)
                .map_err(|_| "native_business_command_unavailable".to_owned())?;
            // An unresolved wrapper or expansion cannot prove that execution
            // stays outside business operations. Fail closed in this opt-in
            // lane, including uncertain commands that appear unrelated.
            if parsed.confidence != "exact" {
                return Ok(true);
            }
            if parsed
                .segments
                .iter()
                .filter_map(|segment| segment.executable.as_deref())
                .any(|program| {
                    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
                    matches!(
                        basename.to_ascii_lowercase().as_str(),
                        "gws" | "gws.exe" | "gog" | "gog.exe"
                    )
                })
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(super) fn guard_untrusted_business_context(
    snapshot: &AdmittedPolicySnapshot,
    payload: &Value,
    result: &mut PreToolResultV1,
) -> Result<(), String> {
    let Some(policy) = &snapshot.business_policy else {
        return Ok(());
    };
    if !requires_business_context(payload, result.action.action_type)? {
        return Ok(());
    }
    let intrinsic = ActionFloor::parse(&result.minimum_action)
        .ok_or_else(|| "native_policy_action_invalid".to_owned())?;
    let floor = policy.floor(intrinsic, None);
    if floor.action > intrinsic {
        result.reason_code = "native_business_context_unavailable".into();
        result.reason = "HOL Guard requires authenticated account, audience and content facts for this business operation.".into();
    }
    result.minimum_action = "block".into();
    result.policy_action = "block".into();
    result.decision = "deny".into();
    result.explicitly_benign = false;
    Ok(())
}
