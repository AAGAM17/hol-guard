//! Non-consuming saved-decision read over several probe groups.
//!
//! A group is one artifact hash with its candidate ids (direct, exact-command,
//! then memory-pattern). Every candidate is probed through the
//! `policy_decision_lookup` engine on one store connection with the portable
//! Git-workspace composition; the candidates of a group compose most
//! restrictive, and across groups a strictly more severe decision replaces the
//! earlier one. Nothing here consumes a one-shot approval or writes the store.

use guard_contracts::{PolicyDecisionLookupRequestV1, PolicyLookupProbeGroupsV1};
use serde_json::{json, Value};

use crate::context_digest::python_strip;
use crate::mcp_tool_policy_lookup::{most_restrictive, severity, without_permission_elevation};
use crate::policy_decision_lookup_op::{evaluate_non_consuming, open_lookup_connection};

const ERR_INVALID: &str = "native_policy_decision_lookup_invalid";
const MAX_GROUPS: usize = 4;
const MAX_CANDIDATES: usize = 8;

fn field<'a>(lookup: &'a Value, key: &str) -> &'a Value {
    lookup.get(key).unwrap_or(&Value::Null)
}

pub(crate) fn evaluate(
    request: &PolicyDecisionLookupRequestV1,
    groups: &PolicyLookupProbeGroupsV1,
) -> Result<Value, String> {
    if request.consume_one_shot || request.local_once_only {
        return Err(ERR_INVALID.to_owned());
    }
    let connection = open_lookup_connection(&request.store_path)?;
    compose_groups(
        groups,
        request.workspace.as_deref(),
        |artifact_id, artifact_hash, workspace| {
            let mut probe = request.clone();
            probe.probe_groups = None;
            probe.artifact_id = Some(artifact_id.to_owned());
            probe.artifact_hash = Some(artifact_hash.to_owned());
            probe.workspace = workspace.map(str::to_owned);
            evaluate_non_consuming(&probe, &connection)
        },
    )
}

/// Probe every group and return `{decision, ignored_local_integrity}`.
pub(crate) fn compose_groups<F>(
    groups: &PolicyLookupProbeGroupsV1,
    workspace: Option<&str>,
    mut probe: F,
) -> Result<Value, String>
where
    F: FnMut(&str, &str, Option<&str>) -> Result<Value, String>,
{
    if groups.groups.is_empty() || groups.groups.len() > MAX_GROUPS {
        return Err(ERR_INVALID.to_owned());
    }
    let portable = groups.portable_workspace.as_deref();
    let mut composed = Vec::with_capacity(groups.groups.len());
    for group in &groups.groups {
        let ids = &group.candidate_artifact_ids;
        if ids.is_empty() || ids.len() > MAX_CANDIDATES {
            return Err(ERR_INVALID.to_owned());
        }
        let mut lookups = Vec::with_capacity(ids.len());
        for id in ids {
            let mut probe_at = |at: Option<&str>| probe(id, &group.artifact_hash, at);
            let lookup = candidate(portable, workspace, &mut probe_at)?;
            let disabled = lookups.is_empty() && remembered_rules_disabled(&lookup);
            lookups.push(lookup);
            if disabled {
                // A home that serves no authority: the remembered-decision
                // probes cannot change the answer.
                break;
            }
        }
        composed.push(most_restrictive(&lookups).ok_or(ERR_INVALID)?);
    }
    Ok(most_severe_group(&composed))
}

/// The empty answer of a home that serves no authority.
fn remembered_rules_disabled(lookup: &Value) -> bool {
    field(lookup, "decision").is_null()
        && field(lookup, "authority_revision") == &json!(-1)
        && field(lookup, "trust_status").get("remembered_rules")
            == Some(&json!("disabled_degraded"))
}

/// One candidate, with the portable Git-workspace authority composed in.
fn candidate(
    portable: Option<&str>,
    workspace: Option<&str>,
    probe: &mut dyn FnMut(Option<&str>) -> Result<Value, String>,
) -> Result<Value, String> {
    let Some(portable) = portable else {
        return probe(workspace);
    };
    let preview = without_permission_elevation(probe(Some(portable))?);
    if workspace.map(python_strip) == Some(portable) {
        return Ok(preview);
    }
    let local = probe(workspace)?;
    most_restrictive(&[local, preview]).ok_or_else(|| ERR_INVALID.to_owned())
}

/// Across groups a strictly more severe decision wins and brings its own
/// integrity evidence; otherwise the first integrity evidence seen is kept.
fn most_severe_group(groups: &[Value]) -> Value {
    let Some(first) = groups.first() else {
        return json!({"decision": null, "ignored_local_integrity": null});
    };
    let mut decision = field(first, "decision").clone();
    let mut ignored = field(first, "ignored_local_integrity").clone();
    for group in &groups[1..] {
        if ignored.is_null() {
            ignored = field(group, "ignored_local_integrity").clone();
        }
        let next = field(group, "decision");
        if !next.is_null()
            && (decision.is_null()
                || severity(next.get("action")) > severity(decision.get("action")))
        {
            decision = next.clone();
            ignored = field(group, "ignored_local_integrity").clone();
        }
    }
    json!({"decision": decision, "ignored_local_integrity": ignored})
}

#[cfg(test)]
#[path = "policy_lookup_groups_tests.rs"]
mod tests;
