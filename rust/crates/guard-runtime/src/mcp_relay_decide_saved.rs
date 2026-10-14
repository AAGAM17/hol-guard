//! The saved lookups a relayed call names, read from the store snapshot.
//!
//! Each answer is the observation the proxy's effect returns
//! (`native_mcp_tool_policy.py`) for a non-consuming read:
//!
//! - `grant_lookup`: `resolve_policy_decision_lookup(harness, selector)`;
//! - `policy_lookup`: `resolve_policy_decision_lookup_with_memory_pattern`,
//!   the direct, exact-command and memory ids composed most restrictive, a
//!   miss diagnosed in the same answer;
//! - `reuse_diagnostic`: `approval_reuse_validation_reason`.
//!
//! The proxy composes each candidate with the portable Git identity of the
//! workspace, which the resident does not derive. It answers only when that
//! composition cannot change the result: no workspace row is bound anywhere
//! but this workspace, so the portable read sees exactly what a read under
//! any other identity sees, and that read neither outranks the local one nor
//! reports anything of its own. Every other answer defers the call.

use super::store::{Probe, Saved, STORE_UNREADABLE};
use super::POLICY_NEED;
use crate::context_digest::python_strip;
use crate::mcp_tool_policy_lookup::{most_restrictive, severity, without_permission_elevation};
use crate::memory_pattern::{verdict, MemoryRequest};
use crate::policy_decision_lookup_op::{evaluate_non_consuming, workspace_policy_key};
use guard_contracts::{ApprovalReuseDiagnosticRequestV1, APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA};
use rusqlite::OptionalExtension;
use serde_json::{json, Value};

const SAVED_LOOKUP: &str = "mcp_relay_saved_lookup_failed";
const SAVED_PORTABLE: &str = "mcp_relay_saved_portable_workspace";
const SAVED_DIAGNOSTIC: &str = "mcp_relay_saved_diagnostic_failed";
const PORTABLE_PREFIX: &str = "git-project:v1:";
/// A well-formed portable identity, read in place of the one the proxy would
/// derive; no row is bound to either once the workspace rows are confined.
const PROBE_PORTABLE: &str =
    "git-project:v1:0000000000000000000000000000000000000000000000000000000000000000";

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

/// A need field the proxy requires to be text.
fn text<'a>(need: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    need.get(key).and_then(Value::as_str).ok_or(POLICY_NEED)
}

/// A need field the proxy requires to be text or `None`.
fn optional<'a>(need: &'a Value, key: &str) -> Result<Option<&'a str>, &'static str> {
    match need.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(POLICY_NEED),
    }
}

impl Saved<'_> {
    /// The observation the proxy returns for `need`.
    pub(super) fn answer(&self, need: &Value) -> Result<Value, &'static str> {
        match need.get("kind").and_then(Value::as_str) {
            Some("grant_lookup") => {
                let lookup = self.probe(&Probe {
                    harness: text(need, "harness")?,
                    artifact_id: text(need, "selector")?,
                    artifact_hash: None,
                    workspace: None,
                    publisher: None,
                    exact_match_context: None,
                })?;
                Ok(json!({"decision": field(&lookup, "decision")}))
            }
            Some("policy_lookup") => self.policy_lookup(need),
            Some("reuse_diagnostic") => Ok(json!({"reason": self.diagnosis(need)?})),
            _ => Err(POLICY_NEED),
        }
    }

    fn policy_lookup(&self, need: &Value) -> Result<Value, &'static str> {
        let harness = text(need, "harness")?;
        let artifact_id = text(need, "artifact_id")?;
        let probe = Probe {
            harness,
            artifact_id,
            artifact_hash: Some(text(need, "artifact_hash")?),
            workspace: optional(need, "workspace")?,
            publisher: optional(need, "publisher")?,
            exact_match_context: optional(need, "runtime_exact_match_context")?,
        };
        let memory = verdict(&MemoryRequest {
            command: optional(need, "memory_command")?,
            artifact_type: optional(need, "memory_artifact_type")?,
            artifact_id: Some(artifact_id),
            artifact_name: optional(need, "memory_artifact_name")?,
            harness: Some(harness),
        });
        let portable = self.portable_composes(probe.workspace)?;
        let mut lookups = vec![self.candidate(&probe, portable)?];
        for id in memory
            .exact_artifact_ids
            .iter()
            .chain(memory.memory_artifact_id.iter())
        {
            let candidate = Probe {
                artifact_id: id,
                ..probe
            };
            lookups.push(self.candidate(&candidate, portable)?);
        }
        let composed = most_restrictive(&lookups).ok_or(SAVED_LOOKUP)?;
        let decision = field(&composed, "decision").clone();
        let ignored = !field(&composed, "ignored_local_integrity").is_null();
        let mut observed = json!({"decision": decision, "ignored_local_integrity": ignored});
        if observed["decision"].is_null() && !ignored {
            observed["reuse_diagnostic"] = json!({"reason": self.diagnosis(need)?});
        }
        Ok(observed)
    }

    /// One candidate as the proxy reads it: the local lookup, which the
    /// portable composition must leave as it is.
    fn candidate(&self, probe: &Probe<'_>, portable: bool) -> Result<Value, &'static str> {
        let local = self.probe(probe)?;
        if !portable {
            return Ok(local);
        }
        let preview = without_permission_elevation(self.probe(&Probe {
            workspace: Some(PROBE_PORTABLE),
            ..*probe
        })?);
        if !field(&preview, "ignored_local_integrity").is_null()
            || field(&preview, "authority_revision") != field(&local, "authority_revision")
        {
            return Err(SAVED_PORTABLE);
        }
        let shadow = field(&preview, "decision");
        let held = field(&local, "decision");
        if !shadow.is_null()
            && (held.is_null() || severity(shadow.get("action")) > severity(held.get("action")))
        {
            return Err(SAVED_PORTABLE);
        }
        Ok(local)
    }

    /// Whether the proxy may compose a portable identity for `workspace`
    /// (`_portable_project_workspace`), once no workspace row is bound to
    /// another workspace. A workspace that already names a portable identity
    /// reads only that identity, so it defers.
    fn portable_composes(&self, workspace: Option<&str>) -> Result<bool, &'static str> {
        let Some(workspace) = workspace.filter(|value| !python_strip(value).is_empty()) else {
            return Ok(false);
        };
        if python_strip(workspace).starts_with(PORTABLE_PREFIX) {
            return Err(SAVED_PORTABLE);
        }
        let key = workspace_policy_key(Some(workspace)).ok_or(SAVED_PORTABLE)?;
        let bound_elsewhere = |query: &str, values: &[&str]| {
            self.connection
                .query_row(
                    query,
                    rusqlite::params_from_iter(values.iter().copied()),
                    |_| Ok(()),
                )
                .optional()
                .map(|found| found.is_some())
                .map_err(|_| STORE_UNREADABLE)
        };
        if bound_elsewhere(
            "select 1 from policy_decisions where scope = 'workspace' \
             and workspace is not null and workspace not in (?1, ?2) limit 1",
            &[key.as_str(), workspace],
        )? || bound_elsewhere(
            "select 1 from guard_local_once_approvals \
             where workspace is not null and workspace <> ?1 limit 1",
            &[key.as_str()],
        )? {
            return Err(SAVED_PORTABLE);
        }
        Ok(true)
    }

    fn probe(&self, probe: &Probe<'_>) -> Result<Value, &'static str> {
        // A read the proxy would follow with an audit write fails here, on the
        // read-only snapshot, and defers the call.
        evaluate_non_consuming(&self.lookup_request(probe), self.connection)
            .map_err(|_| SAVED_LOOKUP)
    }

    /// `approval_reuse_diagnostic`'s reason: the first request carries no
    /// evidence, and the evidence the resident names follows.
    fn diagnosis(&self, need: &Value) -> Result<Value, &'static str> {
        let mut request = ApprovalReuseDiagnosticRequestV1 {
            schema: APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            store_path: self.store_path.clone(),
            guard_home: self.guard_home.clone(),
            harness: text(need, "harness")?.to_owned(),
            artifact_id: text(need, "artifact_id")?.to_owned(),
            artifact_hash: Some(text(need, "artifact_hash")?.to_owned()),
            workspace: optional(need, "workspace")?.map(str::to_owned),
            publisher: optional(need, "publisher")?.map(str::to_owned),
            now: self.now.clone(),
            evidence: None,
        };
        let diagnose = |request: &ApprovalReuseDiagnosticRequestV1| {
            crate::approval_reuse_diagnostic_op::diagnose(
                self.connection,
                request,
                self.now.clone(),
            )
            .map_err(|_| SAVED_DIAGNOSTIC)
        };
        let mut payload = diagnose(&request)?;
        if field(&payload, "need").as_str() == Some("integrity_evidence") {
            request.evidence = Some(self.diagnostic_evidence(
                field(&payload, "policy") == &Value::Bool(true),
                field(&payload, "local_once") == &Value::Bool(true),
            ));
            payload = diagnose(&request)?;
        }
        let shaped = payload.as_object().is_some_and(|fields| {
            fields.len() == 2 && fields.contains_key("reason") && fields.contains_key("stored_hash")
        });
        let (reason, stored) = (field(&payload, "reason"), field(&payload, "stored_hash"));
        if !shaped
            || !(reason.is_null() || reason.is_string())
            || !(stored.is_null() || stored.is_string())
        {
            return Err(SAVED_DIAGNOSTIC);
        }
        Ok(reason.clone())
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_saved_tests.rs"]
mod tests;
