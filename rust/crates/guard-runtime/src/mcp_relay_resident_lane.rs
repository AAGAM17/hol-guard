//! The relay's direct-lane probe and the one retry a deferred call gets.
//!
//! The probe asks the resident's `mcp_relay_ready` whether the lane is bound
//! for the session's workspace and harness. A call the lane deferred for a
//! reason the daemon can clear asks the daemon to prepare the workspace once,
//! within the retry budget, and is decided once more; a deferral that remains
//! is refused as before. A deferred decision queues nothing, so the retry
//! never records a call twice.

use std::path::PathBuf;
use std::time::Instant;

use serde_json::{json, Value};

use super::{defer, ResidentRelayAuthority};
use crate::mcp_relay_lane::{kickable, Kick, LaneKick, RETRY_BUDGET};
use crate::mcp_relay_ready::MCP_RELAY_READY_SCHEMA;

impl ResidentRelayAuthority {
    /// Ask the daemon to prepare the lane for a deferred call.
    pub(crate) fn with_kick(mut self, kick: Box<dyn LaneKick>) -> Self {
        self.kick = Some(kick);
        self
    }

    /// The workspace the session's decisions are admitted under.
    pub(crate) fn lane_workspace(&self) -> Option<&str> {
        let facts = self.facts.as_ref()?;
        Some(facts.workspace.as_deref().unwrap_or(&facts.hash_workspace))
    }

    /// `Ok` when the resident's lane is ready for this session, else the
    /// lane's defer code or the reason the resident did not answer.
    pub(crate) fn lane_ready(&mut self, deadline: Instant) -> Result<(), String> {
        let Some(facts) = self.facts.as_ref() else {
            return Err(defer::FACTS_UNAVAILABLE.to_owned());
        };
        let payload = json!({
            "operation": "mcp_relay_ready",
            "request": {
                "guard_home": facts.guard_home,
                "workspace": facts.workspace.as_deref().unwrap_or(&facts.hash_workspace),
                "harness": facts.harness,
                "server": {
                    "harness": facts.harness,
                    "server_name": facts.server_name,
                    "source_scope": facts.source_scope,
                    "config_path": facts.config_path,
                    "server_id": facts.server_id,
                    "identity_hash": facts.server_identity.get("identity_hash"),
                },
            },
        });
        let guard_home = PathBuf::from(&facts.guard_home);
        let payload =
            serde_json::to_vec(&payload).map_err(|_| defer::REQUEST_UNSENDABLE.to_owned())?;
        let output = self
            .exchange_until(&guard_home, &payload, deadline)
            .ok_or_else(|| defer::RESIDENT_UNREACHABLE.to_owned())?;
        ready_answer(&output)
    }

    /// Whether a call deferred with `output` gets its one retry: the lane
    /// deferred it for a reason the daemon can clear, and the daemon took
    /// the request to prepare the workspace.
    pub(super) fn rekick(&mut self, output: Option<&[u8]>) -> bool {
        let Some(code) = output.and_then(defer::defer_code) else {
            return false;
        };
        let Some(kick) = self.kick.as_mut() else {
            return false;
        };
        kickable(&code) && kick.kick(Instant::now() + RETRY_BUDGET) == Kick::Requested
    }
}

/// The resident's readiness answer.
pub(super) fn ready_answer(output: &[u8]) -> Result<(), String> {
    let invalid = || defer::REPLY_INVALID.to_owned();
    let answer: Value = serde_json::from_slice(output).map_err(|_| invalid())?;
    if answer.get("schema").and_then(Value::as_str) != Some(MCP_RELAY_READY_SCHEMA) {
        return Err(invalid());
    }
    match answer.get("ready").and_then(Value::as_bool) {
        Some(true) => Ok(()),
        Some(false) => Err(answer
            .get("reason")
            .and_then(Value::as_str)
            .filter(|reason| defer::is_code(reason))
            .map_or_else(invalid, str::to_owned)),
        None => Err(invalid()),
    }
}

#[cfg(test)]
#[path = "mcp_relay_resident_lane_tests.rs"]
mod tests;
