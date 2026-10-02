//! Rust wire projection of `runtime/github_workflow_authorization.py`.
//!
//! The host issues/claims workflow capabilities in Python; the resident Rust
//! composition consumes only the evidence surface —
//! `github_workflow_authorization_evidence(authorization, command_identity)`
//! (:294). The wire row carries the sealed object's private fields; the
//! `sealed` flag reproduces the `_seal is not _AUTHORIZATION_SEAL` check so a
//! tampered host object can be marked unsealed on the wire.
//!
//! `len(receipt_sha256) != 64` (Python `len()` counts code points) is mirrored
//! with `chars().count()`.

use serde::{Deserialize, Serialize};

use crate::effect_decision::PositiveProof;
use crate::github_capability_interaction::GITHUB_MAINTENANCE_ACTION_CLASS;

/// `GitHubWorkflowAuthorization` wire row (:74-105): the four sealed
/// attributes plus a `sealed` flag standing in for the `_AUTHORIZATION_SEAL`
/// object-identity check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct GitHubWorkflowAuthorizationV1 {
    pub operation_identity: String,
    pub proof: PositiveProof,
    pub receipt_sha256: String,
    /// `true` iff the host object still carries the claim seal.
    pub sealed: bool,
}

/// `github_workflow_authorization_evidence` (:294). Returns
/// `(proof, action_class)` when the authorization binds `command_identity`.
pub fn github_workflow_authorization_evidence(
    authorization: Option<&GitHubWorkflowAuthorizationV1>,
    command_identity: &str,
) -> Option<(PositiveProof, &'static str)> {
    let authorization = authorization?;
    // `_seal is not _AUTHORIZATION_SEAL` → None.
    if !authorization.sealed {
        return None;
    }
    // `hmac.compare_digest(a, b)` — constant-time; equality is sufficient here
    // because Rust strings are already length-known and compare_digest degrades
    // to equality for str.
    if !hmac_compare_digest(&authorization.operation_identity, command_identity) {
        return None;
    }
    if authorization.receipt_sha256.chars().count() != 64 {
        return None;
    }
    Some((
        authorization.proof.clone(),
        *GITHUB_MAINTENANCE_ACTION_CLASS,
    ))
}

/// `hmac.compare_digest` for UTF-8 strings.
fn hmac_compare_digest(left: &str, right: &str) -> bool {
    let a = left.as_bytes();
    let b = right.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
