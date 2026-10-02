//! Mandatory policy floors for direct secret reads and incomplete local-code
//! inspection (`runtime/command_shell_read_factors.py`, 33 lines — verbatim).

use std::path::Path;

use crate::effect_decision::{
    DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction,
};
use crate::shell_secret_reads::assess_shell_reads;

/// `shell_read_floor_factors` (:13-33). Review floors only — never execution
/// authorization or positive proof.
pub fn shell_read_floor_factors(
    command_text: &str,
    security_identity: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Vec<DecisionFactor> {
    let assessment = assess_shell_reads(command_text, cwd, home_dir);
    if !assessment.requires_review() {
        return Vec::new();
    }
    let reason_code = if !assessment.sensitive_paths.is_empty() {
        "critical.local-secret-read"
    } else {
        "critical.local-script-execution"
    };
    vec![DecisionFactor {
        source: DecisionFactorSource::Policy,
        reason_code: reason_code.to_owned(),
        basis: DecisionBasis {
            action_floor: GuardAction::RequireReapproval,
            proof_route: None,
        },
        segment_ref: None,
        operation_ref: Some(format!(
            "operation:{}",
            security_identity.rsplit(':').next().unwrap_or("")
        )),
        producer_ref: Some("runtime:shell-read-floors-v1".to_owned()),
        evidence_digest: None,
        assessment: None,
        proof: None,
    }]
}
