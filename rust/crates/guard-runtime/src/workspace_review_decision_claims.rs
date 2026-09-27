use std::path::Path;

use super::VerifiedWorkspaceReviewDecision;

pub(super) fn consume_or_replay_claim(
    state_base: &Path,
    state: &mut super::super::workspace_review_secure_state::WorkspaceReviewSecureStateV1,
    verified: &VerifiedWorkspaceReviewDecision,
    semantic_digest: &str,
) -> Result<bool, String> {
    let claim_index = state
        .consumed_claims
        .iter()
        .position(|claim| claim.claim_id == verified.claim_id);
    if let Some(index) = claim_index {
        let claim = &state.consumed_claims[index];
        if claim.semantic_decision_digest.as_deref() == Some(semantic_digest) {
            if !claim.legacy_semantic_recovered || claim.envelope_digest == verified.envelope_digest
            {
                return Ok(true);
            }
        } else if claim.semantic_decision_digest.is_none()
            && claim.envelope_digest == verified.envelope_digest
        {
            state.consumed_claims[index].semantic_decision_digest =
                Some(semantic_digest.to_owned());
            state.consumed_claims[index].legacy_semantic_recovered = true;
            state.validate()?;
            super::super::workspace_review_secure_state::store(state_base, state)?;
            return Ok(true);
        }
        return Err("native_workspace_review_decision_replay".to_owned());
    }
    if state
        .consumed_claims
        .iter()
        .any(|claim| claim.semantic_decision_digest.as_deref() == Some(semantic_digest))
        || state
            .consumed_claims
            .iter()
            .any(|claim| claim.semantic_decision_digest.is_none())
    {
        return Err("native_workspace_review_decision_replay".to_owned());
    }
    Ok(false)
}
