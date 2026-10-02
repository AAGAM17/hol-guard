use std::path::Path;

use super::VerifiedWorkspaceReviewDecision;

pub(super) fn consume_or_replay_claim(
    state_base: &Path,
    state: &mut super::super::workspace_review_secure_state::WorkspaceReviewSecureStateV1,
    verified: &VerifiedWorkspaceReviewDecision,
    semantic_digest: &str,
) -> Result<bool, String> {
    if let Some(index) = state.claim_index.as_ref() {
        if let Some(claim) = super::super::workspace_review_claim_index::find_claim(
            state_base,
            index,
            &verified.claim_id,
        )? {
            if claim.semantic_decision_digest.as_deref() == Some(semantic_digest)
                && (!claim.legacy_semantic_recovered
                    || claim.envelope_digest == verified.envelope_digest)
            {
                if super::super::workspace_review_claim_index::find_semantic(
                    state_base,
                    index,
                    semantic_digest,
                )?
                .as_ref()
                    != Some(&claim)
                {
                    return Err("native_workspace_review_claim_index_invalid".to_owned());
                }
                return Ok(true);
            }

            return Err("native_workspace_review_decision_replay".to_owned());
        }
        if super::super::workspace_review_claim_index::find_semantic(
            state_base,
            index,
            semantic_digest,
        )?
        .is_some()
        {
            return Err("native_workspace_review_decision_replay".to_owned());
        }
    }
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
    // A legacy claim that predates semantic digests has
    // `semantic_decision_digest: None`. Replaying it is still blocked by its
    // claim_id tombstone above (lines 45-67), so an un-backfilled legacy entry
    // must NOT reject a *new* claim_id: a new claim_id cannot be a semantic
    // replay of a claim we cannot yet name. Rejecting on `is_none()` here
    // permanently wedged pre-index installs whose original envelope was gone.
    if state
        .consumed_claims
        .iter()
        .any(|claim| claim.semantic_decision_digest.as_deref() == Some(semantic_digest))
    {
        return Err("native_workspace_review_decision_replay".to_owned());
    }
    Ok(false)
}
