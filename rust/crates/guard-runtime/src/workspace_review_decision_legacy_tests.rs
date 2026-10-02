use super::renewal_tests::{context, setup, signed_envelope};
use super::{semantic_decision_digest, verify_and_claim_at};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use std::fs;

const NOW_MS: u64 = 2_000;

#[test]
fn legacy_history_rejects_fresh_claim_and_backfills_semantics_on_exact_replay() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let first = signed_envelope(
        &authority,
        &context,
        8,
        NOW_MS,
        NOW_MS + 500,
        "allow",
        &super::renewal_tests::REVIEW_SEED,
    );
    let envelope_digest =
        digest_bytes(&canonical_json_bytes(&serde_json::to_value(&first).unwrap()).unwrap());
    let mut state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    state.consumed_claims.push(
        super::super::workspace_review_secure_state::WorkspaceReviewClaimV1 {
            claim_id: first.claim_id.clone(),
            envelope_digest,
            semantic_decision_digest: None,
            legacy_semantic_recovered: false,
            expires_at_ms: None,
        },
    );
    super::super::workspace_review_secure_state::store(&root, &state).unwrap();

    let fresh = signed_envelope(
        &authority,
        &context,
        9,
        NOW_MS,
        NOW_MS + 500,
        "deny",
        &super::renewal_tests::REVIEW_SEED,
    );
    // An un-backfilled legacy entry conservatively blocks fresh claim IDs
    // until the original envelope can recover its semantic digest.
    assert_eq!(
        verify_and_claim_at(&root, &fresh, &context, NOW_MS)
            .err()
            .as_deref(),
        Some("native_workspace_review_decision_replay")
    );
    assert!(
        verify_and_claim_at(&root, &first, &context, NOW_MS)
            .unwrap()
            .replayed
    );
    let state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(
        state.consumed_claims[0].semantic_decision_digest,
        Some(semantic_decision_digest(&first).unwrap())
    );
    fs::remove_dir_all(root).unwrap();
}
