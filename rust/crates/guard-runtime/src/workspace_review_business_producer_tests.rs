use super::super::tests::{input, Fixture};
use super::*;
use guard_policy_snapshot::{integrity_mac, policy_digest};

#[test]
fn native_producer_materializes_authenticated_frozen_snapshot_without_exporting_body() {
    let fixture = Fixture::new("business-producer-owned");
    let value = input(b"private-source-body", &[]);
    let prepared = prepare(value).unwrap();
    persist_prepared_review(&fixture.store, "business-produced", &prepared, || true).unwrap();
    let loaded =
        super::super::super::workspace_review_request::load(&fixture.store, "business-produced")
            .unwrap();
    assert_eq!(loaded.business_input.unwrap().binding(), prepared.binding());
    let path = fixture
        .root
        .join("workspace-review-requests/business-produced.json");
    let state = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8(state.clone())
        .unwrap()
        .contains("private-source-body"));
    let mut value: Value = serde_json::from_slice(&state).unwrap();
    value["action"]["action_envelope"]["business_context"]["prepared_input_binding"] =
        json!("0".repeat(64));
    super::super::tests::write(&fixture.root, &path, &value);
    assert!(super::super::super::workspace_review_request::load(
        &fixture.store,
        "business-produced"
    )
    .is_err());
}

#[test]
fn produced_snapshot_enters_existing_owned_claim_once_without_legacy_retry() {
    let fixture = Fixture::new("business-producer-single-claim");
    let prepared = prepare(input(b"frozen-provider-body", &[])).unwrap();
    persist_prepared_review(&fixture.store, "business-test", &prepared, || true).unwrap();
    let decision = super::super::tests::owned_input_tests::owned_decision(&fixture);
    let bytes = canonical_json_bytes(&decision).unwrap();
    let (_, claimed) =
        super::super::super::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes,
        )
        .unwrap();
    assert_eq!(claimed.binding(), prepared.binding());
    assert_eq!(claimed.primary_bytes(), b"frozen-provider-body");
    assert!(
        super::super::super::workspace_review_decision::claim_owned_business_request(
            &fixture.store,
            "business-test",
            &bytes
        )
        .is_err()
    );
}

#[test]
fn stale_provider_evidence_and_default_off_policy_cannot_publish_a_review() {
    let fixture = Fixture::new("business-producer-stale");
    let prepared = prepare(input(b"body", &[])).unwrap();
    assert_eq!(
        persist_prepared_review(&fixture.store, "business-expired", &prepared, || false)
            .unwrap_err(),
        "native_business_resolution_expired"
    );
    assert!(!fixture
        .root
        .join("workspace-review-requests/business-expired.json")
        .exists());
    let mut snapshot = fixture.snapshot.clone();
    snapshot.generation += 1;
    snapshot.business_policy = None;
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &fixture.key).unwrap();
    fixture
        .store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
        .unwrap();
    assert!(
        persist_prepared_review(&fixture.store, "business-default-off", &prepared, || true)
            .is_err()
    );
    assert!(!fixture
        .root
        .join("workspace-review-requests/business-default-off.json")
        .exists());
}

#[test]
fn signed_business_block_floor_cannot_publish_a_review() {
    let fixture = Fixture::new("business-producer-unresolved");
    let prepared = prepare(input(b"body", &[])).unwrap();
    let mut snapshot = fixture.snapshot.clone();
    snapshot.generation += 1;
    let mut policy = serde_json::to_value(snapshot.business_policy.as_ref().unwrap()).unwrap();
    policy["rules"][0]["action"] = json!("block");
    snapshot.business_policy = Some(serde_json::from_value(policy).unwrap());
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &fixture.key).unwrap();
    fixture
        .store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
        .unwrap();
    assert_eq!(
        persist_prepared_review(&fixture.store, "business-unresolved", &prepared, || true)
            .unwrap_err(),
        "native_workspace_review_business_blocked"
    );
    assert!(!fixture
        .root
        .join("workspace-review-requests/business-unresolved.json")
        .exists());
}
