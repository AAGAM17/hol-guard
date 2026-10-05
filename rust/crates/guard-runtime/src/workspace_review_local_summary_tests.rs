use super::*;

fn summary(fixture: &Fixture) -> Result<Value, String> {
    let request = json!({"operation":"workspace_review_local_summary",
        "request":{"request_id":"business-test"}});
    let response = crate::resident_ops::evaluate_resident_bytes(
        &canonical_json_bytes(&request).unwrap(),
        Some(&fixture.store),
    )?;
    serde_json::from_slice(&response).map_err(|_| "test_invalid_summary_response".into())
}

#[test]
fn resident_summary_omits_private_values_and_asserts_no_current_account_or_effect() {
    let fixture = Fixture::new("business-local-summary");
    let value = input(b"LOCAL_BODY_CANARY", &[b"LOCAL_ATTACHMENT_CANARY".to_vec()]);
    fixture.stage(&value);
    let response = summary(&fixture).unwrap();
    assert_eq!(response["service"], "google_gmail");
    assert_eq!(response["operation"], "mail_send");
    assert_eq!(response["recipient_count"], 1);
    assert_eq!(response["attachment_count"], 1);
    assert_eq!(response["account_currentness"], "not_asserted");
    assert_eq!(response["execution_state"], "not_checked");
    let encoded = response.to_string();
    for private in [
        "LOCAL_BODY_CANARY",
        "LOCAL_ATTACHMENT_CANARY",
        "example.test",
    ] {
        assert!(!encoded.contains(private));
    }
    for name in [
        "primary_base64",
        "attachments_base64",
        "account_binding",
        "tenant_binding",
        "recipients",
        "resource_binding",
        "revision_binding",
    ] {
        assert!(response.get(name).is_none());
    }
    assert!(fixture.load().is_ok());
    assert!(!fixture
        .root
        .join("workspace-review-business-attempts")
        .exists());
}

#[test]
fn changed_private_snapshot_refuses_summary_instead_of_exporting_unverified_facts() {
    let fixture = Fixture::new("business-local-summary-tamper");
    let value = input(b"ORIGINAL_LOCAL_BODY", &[]);
    fixture.stage(&value);
    assert!(summary(&fixture).is_ok());
    let mut changed = value.clone();
    changed["facts"]["volume"]["recipient_count"] = json!(200);
    write(&fixture.root, &fixture.input_path(&value), &changed);
    assert!(summary(&fixture).is_err());
}

#[test]
fn summary_obeys_transition_fence_and_rejects_caller_supplied_facts() {
    let fixture = Fixture::new("business-local-summary-fence");
    fixture.stage(&input(b"LOCAL_BODY", &[]));
    let result =
        super::super::super::approval_enrollment::with_transition_lock(&fixture.root, || {
            Ok(summary(&fixture))
        })
        .unwrap();
    assert_eq!(result.unwrap_err(), "native_approval_authority_busy");
    let forged = json!({"operation":"workspace_review_local_summary",
        "request":{"request_id":"business-test","recipient_count":0}});
    assert!(crate::resident_ops::evaluate_resident_bytes(
        &canonical_json_bytes(&forged).unwrap(),
        Some(&fixture.store)
    )
    .is_err());
}
