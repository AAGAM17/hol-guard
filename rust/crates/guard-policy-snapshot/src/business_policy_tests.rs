use super::*;
use business_policy::{BusinessPolicyBindingV1, BUSINESS_POLICY_BINDING_SCHEMA};
use serde_json::{json, Value};

fn binding_value() -> Value {
    json!({"schema": BUSINESS_POLICY_BINDING_SCHEMA, "version": 1,
        "defaultAction": "allow", "rules": [{"id": "mail.external", "action": "block",
        "match": {"schema": "guard.business-policy-match.v1", "version": 1,
            "services": ["google_gmail"], "operations": ["mail_send"]}}]})
}

fn binding() -> BusinessPolicyBindingV1 {
    serde_json::from_value(binding_value()).unwrap()
}

fn signed_business_snapshot() -> PolicySnapshotV3 {
    let mut value = tests::snapshot(1, &[7; 32]);
    value.business_policy = Some(binding());
    value.policy_digest = policy_digest(&value).unwrap();
    value.integrity.mac = integrity_mac(&value, &[7; 32]).unwrap();
    value
}

#[test]
fn business_binding_is_signed_and_changes_semantic_policy_identity() {
    let legacy = tests::snapshot(1, &[7; 32]);
    let business = signed_business_snapshot();
    assert_ne!(business.policy_digest, legacy.policy_digest);
    assert_ne!(business.integrity.mac, legacy.integrity.mac);
    assert!(validate_v3(
        &business,
        1,
        &"a".repeat(64),
        &"b".repeat(64),
        &[7; 32],
        200
    )
    .is_ok());
    for (field, patch) in [("defaultAction", json!("review")), ("rules", json!([]))] {
        let mut tampered = serde_json::to_value(&business).unwrap();
        tampered["business_policy"][field] = patch;
        let mut tampered: PolicySnapshotV3 = serde_json::from_value(tampered).unwrap();
        assert_eq!(
            validate_v3(
                &tampered,
                1,
                &"a".repeat(64),
                &"b".repeat(64),
                &[7; 32],
                200
            ),
            Err(SnapshotError::DigestMismatch)
        );
        tampered.policy_digest = policy_digest(&tampered).unwrap();
        assert_eq!(
            validate_v3(
                &tampered,
                1,
                &"a".repeat(64),
                &"b".repeat(64),
                &[7; 32],
                200
            ),
            Err(SnapshotError::IntegrityMismatch)
        );
    }
}

#[test]
fn explicit_null_unknown_and_duplicate_binding_fields_never_remove_rules() {
    let mut value = serde_json::to_value(tests::snapshot(1, &[7; 32])).unwrap();
    value["business_policy"] = Value::Null;
    assert!(serde_json::from_value::<PolicySnapshotV3>(value).is_err());
    for (field, patch) in [
        ("ignored", json!(true)),
        ("defaultAction", Value::Null),
        ("rules", Value::Null),
    ] {
        let mut value = binding_value();
        value[field] = patch;
        assert!(serde_json::from_value::<BusinessPolicyBindingV1>(value).is_err());
    }
    let duplicate = format!("{{\"schema\":\"{BUSINESS_POLICY_BINDING_SCHEMA}\",\"version\":1,\"defaultAction\":\"allow\",\"defaultAction\":\"block\",\"rules\":[]}}");
    assert!(serde_json::from_str::<BusinessPolicyBindingV1>(&duplicate).is_err());
    let mut value = binding_value();
    value["rules"][0]["ignored"] = json!(true);
    assert!(serde_json::from_value::<BusinessPolicyBindingV1>(value).is_err());
}

#[test]
fn malformed_versions_actions_ids_selectors_and_rule_limits_are_rejected() {
    for (field, patch) in [
        ("schema", json!("guard.native-business-policy.v2")),
        ("version", json!(2)),
        ("defaultAction", json!("ask")),
    ] {
        let mut value = binding_value();
        value[field] = patch;
        assert_eq!(
            serde_json::from_value::<BusinessPolicyBindingV1>(value)
                .unwrap()
                .validate(),
            Err(SnapshotError::Policy)
        );
    }
    for (field, patch) in [
        ("id", json!("raw@example.test")),
        ("action", json!("ask")),
        (
            "match",
            json!({"schema":"guard.business-policy-match.v1","version":1,"services":[],"operations":[]}),
        ),
    ] {
        let mut value = binding_value();
        value["rules"][0][field] = patch;
        assert_eq!(
            serde_json::from_value::<BusinessPolicyBindingV1>(value)
                .unwrap()
                .validate(),
            Err(SnapshotError::Policy)
        );
    }
    let mut duplicate = binding();
    duplicate.rules.push(duplicate.rules[0].clone());
    assert_eq!(duplicate.validate(), Err(SnapshotError::Policy));
    let mut excessive = binding();
    excessive.rules = (0..=POLICY_SNAPSHOT_MAX_MAP_ENTRIES)
        .map(|n| {
            let mut rule = binding().rules.remove(0);
            rule.id = format!("rule.{n}");
            rule
        })
        .collect();
    assert_eq!(excessive.validate(), Err(SnapshotError::Policy));
}

// Frozen pre-business v3 wire reader. It deliberately has no business field;
// accepting a new snapshot by discarding that field would widen its policy.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySnapshotV3 {
    schema: String,
    version: u16,
    generation: u64,
    policy_digest: String,
    config_digest: String,
    rule_digest: String,
    runtime_identity: String,
    protocol_version: u16,
    mode: String,
    scope_contract: ScopeContractV3,
    effective_policy: EffectiveNativePolicyV3,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command_extensions: Option<guard_contracts::NativeCommandControlBindingV1>,
    issued_at_ms: u64,
    expires_at_ms: u64,
    integrity: SnapshotIntegrityV3,
}

#[test]
fn absent_binding_keeps_legacy_wire_bytes_but_old_reader_rejects_present_binding() {
    let legacy = tests::snapshot(1, &[7; 32]);
    let bytes = snapshot_bytes(&legacy).unwrap();
    let old_reader: LegacySnapshotV3 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        canonical_json_bytes(&serde_json::to_value(old_reader).unwrap()).unwrap(),
        bytes
    );
    let restored: PolicySnapshotV3 = serde_json::from_slice(&bytes).unwrap();
    assert!(restored.business_policy.is_none());
    assert_eq!(restored.policy_digest, legacy.policy_digest);
    assert_eq!(restored.integrity.mac, legacy.integrity.mac);
    assert!(serde_json::from_slice::<LegacySnapshotV3>(
        &snapshot_bytes(&signed_business_snapshot()).unwrap()
    )
    .is_err());
}
