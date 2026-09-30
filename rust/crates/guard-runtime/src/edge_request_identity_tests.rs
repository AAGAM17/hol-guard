use super::*;

#[test]
fn pi_retry_identity_ignores_call_id_but_binds_arguments_and_session() {
    for harness in ["pi", "omp"] {
        let mut first = envelope(
            "PreToolUse",
            serde_json::json!({
                "tool_name": "eval",
                "tool_call_id": "first-call",
                "session_id": "session-one",
                "tool_input": {"code": "1 + 1", "tool_call_id": "argument-id"}
            }),
        );
        first.harness = harness.to_owned();
        let mut retry = first.clone();
        retry.raw_payload["tool_call_id"] = serde_json::json!("retry-call");
        assert_eq!(
            request_identity(&first).unwrap().1,
            request_identity(&retry).unwrap().1
        );
        for (field, value) in [
            ("session_id", serde_json::json!("session-two")),
            (
                "tool_input",
                serde_json::json!({"code": "2 + 2", "tool_call_id": "argument-id"}),
            ),
        ] {
            let mut changed = retry.clone();
            changed.raw_payload[field] = value;
            assert_ne!(
                request_identity(&first).unwrap().1,
                request_identity(&changed).unwrap().1
            );
        }
        retry.raw_payload["tool_input"]["tool_call_id"] = serde_json::json!("different-argument");
        assert_ne!(
            request_identity(&first).unwrap().1,
            request_identity(&retry).unwrap().1
        );
    }
}

#[test]
fn pi_retry_without_session_keeps_transport_identity() {
    for harness in ["pi", "omp"] {
        for session in [serde_json::Value::Null, serde_json::json!("")] {
            let mut first = envelope(
                "PreToolUse",
                serde_json::json!({
                    "tool_name": "eval", "tool_call_id": "first-call",
                    "tool_input": {"code": "1 + 1"}
                }),
            );
            first.harness = harness.to_owned();
            if !session.is_null() {
                first.raw_payload["session_id"] = session;
            }
            let mut retry = first.clone();
            retry.raw_payload["tool_call_id"] = serde_json::json!("retry-call");
            assert_ne!(
                request_identity(&first).unwrap().1,
                request_identity(&retry).unwrap().1
            );
        }
    }
}

#[test]
fn pi_retry_identity_matches_shared_python_fixture_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/fixtures/pi-retry-identity-vectors.json"
    )))
    .unwrap();
    for vector in vectors.as_array().unwrap() {
        let mut before = envelope("PreToolUse", vector["before"].clone());
        before.harness = vector["harness"].as_str().unwrap().to_owned();
        let mut after = before.clone();
        after.raw_payload = vector["after"].clone();
        assert_eq!(
            request_identity(&before).unwrap().1 == request_identity(&after).unwrap().1,
            vector["same_identity"].as_bool().unwrap(),
            "{}",
            vector["name"]
        );
    }
}
