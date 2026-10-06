use super::*;
use crate::directory::tests::{bytes, grant, input, row};
use crate::dispatch::Acknowledgement;
use std::time::Instant;
use zeroize::Zeroizing;

fn prepared() -> PreparedGoogleBusinessRequest {
    grant()
        .resolve_with(input(), |_, address| Ok(bytes(&row(address))))
        .unwrap()
        .prepare_business_request()
        .unwrap()
}
fn owned(input: &PreparedGoogleBusinessRequest) -> PreparedBusinessInputV1 {
    PreparedBusinessInputV1::prepare(
        &serde_json::to_vec(input.prepared_input().facts()).unwrap(),
        input.prepared_input().primary_bytes().to_vec(),
        vec![],
    )
    .unwrap()
}

#[test]
fn owned_send_budget_and_snapshot_cover_headers_and_original_api_json() {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use std::cell::Cell;

    // A tiny text body cannot hide a much larger header from the byte budget.
    let mime = format!(
        "From: sender@work.example\r\nTo: recipient@work.example\r\nSubject: {}\r\nContent-Type: text/plain\r\n\r\nx",
        "meeting agenda ".repeat(20)
    );
    let raw = Base64UrlUnpadded::encode_string(mime.as_bytes());
    let expected_json = format!("{{ \"raw\": \"{raw}\" }}").into_bytes();
    let command = format!(
        "gws gmail users messages send --params '{{\"userId\":\"me\"}}' --json '{}'",
        std::str::from_utf8(&expected_json).unwrap()
    );
    let inspected = crate::oauth::worker_input_tests::credential("subject-one")
        .prepare_command(command)
        .unwrap()
        .inspect_outbound()
        .unwrap();
    assert_eq!(inspected.input().input().body_bytes(), b"x");
    let input = grant()
        .resolve_with(inspected, |_, address| Ok(bytes(&row(address))))
        .unwrap()
        .prepare_business_request()
        .unwrap();
    let facts = input.prepared_input().facts();
    assert_eq!(facts.volume.byte_count, expected_json.len() as u64);
    assert_eq!(facts.content.inspected_bytes, expected_json.len() as u64);
    assert!(facts.volume.byte_count > 256);
    assert_eq!(
        PreparedBusinessInputV1::prepare(
            &serde_json::to_vec(facts).unwrap(),
            b"x".to_vec(),
            vec![]
        )
        .err(),
        Some(guard_command::business_input::PreparedBusinessInputErrorV1::ContentMismatch)
    );
    let frozen = owned(&input);
    let calls = Cell::new(0);
    let attempt = input
        .dispatch_with(frozen, |_, transmitted| {
            calls.set(calls.get() + 1);
            assert_eq!(transmitted, expected_json);
            Ok(RawSendAttempt::Unconfirmed)
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(attempt, GoogleSendAttempt::Unconfirmed);
}

#[test]
fn ownership_boundary_preserves_frozen_json_and_fingerprints_private_response() {
    let input = prepared();
    let frozen = owned(&input);
    let body = frozen.primary_bytes().to_vec();
    let expected = crate::binding(
        &input.resolved.directory.namespace_key,
        b"hol-guard.google-send-acknowledgement.v1\0",
        &[
            input
                .prepared_input()
                .facts()
                .provider
                .account_binding
                .as_deref()
                .unwrap(),
            "synthetic-id",
            "synthetic-thread",
        ],
    );
    let attempt = input
        .dispatch_with(frozen, |_, bytes| {
            assert_eq!(bytes, body);
            Ok(RawSendAttempt::Accepted(Acknowledgement {
                id: Zeroizing::new("synthetic-id".into()),
                thread_id: Zeroizing::new("synthetic-thread".into()),
            }))
        })
        .unwrap();
    assert_eq!(
        attempt,
        GoogleSendAttempt::ApiAccepted {
            message_binding: expected
        }
    );
}

#[test]
fn changed_owned_snapshot_and_expired_resolution_cannot_enter_transport() {
    let input = prepared();
    let mut facts = input.prepared_input().facts().clone();
    facts.provider.account_binding = Some("1".repeat(64));
    let changed = PreparedBusinessInputV1::prepare(
        &serde_json::to_vec(&facts).unwrap(),
        input.prepared_input().primary_bytes().to_vec(),
        vec![],
    )
    .unwrap();
    let never = |_, _: &[u8]| -> Result<RawSendAttempt, GoogleDispatchError> {
        panic!("no effect permitted");
    };
    assert_eq!(
        input.dispatch_with(changed, never),
        Err(GoogleDispatchError::InputChanged)
    );
    let mut input = prepared();
    let frozen = owned(&input);
    input.resolved.deadline = Instant::now();
    assert_eq!(
        input.dispatch_with(frozen, never),
        Err(GoogleDispatchError::Expired)
    );
}
