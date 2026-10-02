//! Native command/effect-composition evaluator.
//!
//! This is the `command_effect_decide` resident op that RTM-008 introduces. The
//! contract (request/response types, schemas, feature flag) lives in
//! `guard-contracts::command_effect`; this module owns the evaluator.
//!
//! The full factor/lattice/decision-plane port from Python's
//! `runtime/command_evaluation.py` lands incrementally behind this op. Until a
//! producer is ported, the evaluator fails closed with
//! `native_command_effect_unimplemented` rather than emit a partial
//! `CompositeCommandEvaluation` — callers keep their Python path until the op
//! returns `ok` for their request shape.

use guard_contracts::{
    CommandEffectRequestV1, CommandEffectResultV1, COMMAND_EFFECT_REQUEST_SCHEMA,
    COMMAND_EFFECT_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use super::context_digest_json::write_canonical_json_with_limit;


fn request_digest(request: &CommandEffectRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_command_effect_invalid")?;
    let mut canonical = Vec::with_capacity(512);
    write_canonical_json_with_limit(&material, &mut canonical, usize::MAX)?;
    Ok(digest_bytes(&canonical))
}

pub(crate) fn evaluate_command_effect_request(
    request: &CommandEffectRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != COMMAND_EFFECT_REQUEST_SCHEMA {
        return Err("native_command_effect_schema_mismatch".to_owned());
    }
    let request_sha256 = request_digest(request)?;
    let result = CommandEffectResultV1 {
        schema: COMMAND_EFFECT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "error".to_owned(),
        // Fail closed until the factor/lattice producers port: emit no partial
        // CompositeCommandEvaluation payload. Callers treat this code as
        // "native op not yet authoritative" and keep their Python path.
        code: "native_command_effect_unimplemented".to_owned(),
        payload: None,
    };
    crate::encode_response(&result)
}

/// CLI byte-path entry (`--stdin`). Kept for parity with the other ops'
/// `*_bytes` evaluators even though the resident dispatch uses the typed
/// request path; #[allow(dead_code)] until the one-shot flag is wired.
#[allow(dead_code)]
pub(crate) fn evaluate_command_effect_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: CommandEffectRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_command_effect_invalid_json".to_owned())?;
    evaluate_command_effect_request(&request)
}
