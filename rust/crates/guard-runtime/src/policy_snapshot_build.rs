//! Publisher-owned construction only; no state access, installation or grant.
#![forbid(unsafe_code)]

use guard_contracts::NativeCommandControlBindingV1;
use guard_policy_snapshot::{
    business_policy::BusinessPolicyBindingV1, config_digest, integrity_mac, policy_digest,
    snapshot_bytes, validate_v3, verifier_key_id, EffectiveNativePolicyV3, PolicySnapshotV3,
    ScopeContractV3, SnapshotIntegrityV3, POLICY_SNAPSHOT_INTEGRITY_ALGORITHM,
    POLICY_SNAPSHOT_MAX_BYTES, POLICY_SNAPSHOT_PROTOCOL_VERSION, POLICY_SNAPSHOT_SCHEMA,
    POLICY_SNAPSHOT_VERSION,
};
use serde::Deserialize;
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

const ERROR: &str = "native_policy_snapshot_build_invalid";
const SCHEMA: &str = "guard-native-policy-build.v1";

// Neither key nor request can be serialized, cloned or formatted for logging.
#[derive(Deserialize)]
struct PublisherKey([u8; 32]);

impl Drop for PublisherKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRequest {
    schema: String,
    version: u16,
    verifier_key: PublisherKey,
    generation: u64,
    runtime_identity: String,
    rule_digest: String,
    mode: String,
    scope_contract: ScopeContractV3,
    effective_policy: EffectiveNativePolicyV3,
    #[serde(default)]
    command_extensions: Option<NativeCommandControlBindingV1>,
    #[serde(default, deserialize_with = "present_business_binding")]
    business_policy: Option<BusinessPolicyBindingV1>,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

fn present_business_binding<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BusinessPolicyBindingV1>, D::Error> {
    BusinessPolicyBindingV1::deserialize(deserializer).map(Some)
}

pub(crate) fn build_from_reader(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(POLICY_SNAPSHOT_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ERROR.to_owned())?;
    if bytes.len() > POLICY_SNAPSHOT_MAX_BYTES {
        return Err(ERROR.into());
    }
    let request: BuildRequest = serde_json::from_slice(&bytes).map_err(|_| ERROR.to_owned())?;
    if request.schema != SCHEMA || request.version != 1 {
        return Err(ERROR.into());
    }
    let mut snapshot = PolicySnapshotV3 {
        schema: POLICY_SNAPSHOT_SCHEMA.into(),
        version: POLICY_SNAPSHOT_VERSION,
        protocol_version: POLICY_SNAPSHOT_PROTOCOL_VERSION,
        generation: request.generation,
        runtime_identity: request.runtime_identity,
        rule_digest: request.rule_digest,
        mode: request.mode,
        scope_contract: request.scope_contract,
        effective_policy: request.effective_policy,
        command_extensions: request.command_extensions,
        business_policy: request.business_policy,
        issued_at_ms: request.issued_at_ms,
        expires_at_ms: request.expires_at_ms,
        config_digest: String::new(),
        policy_digest: String::new(),
        integrity: SnapshotIntegrityV3 {
            algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
            key_id: verifier_key_id(&request.verifier_key.0),
            mac: "0".repeat(64),
        },
    };
    snapshot.config_digest =
        config_digest(&snapshot.effective_policy).map_err(|_| ERROR.to_owned())?;
    snapshot.policy_digest = policy_digest(&snapshot).map_err(|_| ERROR.to_owned())?;
    // Bound the complete output with the fixed-size MAC before signing it.
    snapshot_bytes(&snapshot).map_err(|_| ERROR.to_owned())?;
    snapshot.integrity.mac =
        integrity_mac(&snapshot, &request.verifier_key.0).map_err(|_| ERROR.to_owned())?;
    validate_v3(
        &snapshot,
        request.generation,
        &snapshot.runtime_identity,
        &snapshot.rule_digest,
        &request.verifier_key.0,
        request.issued_at_ms,
    )
    .map_err(|_| ERROR.to_owned())?;
    snapshot_bytes(&snapshot).map_err(|_| ERROR.to_owned())
}

#[cfg(test)]
#[path = "policy_snapshot_build_tests.rs"]
mod tests;
