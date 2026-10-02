//! Rust port of `runtime/launch_identity_binding.py` — the launch-identity
//! drift evidence record.
//!
//! `observe_launch_identity_binding` (:209) pulls live environment/launch
//! material through `launch_identity_environment.py`, `approval_context.py`,
//! `command_tokens.shell_tokens`, `package_execution_context`, and
//! `command.redirects`/`embedded_commands` — a transitive env-model +
//! subprocess surface that has not been ported yet (RTM-016 dependency).
//! This module ports the observation half that is already pure:
//! `LaunchBindingDimension`, `RuleVersionBinding`, `LaunchBindingDimensionDigest`,
//! `LaunchIdentityBindingObservation` (`__post_init__`/`to_dict`/
//! `action_floor`/`can_issue_positive_proof`),
//! `changed_launch_binding_dimensions`, `_binding_digest`, `_dimension`,
//! `_framed_digest`, `_wrapper_identity_digest`.
//!
//! Error strings match Python `ValueError` messages verbatim.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::effect_decision::{maximum_action_floor, GuardAction, ProofRequirement, UncertaintyKind};

/// `LAUNCH_IDENTITY_BINDING_VERSION` (:34).
pub const LAUNCH_IDENTITY_BINDING_VERSION: &str = "1.0.0";

/// `LaunchBindingDimension` (:74).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchBindingDimension {
    CommandStructure,
    ExecutableObservation,
    LaunchEnvironmentObservation,
    RedirectionTargetObservation,
    WorkspaceLocation,
    RepositoryLocation,
    WorkingDirectoryLocation,
    PolicyAndRuleVersions,
    PackageContextObservation,
}

impl LaunchBindingDimension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandStructure => "command-structure",
            Self::ExecutableObservation => "executable-observation",
            Self::LaunchEnvironmentObservation => "launch-environment-observation",
            Self::RedirectionTargetObservation => "redirection-target-observation",
            Self::WorkspaceLocation => "workspace-location",
            Self::RepositoryLocation => "repository-location",
            Self::WorkingDirectoryLocation => "working-directory-location",
            Self::PolicyAndRuleVersions => "policy-and-rule-versions",
            Self::PackageContextObservation => "package-context-observation",
        }
    }

    /// Every dimension, in `as_str` sort order. `_REQUIRED_DIMENSIONS` (:86).
    pub const ALL: [LaunchBindingDimension; 9] = [
        Self::CommandStructure,
        Self::ExecutableObservation,
        Self::LaunchEnvironmentObservation,
        Self::PackageContextObservation,
        Self::PolicyAndRuleVersions,
        Self::RedirectionTargetObservation,
        Self::RepositoryLocation,
        Self::WorkingDirectoryLocation,
        Self::WorkspaceLocation,
    ];
}

/// `_MANDATORY_UNCERTAINTIES` (:38) — `{unknown-effect, unresolved-launch-identity}`.
const MANDATORY_UNCERTAINTIES: [UncertaintyKind; 2] = [
    UncertaintyKind::UnresolvedLaunchIdentity,
    UncertaintyKind::UnknownEffect,
];

/// `_CORE_REQUIREMENTS` (:193).
const CORE_REQUIREMENTS: [ProofRequirement; 10] = [
    ProofRequirement::OperationAndTargets,
    ProofRequirement::WorkspaceIdentity,
    ProofRequirement::RepositoryIdentity,
    ProofRequirement::WorkingDirectoryIdentity,
    ProofRequirement::ExecutableIdentity,
    ProofRequirement::LaunchChain,
    ProofRequirement::ConfigurationIdentity,
    ProofRequirement::ShellDataFlow,
    ProofRequirement::ParserConfidence,
    ProofRequirement::ExpectedEffects,
];

type ObservationResult<T> = Result<T, String>;

/// `RuleVersionBinding` (:89) — `(rule_id, version)` with `_REFERENCE` /
/// `_VERSION` fullmatch gates from `__post_init__`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RuleVersionBinding {
    pub rule_id: String,
    pub version: String,
}

impl RuleVersionBinding {
    /// `__post_init__` (:94).
    pub fn validate(&self) -> ObservationResult<()> {
        // `_REFERENCE` (:36): `[a-z][a-z0-9_-]*(?:[.:/][a-z0-9][a-z0-9_-]*)+`
        let reference_ok = regex::Regex::new(r"^[a-z][a-z0-9_-]*(?:[.:/][a-z0-9][a-z0-9_-]*)+$")
            .unwrap()
            .is_match(&self.rule_id);
        // `_VERSION` (:37): `[A-Za-z0-9][A-Za-z0-9._+-]{0,127}`
        let version_ok = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
            .unwrap()
            .is_match(&self.version);
        if !reference_ok || !version_ok {
            return Err("rule binding must use canonical identifiers".to_string());
        }
        Ok(())
    }
}

/// `LaunchBindingDimensionDigest` (:99).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LaunchBindingDimensionDigest {
    pub dimension: LaunchBindingDimension,
    pub digest: String,
}

impl LaunchBindingDimensionDigest {
    /// `__post_init__` (:104).
    pub fn validate(&self) -> ObservationResult<()> {
        if !is_sha256(&self.digest) {
            return Err("dimension digest must be a lowercase SHA-256 value".to_string());
        }
        Ok(())
    }
}

/// `LaunchIdentityBindingObservation` (:111). Construct via [`new`] so
/// `__post_init__` runs end-to-end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LaunchIdentityBindingObservation {
    pub binding_digest: String,
    pub dimensions: Vec<LaunchBindingDimensionDigest>,
    pub required_requirements: Vec<ProofRequirement>,
    pub unresolved_requirements: Vec<ProofRequirement>,
    pub uncertainties: Vec<UncertaintyKind>,
    pub schema_version: String,
}

impl LaunchIdentityBindingObservation {
    /// `LaunchIdentityBindingObservation(...)` → `__post_init__` (:122).
    pub fn new(
        binding_digest: String,
        dimensions: Vec<LaunchBindingDimensionDigest>,
        required_requirements: Vec<ProofRequirement>,
        unresolved_requirements: Vec<ProofRequirement>,
        uncertainties: Vec<UncertaintyKind>,
    ) -> ObservationResult<Self> {
        let observation = Self {
            binding_digest,
            dimensions,
            required_requirements,
            unresolved_requirements,
            uncertainties,
            schema_version: LAUNCH_IDENTITY_BINDING_VERSION.to_string(),
        };
        observation.validate()?;
        Ok(observation)
    }

    /// `__post_init__` (:122-168), same check order, same messages.
    pub fn validate(&self) -> ObservationResult<()> {
        if self.schema_version != LAUNCH_IDENTITY_BINDING_VERSION {
            return Err("unsupported launch binding observation version".to_string());
        }
        if !is_sha256(&self.binding_digest) {
            return Err("binding digest must be a lowercase SHA-256 value".to_string());
        }
        for item in &self.dimensions {
            item.validate()
                .map_err(|_| "dimensions must contain exact dimension digests".to_string())?;
        }
        // `dimension_names == tuple(sorted(set(dimension_names), key=value))` —
        // unique AND ordered by dimension value.
        let mut sorted = self.dimensions.clone();
        sorted.sort_by_key(|d| d.dimension.as_str());
        sorted.dedup_by_key(|d| d.dimension.as_str());
        if sorted.len() != self.dimensions.len()
            || sorted
                .iter()
                .zip(self.dimensions.iter())
                .any(|(a, b)| a.dimension != b.dimension)
        {
            return Err("dimensions must be unique and ordered".to_string());
        }
        let names: BTreeSet<_> = self.dimensions.iter().map(|d| d.dimension).collect();
        if names.len() != LaunchBindingDimension::ALL.len()
            || !names.iter().all(|d| LaunchBindingDimension::ALL.contains(d))
        {
            return Err("all launch binding dimensions are required".to_string());
        }
        // required/unresolved are frozensets in Python; the Vec here is the
        // member list — required ⊇ _CORE_REQUIREMENTS.
        let required: BTreeSet<_> = self.required_requirements.iter().copied().collect();
        if !CORE_REQUIREMENTS.iter().all(|r| required.contains(r)) {
            return Err("core launch proof requirements cannot be omitted".to_string());
        }
        // `required_requirements != unresolved_requirements` → frozenset eq.
        let unresolved: BTreeSet<_> = self.unresolved_requirements.iter().copied().collect();
        if required != unresolved {
            return Err(
                "observation-only bindings cannot satisfy proof requirements".to_string()
            );
        }
        // uncertainties unique + ordered by value, ⊇ _MANDATORY_UNCERTAINTIES.
        let mut sorted_u = self.uncertainties.clone();
        sorted_u.sort_by_key(|u: &UncertaintyKind| u.as_str());
        sorted_u.dedup_by_key(|u| *u);
        if sorted_u.len() != self.uncertainties.len()
            || sorted_u
                .iter()
                .zip(self.uncertainties.iter())
                .any(|(a, b)| a != b)
        {
            return Err("uncertainties must be unique and ordered".to_string());
        }
        let set_u: BTreeSet<_> = self.uncertainties.iter().copied().collect();
        if !MANDATORY_UNCERTAINTIES.iter().all(|u| set_u.contains(u)) {
            return Err(
                "observation-only bindings require launch and effect uncertainty".to_string()
            );
        }
        let expected = binding_digest(
            &self.dimensions,
            &required,
            &self.uncertainties,
        );
        if self.binding_digest != expected {
            return Err("binding digest does not match launch binding material".to_string());
        }
        Ok(())
    }

    /// `can_issue_positive_proof` (:170) — observation is never a proof.
    pub const fn can_issue_positive_proof(&self) -> bool {
        false
    }

    /// `action_floor` (:174) — `maximum_action_floor(UNCERTAINTY_FLOOR[u])`.
    pub fn action_floor(&self) -> GuardAction {
        let floors: Vec<GuardAction> =
            self.uncertainties.iter().map(|u| u.floor()).collect();
        maximum_action_floor(floors.iter())
    }

    /// `to_dict` (:180).
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        m.insert(
            "binding_digest".into(),
            Value::String(self.binding_digest.clone()),
        );
        m.insert(
            "dimensions".into(),
            Value::Array(
                self.dimensions
                    .iter()
                    .map(|d| {
                        let mut dm = Map::new();
                        dm.insert(
                            "dimension".into(),
                            Value::String(d.dimension.as_str().to_string()),
                        );
                        dm.insert("digest".into(), Value::String(d.digest.clone()));
                        Value::Object(dm)
                    })
                    .collect(),
            ),
        );
        m.insert(
            "required_requirements".into(),
            sorted_str_array(self.required_requirements.iter().map(|r| r.as_str())),
        );
        m.insert(
            "unresolved_requirements".into(),
            sorted_str_array(self.unresolved_requirements.iter().map(|r| r.as_str())),
        );
        m.insert(
            "uncertainties".into(),
            Value::Array(
                self.uncertainties
                    .iter()
                    .map(|u| Value::String(u.as_str().to_string()))
                    .collect(),
            ),
        );
        m.insert("can_issue_positive_proof".into(), Value::Bool(false));
        m.insert(
            "action_floor".into(),
            Value::String(self.action_floor().as_str().to_string()),
        );
        Value::Object(m)
    }
}

/// `changed_launch_binding_dimensions` (:388) — dimensions whose digest
/// differs between two observations, ordered by dimension value.
pub fn changed_launch_binding_dimensions(
    previous: &LaunchIdentityBindingObservation,
    current: &LaunchIdentityBindingObservation,
) -> Vec<LaunchBindingDimension> {
    let previous_digests: BTreeMap<_, _> = previous
        .dimensions
        .iter()
        .map(|d| (d.dimension, &d.digest))
        .collect();
    let current_digests: BTreeMap<_, _> = current
        .dimensions
        .iter()
        .map(|d| (d.dimension, &d.digest))
        .collect();
    let mut changed: Vec<LaunchBindingDimension> = LaunchBindingDimension::ALL
        .iter()
        .copied()
        .filter(|d| previous_digests.get(d) != current_digests.get(d))
        .collect();
    changed.sort_by_key(|d| d.as_str());
    changed
}

/// `_binding_digest` (:472) — framed digest of the schema/dimensions/
/// requirements/uncertainties material.
pub fn binding_digest(
    dimensions: &[LaunchBindingDimensionDigest],
    required_requirements: &BTreeSet<ProofRequirement>,
    uncertainties: &[UncertaintyKind],
) -> String {
    let mut sorted_req: Vec<&str> = required_requirements
        .iter()
        .map(|r| r.as_str())
        .collect();
    sorted_req.sort_unstable();
    let mut sorted_unc: Vec<&str> = uncertainties.iter().map(|u| u.as_str()).collect();
    sorted_unc.sort_unstable();
    let material = serde_json::json!({
        "schema_version": LAUNCH_IDENTITY_BINDING_VERSION,
        "dimensions": dimensions
            .iter()
            .map(|d| Value::Array(vec![
                Value::String(d.dimension.as_str().to_string()),
                Value::String(d.digest.clone()),
            ]))
            .collect::<Vec<_>>(),
        "required_requirements": sorted_req,
        "uncertainties": sorted_unc,
    });
    framed_digest("hol-guard.launch-binding-observation", &material)
}

/// `_dimension` (:487) — wrap a material value into a dimension digest.
pub fn dimension_digest(
    dimension: LaunchBindingDimension,
    material: &Value,
) -> LaunchBindingDimensionDigest {
    LaunchBindingDimensionDigest {
        dimension,
        digest: framed_digest(&format!("hol-guard.{}", dimension.as_str()), material),
    }
}

/// `_wrapper_identity_digest` (:431) — framed digest of the runtime-executable
/// identity minus `reuse_nonce`.
pub fn wrapper_identity_digest(identity: &Value) -> String {
    let mut stable = Map::new();
    if let Value::Object(m) = identity {
        for (k, v) in m {
            if k != "reuse_nonce" {
                stable.insert(k.clone(), v.clone());
            }
        }
    }
    framed_digest(
        "hol-guard.runtime-wrapper-executable",
        &Value::Object(stable),
    )
}

/// `_framed_digest` (:495) — `sha256(domain + NUL + u64be(len) + canonical)`.
pub fn framed_digest(domain: &str, value: &Value) -> String {
    let payload = guard_contracts::capability_canonical_json(value)
        .unwrap_or_default()
        .into_bytes();
    let mut frame = Vec::with_capacity(domain.len() + 1 + 8 + payload.len());
    frame.extend_from_slice(domain.as_bytes());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut hasher = Sha256::new();
    hasher.update(&frame);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `_SHA256.fullmatch` (:35).
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `sorted(item.value for item in …)` → JSON array.
fn sorted_str_array<'a>(items: impl Iterator<Item = &'a str>) -> Value {
    let mut values: Vec<String> = items.map(str::to_string).collect();
    values.sort_unstable();
    values.dedup();
    Value::Array(values.into_iter().map(Value::String).collect())
}

#[cfg(test)]
mod digest_parity {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn framed_digest_matches_python_oracle() {
        // python: framed('hol-guard.command-structure', {'segments':[['gh','issue','lock']],'unicode':'héllo'})
        //       = d10f8ee5…9429319
        let material = serde_json::json!({
            "segments": [["gh", "issue", "lock"]],
            "unicode": "héllo",
        });
        assert_eq!(
            framed_digest("hol-guard.command-structure", &material),
            "d10f8ee54304afc101086609aeeea553682e1ece071bc4165c703c6b58429319"
        );
    }

    #[test]
    fn binding_digest_matches_python_oracle() {
        // material with dims [[command-structure,a*64],[executable-observation,b*64]],
        // required [operation-and-targets, workspace-identity], uncertainties [unresolved-launch-identity, unknown-effect]
        let dims = vec![
            LaunchBindingDimensionDigest { dimension: LaunchBindingDimension::CommandStructure, digest: "a".repeat(64) },
            LaunchBindingDimensionDigest { dimension: LaunchBindingDimension::ExecutableObservation, digest: "b".repeat(64) },
        ];
        let required: BTreeSet<ProofRequirement> = [
            ProofRequirement::OperationAndTargets,
            ProofRequirement::WorkspaceIdentity,
        ].into_iter().collect();
        let uncertainties = vec![
            UncertaintyKind::UnresolvedLaunchIdentity,
            UncertaintyKind::UnknownEffect,
        ];
        assert_eq!(
            binding_digest(&dims, &required, &uncertainties),
            "a84eb5f03410da2511c17e85f2209a47241ca5adcf17e13e9f831c24b0fa3958"
        );
    }
}
