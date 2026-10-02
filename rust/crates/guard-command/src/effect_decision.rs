//! Native port of `effect_decision.py` — the effect-decision plane.
//!
//! `evaluate_effect_decision` composes the maximum action floor from every
//! `DecisionFactor` and `UncertaintyKind`, emits an auditable `DecisionReason`
//! set, and derives the `FinalDisposition`. This module reproduces the Python
//! semantics byte-for-byte: enum values are the Python str-enum values, reason
//! ordering is `_reason_key`, factor ordering is `semantic_key`, and the
//! disposition lattice is `_disposition`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Effect-decision contract schema version (mirrors EFFECT_DECISION_SCHEMA_VERSION).
pub const EFFECT_DECISION_SCHEMA_VERSION: &str = "1.1.0";
/// Effect-contract schema version (mirrors EFFECT_CONTRACT_SCHEMA_VERSION).
pub const EFFECT_CONTRACT_SCHEMA_VERSION: &str = "1.0.0";

/// Canonical action lattice rank (mirrors `action_lattice.GUARD_ACTION_SEVERITY`).
///
/// `GuardAction` is a string literal in Python; we model it as a serde string
/// enum with the exact wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardAction {
    Allow,
    Warn,
    Review,
    RequireReapproval,
    SandboxRequired,
    Block,
}

impl GuardAction {
    pub const fn severity(self) -> u8 {
        match self {
            GuardAction::Allow => 0,
            GuardAction::Warn => 1,
            GuardAction::Review => 2,
            GuardAction::RequireReapproval => 3,
            GuardAction::SandboxRequired => 4,
            GuardAction::Block => 5,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            GuardAction::Allow => "allow",
            GuardAction::Warn => "warn",
            GuardAction::Review => "review",
            GuardAction::RequireReapproval => "require-reapproval",
            GuardAction::SandboxRequired => "sandbox-required",
            GuardAction::Block => "block",
        }
    }
}

/// `most_restrictive_guard_action`: the max-severity action, "review" if empty.
pub fn maximum_action_floor<'a>(floors: impl IntoIterator<Item = &'a GuardAction>) -> GuardAction {
    floors
        .into_iter()
        .copied()
        .max_by_key(|a| a.severity())
        .unwrap_or(GuardAction::Review)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofRoute {
    Verified,
    Contained,
    WorkflowAuthorized,
}

impl ProofRoute {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProofRoute::Verified => "verified",
            ProofRoute::Contained => "contained",
            ProofRoute::WorkflowAuthorized => "workflow-authorized",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofRequirement {
    OperationAndTargets,
    WorkspaceIdentity,
    RepositoryIdentity,
    RemoteResourceIdentity,
    WorkingDirectoryIdentity,
    ExecutableIdentity,
    LaunchChain,
    DependencyProvenance,
    ConfigurationIdentity,
    ShellDataFlow,
    ParserConfidence,
    ExpectedEffects,
    ContainmentIdentity,
    CapabilityConstraints,
}

impl ProofRequirement {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProofRequirement::OperationAndTargets => "operation-and-targets",
            ProofRequirement::WorkspaceIdentity => "workspace-identity",
            ProofRequirement::RepositoryIdentity => "repository-identity",
            ProofRequirement::RemoteResourceIdentity => "remote-resource-identity",
            ProofRequirement::WorkingDirectoryIdentity => "working-directory-identity",
            ProofRequirement::ExecutableIdentity => "executable-identity",
            ProofRequirement::LaunchChain => "launch-chain",
            ProofRequirement::DependencyProvenance => "dependency-provenance",
            ProofRequirement::ConfigurationIdentity => "configuration-identity",
            ProofRequirement::ShellDataFlow => "shell-data-flow",
            ProofRequirement::ParserConfidence => "parser-confidence",
            ProofRequirement::ExpectedEffects => "expected-effects",
            ProofRequirement::ContainmentIdentity => "containment-identity",
            ProofRequirement::CapabilityConstraints => "capability-constraints",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UncertaintyKind {
    PartialParse,
    DynamicInput,
    UnsupportedInput,
    MalformedInput,
    ParserBudgetExhausted,
    MatcherFailure,
    ParserFailure,
    UnresolvedLaunchIdentity,
    UnknownEffect,
    DegradedContainment,
    ProtectionHealthDegraded,
    PolicyVersionMismatch,
    MalformedBoundaryVersion,
    UnknownBoundaryVersion,
    RollbackBoundaryVersion,
}

impl UncertaintyKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            UncertaintyKind::PartialParse => "partial-parse",
            UncertaintyKind::DynamicInput => "dynamic-input",
            UncertaintyKind::UnsupportedInput => "unsupported-input",
            UncertaintyKind::MalformedInput => "malformed-input",
            UncertaintyKind::ParserBudgetExhausted => "parser-budget-exhausted",
            UncertaintyKind::MatcherFailure => "matcher-failure",
            UncertaintyKind::ParserFailure => "parser-failure",
            UncertaintyKind::UnresolvedLaunchIdentity => "unresolved-launch-identity",
            UncertaintyKind::UnknownEffect => "unknown-effect",
            UncertaintyKind::DegradedContainment => "degraded-containment",
            UncertaintyKind::ProtectionHealthDegraded => "protection-health-degraded",
            UncertaintyKind::PolicyVersionMismatch => "policy-version-mismatch",
            UncertaintyKind::MalformedBoundaryVersion => "malformed-boundary-version",
            UncertaintyKind::UnknownBoundaryVersion => "unknown-boundary-version",
            UncertaintyKind::RollbackBoundaryVersion => "rollback-boundary-version",
        }
    }

    /// `UNCERTAINTY_FLOOR[kind]` (effect_contract.py:151).
    pub const fn floor(self) -> GuardAction {
        match self {
            UncertaintyKind::PartialParse
            | UncertaintyKind::DynamicInput
            | UncertaintyKind::UnsupportedInput
            | UncertaintyKind::MalformedInput => GuardAction::Review,
            UncertaintyKind::ParserBudgetExhausted
            | UncertaintyKind::UnresolvedLaunchIdentity
            | UncertaintyKind::UnknownEffect => GuardAction::RequireReapproval,
            UncertaintyKind::MatcherFailure
            | UncertaintyKind::ParserFailure
            | UncertaintyKind::DegradedContainment
            | UncertaintyKind::ProtectionHealthDegraded
            | UncertaintyKind::PolicyVersionMismatch
            | UncertaintyKind::MalformedBoundaryVersion
            | UncertaintyKind::UnknownBoundaryVersion
            | UncertaintyKind::RollbackBoundaryVersion => GuardAction::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionFactorSource {
    Effect,
    Match,
    Policy,
    Containment,
    Authorization,
    Assurance,
    Control,
}

impl DecisionFactorSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            DecisionFactorSource::Effect => "effect",
            DecisionFactorSource::Match => "match",
            DecisionFactorSource::Policy => "policy",
            DecisionFactorSource::Containment => "containment",
            DecisionFactorSource::Authorization => "authorization",
            DecisionFactorSource::Assurance => "assurance",
            DecisionFactorSource::Control => "control",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectKind {
    WorkspaceOrPublicRead,
    SensitiveRead,
    WorkspaceWrite,
    ExternalFilesystemWrite,
    ProcessExecution,
    NetworkRead,
    NetworkWrite,
    RemoteStateRead,
    RemoteStateMutation,
    PermissionOrAccessChange,
    CredentialOrSecretOperation,
    SystemOrPrivilegeOperation,
    PackageOrSourceInstallation,
    DestructiveOrIrreversibleOperation,
    GuardControlOperation,
}

impl EffectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectKind::WorkspaceOrPublicRead => "workspace-or-public-read",
            EffectKind::SensitiveRead => "sensitive-read",
            EffectKind::WorkspaceWrite => "workspace-write",
            EffectKind::ExternalFilesystemWrite => "external-filesystem-write",
            EffectKind::ProcessExecution => "process-execution",
            EffectKind::NetworkRead => "network-read",
            EffectKind::NetworkWrite => "network-write",
            EffectKind::RemoteStateRead => "remote-state-read",
            EffectKind::RemoteStateMutation => "remote-state-mutation",
            EffectKind::PermissionOrAccessChange => "permission-or-access-change",
            EffectKind::CredentialOrSecretOperation => "credential-or-secret-operation",
            EffectKind::SystemOrPrivilegeOperation => "system-or-privilege-operation",
            EffectKind::PackageOrSourceInstallation => "package-or-source-installation",
            EffectKind::DestructiveOrIrreversibleOperation => "destructive-or-irreversible-operation",
            EffectKind::GuardControlOperation => "guard-control-operation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectTargetScope {
    PublicResource,
    Workspace,
    SensitiveLocal,
    ExternalLocal,
    NetworkEndpoint,
    RemoteResource,
    System,
    Guard,
    Unknown,
}

impl EffectTargetScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectTargetScope::PublicResource => "public-resource",
            EffectTargetScope::Workspace => "workspace",
            EffectTargetScope::SensitiveLocal => "sensitive-local",
            EffectTargetScope::ExternalLocal => "external-local",
            EffectTargetScope::NetworkEndpoint => "network-endpoint",
            EffectTargetScope::RemoteResource => "remote-resource",
            EffectTargetScope::System => "system",
            EffectTargetScope::Guard => "guard",
            EffectTargetScope::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectReversibility {
    Reversible,
    TriviallyRecoverable,
    RecoverableWithReview,
    Irreversible,
    Unknown,
}

impl EffectReversibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectReversibility::Reversible => "reversible",
            EffectReversibility::TriviallyRecoverable => "trivially-recoverable",
            EffectReversibility::RecoverableWithReview => "recoverable-with-review",
            EffectReversibility::Irreversible => "irreversible",
            EffectReversibility::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectBlastRadius {
    SingleResource,
    Workspace,
    MultipleResources,
    SystemWide,
    Catastrophic,
    Unknown,
}

impl EffectBlastRadius {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectBlastRadius::SingleResource => "single-resource",
            EffectBlastRadius::Workspace => "workspace",
            EffectBlastRadius::MultipleResources => "multiple-resources",
            EffectBlastRadius::SystemWide => "system-wide",
            EffectBlastRadius::Catastrophic => "catastrophic",
            EffectBlastRadius::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectEvidenceSource {
    Parser,
    Extension,
    LaunchIdentity,
    Manifest,
    Lockfile,
    Configuration,
    Policy,
    Containment,
    Capability,
    Runtime,
}

impl EffectEvidenceSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectEvidenceSource::Parser => "parser",
            EffectEvidenceSource::Extension => "extension",
            EffectEvidenceSource::LaunchIdentity => "launch-identity",
            EffectEvidenceSource::Manifest => "manifest",
            EffectEvidenceSource::Lockfile => "lockfile",
            EffectEvidenceSource::Configuration => "configuration",
            EffectEvidenceSource::Policy => "policy",
            EffectEvidenceSource::Containment => "containment",
            EffectEvidenceSource::Capability => "capability",
            EffectEvidenceSource::Runtime => "runtime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectConfidence {
    Exact,
    Strong,
    Partial,
    Dynamic,
    Unknown,
}

impl EffectConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectConfidence::Exact => "exact",
            EffectConfidence::Strong => "strong",
            EffectConfidence::Partial => "partial",
            EffectConfidence::Dynamic => "dynamic",
            EffectConfidence::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainmentRequirement {
    None,
    Eligible,
    Required,
    NotEligible,
}

impl ContainmentRequirement {
    pub const fn as_str(self) -> &'static str {
        match self {
            ContainmentRequirement::None => "none",
            ContainmentRequirement::Eligible => "eligible",
            ContainmentRequirement::Required => "required",
            ContainmentRequirement::NotEligible => "not-eligible",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FinalDisposition {
    SilentVerified,
    SilentContained,
    WorkflowAuthorized,
    Warn,
    Review,
    RequireReapproval,
    SandboxRequired,
    Block,
}

impl FinalDisposition {
    /// `FinalDisposition(action)` coercion: maps each non-silent action value.
    pub const fn from_action(action: GuardAction) -> Option<FinalDisposition> {
        match action {
            GuardAction::Allow => None, // resolved via proof route below
            GuardAction::Warn => Some(FinalDisposition::Warn),
            GuardAction::Review => Some(FinalDisposition::Review),
            GuardAction::RequireReapproval => Some(FinalDisposition::RequireReapproval),
            GuardAction::SandboxRequired => Some(FinalDisposition::SandboxRequired),
            GuardAction::Block => Some(FinalDisposition::Block),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecisionBasis {
    pub action_floor: GuardAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_route: Option<ProofRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PositiveProof {
    pub route: ProofRoute,
    pub binding_digest: String,
    pub satisfied_requirements: Vec<ProofRequirement>,
    #[serde(default)]
    pub enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EffectAssessment {
    pub kind: EffectKind,
    pub target_scope: EffectTargetScope,
    pub reversibility: EffectReversibility,
    pub blast_radius: EffectBlastRadius,
    pub evidence_source: EffectEvidenceSource,
    pub confidence: EffectConfidence,
    pub containment: ContainmentRequirement,
    pub proof_requirements: Vec<ProofRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncertainty_reasons: Vec<UncertaintyKind>,
    #[serde(default = "default_contract_schema")]
    pub schema_version: String,
}

fn default_contract_schema() -> String {
    EFFECT_CONTRACT_SCHEMA_VERSION.to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecisionFactor {
    pub source: DecisionFactorSource,
    pub reason_code: String,
    pub basis: DecisionBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<EffectAssessment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<PositiveProof>,
}

impl DecisionFactor {
    /// `_assessment_key` (effect_decision.py): 11-tuple, empty for None.
    fn assessment_key(assessment: Option<&EffectAssessment>) -> Vec<String> {
        match assessment {
            None => vec![String::new(); 11],
            Some(a) => vec![
                a.kind.as_str().to_owned(),
                a.target_scope.as_str().to_owned(),
                a.reversibility.as_str().to_owned(),
                a.blast_radius.as_str().to_owned(),
                a.evidence_source.as_str().to_owned(),
                a.confidence.as_str().to_owned(),
                a.containment.as_str().to_owned(),
                sorted_join(&a.proof_requirements, ProofRequirement::as_str),
                sorted_join(&a.uncertainty_reasons, UncertaintyKind::as_str),
                a.schema_version.clone(),
                "assessment".to_owned(),
            ],
        }
    }

    /// `_proof_key` (effect_decision.py): 4-tuple, empty for None.
    fn proof_key(proof: Option<&PositiveProof>) -> Vec<String> {
        match proof {
            None => vec![String::new(); 4],
            Some(p) => vec![
                p.route.as_str().to_owned(),
                p.binding_digest.clone(),
                sorted_join(&p.satisfied_requirements, ProofRequirement::as_str),
                if p.enforced { "enforced" } else { "not-enforced" }.to_owned(),
            ],
        }
    }

    /// `semantic_key` (effect_decision.py:148): deterministic sort key.
    pub fn semantic_key(&self) -> Vec<String> {
        let mut key = vec![
            self.segment_ref.clone().unwrap_or_default(),
            self.operation_ref.clone().unwrap_or_default(),
            self.producer_ref.clone().unwrap_or_default(),
            self.evidence_digest.clone().unwrap_or_default(),
            self.source.as_str().to_owned(),
            self.reason_code.clone(),
            self.basis.action_floor.as_str().to_owned(),
            self.basis
                .proof_route
                .map(ProofRoute::as_str)
                .unwrap_or("")
                .to_owned(),
        ];
        key.extend(Self::assessment_key(self.assessment.as_ref()));
        key.extend(Self::proof_key(self.proof.as_ref()));
        key
    }
}

/// Sorted, comma-joined enum values — mirrors `",".join(sorted(item.value ...))`.
fn sorted_join<T: Copy>(items: &[T], as_str: impl Fn(T) -> &'static str) -> String {
    let mut values: Vec<&'static str> = items.iter().map(|&i| as_str(i)).collect();
    values.sort_unstable();
    values.join(",")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecisionReason {
    pub source: DecisionFactorSource,
    pub reason_code: String,
    pub action_floor: GuardAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_ref: Option<String>,
}

impl DecisionReason {
    /// `_reason_key` (effect_decision.py:278): (segment_ref, operation_ref,
    /// source.value, reason_code, severity_rank).
    fn reason_key(&self) -> (String, String, &'static str, String, u8) {
        (
            self.segment_ref.clone().unwrap_or_default(),
            self.operation_ref.clone().unwrap_or_default(),
            self.source.as_str(),
            self.reason_code.clone(),
            self.action_floor.severity(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EffectDecisionRequest {
    pub factors: Vec<DecisionFactor>,
    #[serde(default)]
    pub uncertainties: Vec<UncertaintyKind>,
    #[serde(default = "default_decision_schema")]
    pub schema_version: String,
}

fn default_decision_schema() -> String {
    EFFECT_DECISION_SCHEMA_VERSION.to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EffectDecision {
    pub action: GuardAction,
    pub disposition: FinalDisposition,
    pub controlling_reasons: Vec<DecisionReason>,
    pub reasons: Vec<DecisionReason>,
    pub proof_routes: Vec<ProofRoute>,
    pub schema_version: String,
}

/// `evaluate_effect_decision` (effect_decision.py:203).
///
/// Reproduces: reasons = factors→floor + request uncertainties→UNCERTAINTY_FLOOR
/// + per-assessment uncertainties (EFFECT source); sort by `_reason_key`;
/// `maximum_action_floor`; `controlling` = reasons at max severity;
/// `proof_routes` = {proof.route for positive proofs}; `_disposition`.
///
/// The request must already satisfy the Python `__post_init__` invariants
/// (factors sorted by `semantic_key`, no duplicate keys, deduped sorted
/// uncertainties); serde deserialization + `prepare` enforces this.
pub fn evaluate_effect_decision(
    request: &EffectDecisionRequest,
) -> Result<EffectDecision, &'static str> {
    if request.schema_version != EFFECT_DECISION_SCHEMA_VERSION {
        return Err("unsupported effect decision schema version");
    }
    // Python __post_init__ orders factors by semantic_key and uncertainties by
    // value; we sort copies to match regardless of wire order.
    let mut factors = request.factors.clone();
    factors.sort_by_cached_key(DecisionFactor::semantic_key);
    let mut uncertainties = request.uncertainties.clone();
    uncertainties.sort_by_key(|u| u.as_str());

    let mut reasons: Vec<DecisionReason> = Vec::new();
    for item in &factors {
        reasons.push(DecisionReason {
            source: item.source,
            reason_code: item.reason_code.clone(),
            action_floor: item.basis.action_floor,
            segment_ref: item.segment_ref.clone(),
            operation_ref: item.operation_ref.clone(),
        });
    }
    for uncertainty in &uncertainties {
        reasons.push(DecisionReason {
            source: DecisionFactorSource::Policy,
            reason_code: format!("uncertainty.{}", uncertainty.as_str()),
            action_floor: uncertainty.floor(),
            segment_ref: None,
            operation_ref: None,
        });
    }
    for factor in &factors {
        if let Some(assessment) = &factor.assessment {
            for uncertainty in &assessment.uncertainty_reasons {
                reasons.push(DecisionReason {
                    source: DecisionFactorSource::Effect,
                    reason_code: format!("uncertainty.{}", uncertainty.as_str()),
                    action_floor: uncertainty.floor(),
                    segment_ref: factor.segment_ref.clone(),
                    operation_ref: factor.operation_ref.clone(),
                });
            }
        }
    }
    reasons.sort_by_cached_key(DecisionReason::reason_key);

    let action = maximum_action_floor(reasons.iter().map(|r| &r.action_floor));
    let max_severity = action.severity();
    let controlling_reasons: Vec<DecisionReason> = reasons
        .iter()
        .filter(|r| r.action_floor.severity() == max_severity)
        .cloned()
        .collect();

    let proof_routes: BTreeSet<ProofRoute> = factors
        .iter()
        .filter_map(|f| f.proof.as_ref().map(|p| p.route))
        .collect();
    // Preserve a stable sorted order (enum Ord = declaration order, matching
    // Python's set→sorted-by-value in to_dict consumers).
    let proof_routes: Vec<ProofRoute> = proof_routes.into_iter().collect();

    let disposition = disposition(action, &proof_routes);

    Ok(EffectDecision {
        action,
        disposition,
        controlling_reasons,
        reasons,
        proof_routes,
        schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    })
}

/// `_disposition` (effect_decision.py:288).
fn disposition(action: GuardAction, routes: &[ProofRoute]) -> FinalDisposition {
    if action == GuardAction::Allow {
        if routes.contains(&ProofRoute::WorkflowAuthorized) {
            return FinalDisposition::WorkflowAuthorized;
        }
        if routes.contains(&ProofRoute::Contained) {
            return FinalDisposition::SilentContained;
        }
        return FinalDisposition::SilentVerified;
    }
    FinalDisposition::from_action(action).unwrap_or(FinalDisposition::Review)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factor(source: DecisionFactorSource, code: &str, floor: GuardAction) -> DecisionFactor {
        DecisionFactor {
            source,
            reason_code: code.to_owned(),
            basis: DecisionBasis {
                action_floor: floor,
                proof_route: if floor.severity() < GuardAction::Review.severity() {
                    Some(ProofRoute::Verified)
                } else {
                    None
                },
            },
            segment_ref: None,
            operation_ref: None,
            producer_ref: None,
            evidence_digest: None,
            assessment: None,
            proof: None,
        }
    }

    #[test]
    fn max_floor_composes_across_factors_and_uncertainties() {
        let req = EffectDecisionRequest {
            factors: vec![
                factor(DecisionFactorSource::Match, "a", GuardAction::Review),
                factor(DecisionFactorSource::Policy, "b", GuardAction::Allow),
            ],
            uncertainties: vec![UncertaintyKind::MatcherFailure], // floor = block
            schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        };
        let decision = evaluate_effect_decision(&req).unwrap();
        assert_eq!(decision.action, GuardAction::Block);
        assert_eq!(decision.disposition, FinalDisposition::Block);
    }

    #[test]
    fn allow_with_workflow_proof_disposes_workflow_authorized() {
        let mut f = factor(DecisionFactorSource::Match, "ok", GuardAction::Allow);
        f.proof = Some(PositiveProof {
            route: ProofRoute::WorkflowAuthorized,
            binding_digest: "a".repeat(64),
            satisfied_requirements: vec![],
            enforced: false,
        });
        let req = EffectDecisionRequest {
            factors: vec![f],
            uncertainties: vec![],
            schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        };
        let decision = evaluate_effect_decision(&req).unwrap();
        assert_eq!(decision.action, GuardAction::Allow);
        assert_eq!(decision.disposition, FinalDisposition::WorkflowAuthorized);
        assert_eq!(decision.proof_routes, vec![ProofRoute::WorkflowAuthorized]);
    }

    #[test]
    fn assessment_uncertainty_raises_effect_reason() {
        let mut f = factor(DecisionFactorSource::Effect, "e", GuardAction::Review);
        f.assessment = Some(EffectAssessment {
            kind: EffectKind::SensitiveRead,
            target_scope: EffectTargetScope::SensitiveLocal,
            reversibility: EffectReversibility::Reversible,
            blast_radius: EffectBlastRadius::SingleResource,
            evidence_source: EffectEvidenceSource::Parser,
            confidence: EffectConfidence::Partial,
            containment: ContainmentRequirement::None,
            proof_requirements: vec![],
            uncertainty_reasons: vec![UncertaintyKind::ParserFailure], // block
            schema_version: EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
        });
        let req = EffectDecisionRequest {
            factors: vec![f],
            uncertainties: vec![],
            schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        };
        let decision = evaluate_effect_decision(&req).unwrap();
        assert_eq!(decision.action, GuardAction::Block);
        assert!(decision
            .reasons
            .iter()
            .any(|r| r.source == DecisionFactorSource::Effect
                && r.reason_code == "uncertainty.parser-failure"));
    }
}
