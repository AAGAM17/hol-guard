//! `evaluate_command` decision-floor lattice and composite type surface.
//!
//! Byte-parity port of the pure (no-IO) helpers in
//! `command_evaluation.py:60-168` and `:723-755` plus the
//! `CompositeCommandEvaluation` projection (`to_dict`). Producer functions that
//! construct the individual `DecisionFactor`s live in sibling modules and are
//! assembled by the resident `command_effect_decide` op.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::effect_decision::{
    effect_decision_to_payload, DecisionFactor, EffectDecision, UncertaintyKind,
};

/// `CommandDecisionFloor` — the 4-level minimum-action lattice.
///
/// Distinct from `GuardAction` (the 6-level action lattice): floors are the
/// *minimum* a factor/match can demand; the effect-decision reduction maps the
/// winning floor to a `GuardAction`. Wire values are kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandDecisionFloor {
    Allow,
    Monitor,
    Review,
    Block,
}

impl CommandDecisionFloor {
    /// `_FLOOR_RANK` (command_evaluation.py:66): allow=0 monitor=1 review=2 block=3.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Monitor => 1,
            Self::Review => 2,
            Self::Block => 3,
        }
    }

    /// The literal wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Monitor => "monitor",
            Self::Review => "review",
            Self::Block => "block",
        }
    }
}

/// `_SEVERITY_RANK` (command_evaluation.py:78): low=0 medium=1 high=2 critical=3.
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "low" => 0,
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => 0,
    }
}

/// `_MODE_FLOOR` (command_evaluation.py:79): declared default_mode → floor.
/// `None` for an unrecognized mode.
pub fn mode_floor(default_mode: &str) -> Option<CommandDecisionFloor> {
    Some(match default_mode {
        "disabled" => CommandDecisionFloor::Allow,
        "monitor" => CommandDecisionFloor::Monitor,
        "review" => CommandDecisionFloor::Review,
        "enforce" => CommandDecisionFloor::Block,
        "required" => CommandDecisionFloor::Review,
        _ => return None,
    })
}

/// `_UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS` (command_evaluation.py:67).
pub const UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS: &[&str] = &[
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "encoded_exfiltration",
    "guard_bypass",
    "policy_bypass",
];

/// `NativeMatcherEvidence` (native_command_extension_evidence.py:20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NativeMatcherEvidence {
    pub segment_index: u32,
    #[serde(default)]
    pub executable: Option<String>,
    pub detail: String,
}

impl NativeMatcherEvidence {
    /// `to_dict` (native_command_extension_evidence.py).
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "segment_index": self.segment_index,
            "executable": self.executable,
            "detail": self.detail,
        })
    }
}

/// `NativeSafeVariantObservation` (native_command_extension_evidence.py:29).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NativeSafeVariantObservation {
    pub variant_id: String,
    #[serde(default)]
    pub matcher_evidence: Vec<NativeMatcherEvidence>,
}

impl NativeSafeVariantObservation {
    /// `to_dict` adds the literal `match_class: "safe-variant"`.
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "variant_id": self.variant_id,
            "match_class": "safe-variant",
            "matcher_evidence": self
                .matcher_evidence
                .iter()
                .map(NativeMatcherEvidence::to_payload)
                .collect::<Vec<_>>(),
        })
    }
}

/// `NativeCommandExtensionObservation` (native_command_extension_evidence.py:42).
#[derive(Debug, Clone)]
pub struct NativeCommandExtensionObservation {
    pub extension_id: String,
    pub extension_version: String,
    pub extension_required: bool,
    pub rule_id: String,
    pub rule_version: String,
    pub matcher_evidence: Vec<NativeMatcherEvidence>,
    pub safe_variants: Vec<NativeSafeVariantObservation>,
    pub uncertainty_reasons: Vec<UncertaintyKind>,
}

impl NativeCommandExtensionObservation {
    /// `effective_evidence` (native_command_extension_evidence.py:51):
    /// matcher_evidence minus segment_indexes covered by any safe variant.
    pub fn effective_evidence(&self) -> Vec<&NativeMatcherEvidence> {
        let covered: BTreeSet<u32> = self
            .safe_variants
            .iter()
            .flat_map(|v| v.matcher_evidence.iter().map(|e| e.segment_index))
            .collect();
        self.matcher_evidence
            .iter()
            .filter(|e| !covered.contains(&e.segment_index))
            .collect()
    }

    /// `match_class` — "uncertainty" if any uncertainty, else "unsafe".
    fn match_class(&self) -> &'static str {
        if self.uncertainty_reasons.is_empty() {
            "unsafe"
        } else {
            "uncertainty"
        }
    }

    /// `match_classes` — `["unsafe"]` when there is effective evidence, plus
    /// `"uncertainty"` when uncertainty_reasons non-empty.
    fn match_classes(&self) -> Vec<&'static str> {
        let mut classes = Vec::new();
        if !self.effective_evidence().is_empty() {
            classes.push("unsafe");
        }
        if !self.uncertainty_reasons.is_empty() {
            classes.push("uncertainty");
        }
        classes
    }

    /// `to_dict` (native_command_extension_evidence.py:59).
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "extension_id": self.extension_id,
            "extension_version": self.extension_version,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "match_class": self.match_class(),
            "match_classes": self.match_classes(),
            "matcher_evidence": self
                .matcher_evidence
                .iter()
                .map(NativeMatcherEvidence::to_payload)
                .collect::<Vec<_>>(),
            "safe_variants": self
                .safe_variants
                .iter()
                .map(NativeSafeVariantObservation::to_payload)
                .collect::<Vec<_>>(),
            "uncertainty_reasons": self
                .uncertainty_reasons
                .iter()
                .map(|u| u.as_str())
                .collect::<Vec<_>>(),
            "effective_segment_indexes": self
                .effective_evidence()
                .iter()
                .map(|e| e.segment_index)
                .collect::<Vec<_>>(),
        })
    }
}

/// `CommandSafetyRule` projection — the fields the composition + `to_dict`
/// read (command_rules.py:290; evaluate_command uses `.rule_id`,`.severity`,
/// `.risk_classes`,`.action_classes`,`.safer_alternatives`,`.default_mode`,
/// `.compatibility_fallback`,`.description`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CommandSafetyRule {
    pub rule_id: String,
    pub severity: String,
    #[serde(default)]
    pub risk_classes: Vec<String>,
    /// `action_classes` — controlling-class candidates this rule owns.
    #[serde(default)]
    pub action_classes: Vec<String>,
    /// `description` — used as `reason` for non-fallback matches (:262).
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub safer_alternatives: Vec<String>,
    pub default_mode: String,
    #[serde(default)]
    pub compatibility_fallback: bool,
    /// `rule_version` — carried for observation payload parity.
    #[serde(default)]
    pub rule_version: String,
}

/// One rule match with its owning extension (command_evaluation.py:110).
///
/// `extension_id`/`required` are flattened here — Rust keeps the two fields
/// Python reads off `owned.extension`, avoiding a full `CommandSafetyExtension`
/// port for the composition lattice. `command.confidence` is carried as
/// `parse_confidence` for `to_dict` byte-parity.
#[derive(Debug, Clone)]
pub struct OwnedCommandRuleMatch {
    /// `extension.extension_id`.
    pub extension_id: String,
    /// `extension.required`.
    pub extension_required: bool,
    /// `extension.provenance_digest`.
    pub extension_provenance_digest: String,
    /// `extension.trust_class` — needed by `extension_is_active` filtering.
    pub extension_trust_class: String,
    /// `match.rule`.
    pub rule: CommandSafetyRule,
    /// `match.action_class` — the controlling-class candidate for this match.
    pub action_class: Option<String>,
    /// `match.reason` (= `rule.description`, or `compatibility_reason` when
    /// `rule.compatibility_fallback`).
    pub reason: String,
    /// `match.matcher_evidence`.
    pub matcher_evidence: Vec<NativeMatcherEvidence>,
    /// `command.confidence` at match time (`parse_confidence` in `to_dict`).
    pub parse_confidence: String,
}

impl OwnedCommandRuleMatch {
    /// `OwnedCommandRuleMatch.to_dict` (:116-120): `extension_id` merged over
    /// `match.to_dict()` (:96-106).
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "extension_id": self.extension_id,
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity,
            "risk_classes": self.rule.risk_classes,
            "action_class": self.action_class,
            "reason": self.reason,
            "safer_alternatives": self.rule.safer_alternatives,
            "matcher_evidence": self
                .matcher_evidence
                .iter()
                .map(NativeMatcherEvidence::to_payload)
                .collect::<Vec<_>>(),
            "parse_confidence": self.parse_confidence,
        })
    }
}

/// `_rule_floor` (command_evaluation.py:723): per-match minimum floor.
pub fn rule_floor(owned: &OwnedCommandRuleMatch) -> CommandDecisionFloor {
    if owned.extension_required && owned.rule.severity == "critical" {
        return CommandDecisionFloor::Block;
    }
    if owned.rule.default_mode == "disabled" {
        return CommandDecisionFloor::Allow;
    }
    if owned.extension_required {
        return CommandDecisionFloor::Review;
    }
    mode_floor(&owned.rule.default_mode).unwrap_or(CommandDecisionFloor::Review)
}

/// `_stronger_floor` (command_evaluation.py:736): max by `_FLOOR_RANK`.
pub fn stronger_floor(
    left: CommandDecisionFloor,
    right: CommandDecisionFloor,
) -> CommandDecisionFloor {
    if left.rank() >= right.rank() {
        left
    } else {
        right
    }
}

/// `_decision_action_floor` (command_evaluation.py:740).
pub fn decision_action_floor(action: &str) -> CommandDecisionFloor {
    match action {
        "allow" => CommandDecisionFloor::Allow,
        "warn" => CommandDecisionFloor::Monitor,
        "block" => CommandDecisionFloor::Block,
        _ => CommandDecisionFloor::Review,
    }
}

/// `_match_precedence_key` (command_evaluation.py:750): descending precedence.
pub fn match_precedence_key(owned: &OwnedCommandRuleMatch) -> (u8, u8, u8) {
    (
        rule_floor(owned).rank(),
        severity_rank(&owned.rule.severity),
        if owned.rule.compatibility_fallback {
            0
        } else {
            1
        },
    )
}

/// `CompositeCommandEvaluation` (command_evaluation.py:124) — the assembled
/// result the `command_effect_decide` op returns as `to_dict()`.
#[derive(Debug, Clone)]
pub struct CompositeCommandEvaluation {
    /// `command.security_identity`.
    pub security_identity: String,
    /// `command.confidence` (parse confidence string).
    pub parse_confidence: String,
    /// `command.uncertainty_reason`.
    pub uncertainty_reason: Option<String>,
    pub matches: Vec<OwnedCommandRuleMatch>,
    pub controlling_action_class: Option<String>,
    pub controlling_reason: Option<String>,
    pub controlling_rule_id: Option<String>,
    pub minimum_action: CommandDecisionFloor,
    /// `extension_observations` — typed projection.
    pub extension_observations: Vec<NativeCommandExtensionObservation>,
    pub decision_plane: EffectDecision,
    pub baseline_factors: Vec<DecisionFactor>,
    #[allow(dead_code)] // carried for risk_classes derivation
    pub baseline_uncertainties: Vec<UncertaintyKind>,
}

impl CompositeCommandEvaluation {
    /// `risk_classes` property (:141-149): union of match rule risk classes +
    /// controlling-action risk classes + the two local-critical sentinels.
    pub fn risk_classes(&self) -> Vec<String> {
        let mut risks: BTreeSet<String> = BTreeSet::new();
        for owned in &self.matches {
            risks.extend(owned.rule.risk_classes.iter().cloned());
        }
        if let Some(action) = &self.controlling_action_class {
            risks.extend(
                risk_classes_for_command_action(action)
                    .iter()
                    .map(|s| s.to_string()),
            );
        }
        if self
            .baseline_factors
            .iter()
            .any(|f| f.reason_code == "critical.local-secret-read")
        {
            risks.insert("local_secret_read".to_owned());
        }
        if self
            .baseline_factors
            .iter()
            .any(|f| f.reason_code == "critical.local-script-execution")
        {
            risks.insert("execution".to_owned());
        }
        risks.into_iter().collect()
    }

    /// `matched` property (:152).
    pub fn matched(&self) -> bool {
        self.controlling_action_class.is_some() || !self.matches.is_empty()
    }

    /// `to_dict` (:155) — the exact op wire payload.
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "security_identity": self.security_identity,
            "controlling_action_class": self.controlling_action_class,
            "controlling_reason": self.controlling_reason,
            "controlling_rule_id": self.controlling_rule_id,
            "minimum_action": self.minimum_action.as_str(),
            "risk_classes": self.risk_classes(),
            "matches": self
                .matches
                .iter()
                .map(OwnedCommandRuleMatch::to_payload)
                .collect::<Vec<_>>(),
            "extension_observations": self
                .extension_observations
                .iter()
                .map(NativeCommandExtensionObservation::to_payload)
                .collect::<Vec<_>>(),
            "decision_plane": effect_decision_to_payload(&self.decision_plane),
            "parse_confidence": self.parse_confidence,
            "uncertainty_reason": self.uncertainty_reason,
        })
    }
}

/// `risk_classes_for_command_action` (command_extensions.py:32):
/// `COMMAND_ACTION_RISK_CLASSES.get(action_class.strip().lower(), ())`.
///
/// The table is `_BASE_COMMAND_ACTION_RISK_CLASSES` +
/// `BLITCP_ACTION_RISK_CLASSES` + `GITHUB_ACTION_RISK_CLASSES` +
/// `OLLAMA_ACTION_RISK_CLASSES` (command_action_risk_metadata.py:12-112).
pub fn risk_classes_for_command_action(action_class: &str) -> &'static [&'static str] {
    let key = action_class.trim().to_lowercase();
    for (k, v) in COMMAND_ACTION_RISK_CLASSES {
        if *k == key {
            return v;
        }
    }
    &[]
}

/// `COMMAND_ACTION_RISK_CLASSES` — the merged table. Ordered; linear scan is
/// fine (84 entries, called once per composition).
pub static COMMAND_ACTION_RISK_CLASSES: &[(&str, &[&str])] = &[
    ("local secret read shell command", &["local_secret_read"]),
    ("local script execution shell command", &["execution"]),
    (
        "credential exfiltration shell command",
        &[
            "data_flow_exfiltration",
            "credential_exfiltration",
            "network_egress",
        ],
    ),
    ("guard-managed config write", &["destructive_shell"]),
    (
        "docker-sensitive command",
        &["network_egress", "destructive_shell"],
    ),
    ("docker client config access", &["local_secret_read"]),
    ("encoded or encrypted shell command", &["encoded_execution"]),
    ("kubernetes secret read command", &["local_secret_read"]),
    ("process environment secret read", &["local_secret_read"]),
    (
        "shell file upload command",
        &["credential_exfiltration", "network_egress"],
    ),
    (
        "sensitive local file write",
        &["destructive_shell", "local_secret_read"],
    ),
    ("destructive shell command", &["destructive_shell"]),
    ("pytest repository-code execution", &["execution"]),
    ("untrusted python interpreter", &["execution"]),
    (
        "guard approval self-authorization command",
        &["policy_bypass"],
    ),
    ("github pr body shell substitution", &["execution"]),
    ("filesystem destructive command", &["destructive_shell"]),
    ("git destructive command", &["destructive_shell"]),
    ("git origin refresh", &["network_egress"]),
    ("git index inspection", &["local_secret_read"]),
    (
        "git workspace command",
        &["destructive_shell", "network_egress"],
    ),
    ("git read command", &["local_secret_read"]),
    (
        "skill sunset configuration audit command",
        &["local_secret_read"],
    ),
    ("system destructive command", &["destructive_shell"]),
    ("windows destructive command", &["destructive_shell"]),
    (
        "kubernetes destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "infrastructure destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "aws destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "google cloud destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "azure destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "aws dns destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "google dns destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "azure dns destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "aws storage destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "google storage destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "azure storage destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "minio storage destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "rclone destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "restic destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "borg destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "velero destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "ssh remote execution command",
        &["execution", "network_egress"],
    ),
    (
        "ssh configured execution command",
        &["execution", "network_egress"],
    ),
    (
        "scp overwrite command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "rsync destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "postgresql destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "mysql destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "mongodb destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "redis destructive command",
        &["destructive_shell", "network_egress"],
    ),
    ("sqlite destructive command", &["destructive_shell"]),
    (
        "supabase destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "rsync remote shell command",
        &["execution", "network_egress"],
    ),
    (
        "essh group execution command",
        &["execution", "network_egress"],
    ),
    ("essh cache removal command", &["destructive_shell"]),
    (
        "noodle request execution command",
        &["execution", "network_egress"],
    ),
    (
        "probe request execution command",
        &["execution", "network_egress"],
    ),
    ("probe workspace mutation command", &["destructive_shell"]),
    ("probe destructive command", &["destructive_shell"]),
    // BLITCP_ACTION_RISK_CLASSES
    ("blitcp remote destination command", &["network_egress"]),
    ("blitcp privilege escalation command", &["execution"]),
    (
        "blitcp self-update command",
        &["execution", "network_egress"],
    ),
    ("blitcp unverified copy command", &["destructive_shell"]),
    // GITHUB_ACTION_RISK_CLASSES
    (
        "github routine pull-request merge command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github workflow rerun",
        &["destructive_shell", "network_egress"],
    ),
    ("github local configuration write", &["destructive_shell"]),
    (
        "github bounded maintenance command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github content mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github merge command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github administrator pull-request merge command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github release publication command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github workflow mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github force mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github delete command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github secret mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github access mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github remote mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "unverified github command capability",
        &["destructive_shell", "network_egress"],
    ),
    // OLLAMA_ACTION_RISK_CLASSES
    ("ollama model publication command", &["network_egress"]),
    ("ollama model removal command", &["destructive_shell"]),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(severity: &str, mode: &str, compat: bool) -> CommandSafetyRule {
        CommandSafetyRule {
            rule_id: "r".to_owned(),
            severity: severity.to_owned(),
            risk_classes: vec![],
            action_classes: vec![],
            description: "desc".to_owned(),
            safer_alternatives: vec![],
            default_mode: mode.to_owned(),
            compatibility_fallback: compat,
            rule_version: "1".to_owned(),
        }
    }

    fn owned(rule: CommandSafetyRule, required: bool) -> OwnedCommandRuleMatch {
        OwnedCommandRuleMatch {
            extension_id: "ext".to_owned(),
            extension_required: required,
            extension_provenance_digest: String::new(),
            extension_trust_class: "internal".to_owned(),
            rule,
            action_class: None,
            reason: "r".to_owned(),
            matcher_evidence: vec![],
            parse_confidence: "exact".to_owned(),
        }
    }

    #[test]
    fn rule_floor_required_critical_blocks() {
        assert_eq!(
            rule_floor(&owned(rule("critical", "review", false), true)),
            CommandDecisionFloor::Block
        );
    }

    #[test]
    fn rule_floor_required_noncritical_reviews() {
        assert_eq!(
            rule_floor(&owned(rule("high", "enforce", false), true)),
            CommandDecisionFloor::Review
        );
    }

    #[test]
    fn rule_floor_disabled_allows() {
        assert_eq!(
            rule_floor(&owned(rule("low", "disabled", false), true)),
            CommandDecisionFloor::Allow
        );
    }

    #[test]
    fn rule_floor_maps_mode() {
        assert_eq!(
            rule_floor(&owned(rule("low", "monitor", false), false)),
            CommandDecisionFloor::Monitor
        );
        assert_eq!(
            rule_floor(&owned(rule("low", "enforce", false), false)),
            CommandDecisionFloor::Block
        );
    }

    #[test]
    fn stronger_floor_takes_higher_rank() {
        assert_eq!(
            stronger_floor(CommandDecisionFloor::Monitor, CommandDecisionFloor::Block),
            CommandDecisionFloor::Block
        );
        assert_eq!(
            stronger_floor(CommandDecisionFloor::Block, CommandDecisionFloor::Allow),
            CommandDecisionFloor::Block
        );
    }

    #[test]
    fn decision_action_floor_maps_classes() {
        assert_eq!(decision_action_floor("allow"), CommandDecisionFloor::Allow);
        assert_eq!(decision_action_floor("warn"), CommandDecisionFloor::Monitor);
        assert_eq!(decision_action_floor("block"), CommandDecisionFloor::Block);
        assert_eq!(
            decision_action_floor("review"),
            CommandDecisionFloor::Review
        );
        assert_eq!(decision_action_floor("other"), CommandDecisionFloor::Review);
    }

    #[test]
    fn precedence_prefers_floor_then_severity_then_noncompat() {
        let a = owned(rule("critical", "enforce", false), false);
        let b = owned(rule("low", "enforce", false), false);
        assert!(match_precedence_key(&a) > match_precedence_key(&b));
        let c = owned(rule("critical", "enforce", true), false);
        assert!(match_precedence_key(&a) > match_precedence_key(&c));
    }

    #[test]
    fn risk_table_matches_python_entries() {
        assert_eq!(
            risk_classes_for_command_action("destructive shell command"),
            &["destructive_shell"]
        );
        assert_eq!(
            risk_classes_for_command_action("credential exfiltration shell command"),
            &[
                "data_flow_exfiltration",
                "credential_exfiltration",
                "network_egress"
            ]
        );
        // Normalization: strip + lowercase.
        assert_eq!(
            risk_classes_for_command_action("  Git Destructive Command "),
            &["destructive_shell"]
        );
        assert_eq!(
            risk_classes_for_command_action("unknown class"),
            &[] as &[&str]
        );
    }

    #[test]
    fn observation_effective_evidence_excludes_safe_variant_segments() {
        let obs = NativeCommandExtensionObservation {
            extension_id: "e".to_owned(),
            extension_version: "1".to_owned(),
            extension_required: true,
            rule_id: "r".to_owned(),
            rule_version: "1".to_owned(),
            matcher_evidence: vec![
                NativeMatcherEvidence {
                    segment_index: 0,
                    executable: None,
                    detail: "d0".to_owned(),
                },
                NativeMatcherEvidence {
                    segment_index: 1,
                    executable: None,
                    detail: "d1".to_owned(),
                },
            ],
            safe_variants: vec![NativeSafeVariantObservation {
                variant_id: "v".to_owned(),
                matcher_evidence: vec![NativeMatcherEvidence {
                    segment_index: 1,
                    executable: None,
                    detail: "d1".to_owned(),
                }],
            }],
            uncertainty_reasons: vec![],
        };
        let eff = obs.effective_evidence();
        assert_eq!(eff.len(), 1);
        assert_eq!(eff[0].segment_index, 0);
        assert_eq!(obs.match_class(), "unsafe");
        assert_eq!(obs.match_classes(), vec!["unsafe"]);
    }
}
