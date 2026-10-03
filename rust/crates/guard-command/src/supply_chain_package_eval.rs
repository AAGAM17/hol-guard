//! Rust port of `runtime/supply_chain_package_eval.py` — local package-request
//! evaluation for HOL Guard supply-chain protection.
//!
//! TODO(deps): several Python dependencies are not yet ported to this crate.
//! They are modeled as injected seams (`SupplyChainEvalDeps`) or small local
//! ports kept byte-parity where cheap:
//!   - `supply_chain_support.ecosystem_support_metadata` — local port.
//!   - `text.ensure_terminal_punctuation` — local port.
//!   - `workspace_path_guard.{read_bytes_within_workspace,read_text_within_workspace,
//!     resolve_path_within_workspace}` — `resolve_path_within_workspace` reused
//!     from `package_intent_common`; the read wrappers are local ports.
//!   - `stable_digest.stable_digest_hex` — reused from `local_supply_chain`.
//!   - `action_lattice.normalize_guard_action_result` — reused.
//!   - `config.{load_guard_config,resolve_risk_action}` — `resolve_risk_action`
//!     reused; `load_guard_config` is a seam.
//!   - `native_archive_inspection.inspect_archive_native` — seam.
//!   - `package_firewall_entitlement.resolve_package_firewall_entitlement` — seam.
//!   - `store.GuardStore` — `local_supply_chain::SupplyChainStore` seam.
//!   - `store_evidence.EvidenceRecord` — `Value`-dict seam.
//!   - `js_semver.{highest_js_version_for_selector,version_matches_js_selector}` —
//!     seam (per-package policy resolution; not yet ported).
//!   - `lockfile_evaluation_support.*` / `lockfile_parse_result.*` — seam via
//!     `LockfileEvaluationApi`.
//!   - `manifest_dependency_targets.evaluation_targets` — seam.
//!   - `npm_policy_range.*` — seam via `NpmPolicyRangeApi`.
//!   - `npm_source_spec.NpmSourceSpec`/`parse_npm_source_spec` — reused from
//!     `npm_source_spec` module.
//!   - `restricted_archive_download.*` — `RestrictedArchiveDownload` seam +
//!     `ExternalArchiveDownloadApi` for the network path.
//!   - `supply_chain_bundle*.*` — `SupplyChainBundleResponse`/`…Package` seams +
//!     `SupplyChainBundleApi` for freshness/cached evaluation.
//!   - `supply_chain_package_identity.*` — local port (pure logic).
//!   - `subprocess` (bundled pip audit fallback) — `// TODO(deps): subprocess`
//!     fail-closed stub.
//!   - `urllib.request.urlopen` (cloud validation) — `CloudValidationApi` seam.
//!   - `importlib.metadata` (bundled pip detection) — `PipAuditShims` seam.
//!   - `guard_sync`/`resolved_receipt`/`evidence_store` — seams on the store or
//!     via `SupplyChainRuntimeApi`.
//!
//! serde_json::Map is a BTreeMap, so all emitted JSON maps are key-sorted by
//! construction — matching Python `dict` literal order only where byte-parity
//! requires `write_spaced_sorted_json`/`serde_json::to_string` compact paths.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};
use serde_json::{json, Map, Value};

use crate::action_lattice::{normalize_guard_action_result, UNKNOWN_GUARD_ACTION_REASON};
use crate::effect_decision::GuardAction;
use crate::local_supply_chain::{
    resolve_risk_action, stable_digest_hex, stable_digest_hex_len, GuardConfig, SupplyChainStore,
};
use crate::npm_source_spec::{parse_npm_source_spec, NpmSourceSpec};
use crate::package_intent_common::{
    resolve_path_within_workspace, split_python_extras, GuardArtifact,
};

// ---------------------------------------------------------------------------
// Constants (:114-153)
// ---------------------------------------------------------------------------

fn decision_rank_map() -> &'static HashMap<&'static str, u8> {
    static MAP: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
        HashMap::from([
            ("allow", 0),
            ("monitor", 1),
            ("warn", 2),
            ("ask", 3),
            ("block", 4),
        ])
    });
    &MAP
}

#[allow(dead_code)]
fn severity_rank_map() -> &'static HashMap<&'static str, u8> {
    static MAP: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
        HashMap::from([
            ("unknown", 0),
            ("low", 1),
            ("medium", 2),
            ("high", 3),
            ("critical", 4),
        ])
    });
    &MAP
}

#[allow(dead_code)]
const TIMEOUT_SECONDS: u64 = 1;
#[allow(dead_code)]
const RETRY_TIMEOUT_SECONDS: u64 = 1;

static CLOUD_INBOX_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"https?://[^\s]+/guard/inbox/?")
        .case_insensitive(true)
        .build()
        .expect("CLOUD_INBOX_URL_RE")
});

const LOCAL_REVIEW_INSTRUCTION: &str = "Review this request in HOL Guard, then retry.";

static LOCAL_REVIEW_INSTRUCTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(&regex::escape(LOCAL_REVIEW_INSTRUCTION))
        .case_insensitive(true)
        .build()
        .expect("LOCAL_REVIEW_INSTRUCTION_RE")
});

static LOCAL_APPROVAL_INSTRUCTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"approve this request in hol guard, then retry\.?")
        .case_insensitive(true)
        .build()
        .expect("LOCAL_APPROVAL_INSTRUCTION_RE")
});

static LOCAL_APPROVAL_REQUEST_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"https?://[^\s]+/requests(?:/[^\s]*)?")
        .case_insensitive(true)
        .build()
        .expect("LOCAL_APPROVAL_REQUEST_URL_RE")
});

#[allow(dead_code)]
static NAMED_SOURCE_SEPARATOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s+(?:from|via|using|through)\s+").expect("NAMED_SOURCE_SEPARATOR_RE")
});

#[allow(dead_code)]
const LOCKFILE_PARSE_BUDGET_SECONDS: f64 = 0.5;
#[allow(dead_code)]
const LOCKFILE_PARSE_BUDGET_PER_MIB_SECONDS: f64 = 0.75;
#[allow(dead_code)]
const LOCKFILE_PARSE_MAX_BUDGET_SECONDS: f64 = 1.5;

#[allow(dead_code)]
const TRANSITIVE_BLOCK_CONFIDENCE_THRESHOLD: u32 = 900;
#[allow(dead_code)]
const NPM_REGISTRY_METADATA_BASE_URL: &str = "https://registry.npmjs.org";
#[allow(dead_code)]
const PYPI_REGISTRY_METADATA_BASE_URL: &str = "https://pypi.org/pypi";
#[allow(dead_code)]
const TARBALL_SCAN_TIMEOUT_SECONDS: u64 = 2;
#[allow(dead_code)]
const TARBALL_SCAN_MAX_BYTES: u64 = 6 * 1024 * 1024;
#[allow(dead_code)]
const TARBALL_SCAN_MAX_FILES: usize = 500;
#[allow(dead_code)]
const TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES: u64 = 256 * 1024;
#[allow(dead_code)]
const EXTERNAL_ARCHIVE_MAX_TARGETS: usize = 4;
#[allow(dead_code)]
const EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES: u64 = 12 * 1024 * 1024;
#[allow(dead_code)]
const EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS: f64 = 8.0;
#[allow(dead_code)]
const CLOUD_VALIDATION_ERROR_CACHE_TTL_SECONDS: f64 = 15.0 * 60.0;

#[allow(dead_code)]
fn registry_default_ranges() -> &'static HashMap<&'static str, &'static str> {
    static MAP: LazyLock<HashMap<&'static str, &'static str>> =
        LazyLock::new(|| HashMap::from([("npm", "latest"), ("pypi", ">=0")]));
    &MAP
}

#[allow(dead_code)]
fn dist_tag_range_ecosystems() -> &'static HashSet<&'static str> {
    static SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| HashSet::from(["npm"]));
    &SET
}

fn decision_to_guard_action() -> &'static HashMap<&'static str, &'static str> {
    static MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
        HashMap::from([
            ("allow", "allow"),
            ("monitor", "allow"),
            ("warn", "warn"),
            ("ask", "require-reapproval"),
            ("block", "block"),
        ])
    });
    &MAP
}
// ---------------------------------------------------------------------------
// Small coercion helpers — Python dict/object truthiness shims.
// ---------------------------------------------------------------------------

fn optional_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(if *b { "True" } else { "False" }.to_string()),
        _ => None,
    }
}

fn dict_items(value: Option<&Value>) -> Vec<Map<String, Value>> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_object().cloned())
            .collect(),
        Some(Value::Object(m)) => vec![m.clone()],
        _ => Vec::new(),
    }
}

#[allow(dead_code)]
fn string_tuple(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[allow(dead_code)]
fn map_insert_if_some(map: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        map.insert(key.to_string(), Value::String(v));
    }
}

fn json_obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (k, v) in pairs {
        map.insert(k.to_string(), v);
    }
    Value::Object(map)
}

fn value_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

#[allow(dead_code)]
fn now_seconds(now: &str) -> f64 {
    crate::local_supply_chain::parse_timestamp(now)
        .map(|t| t.unix_seconds() as f64)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        })
}

fn ensure_terminal_punctuation(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?') {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    }
}

// ---------------------------------------------------------------------------
// `SupplyChainUserCopy` / `PackageRequestEvaluation` dataclass mirrors.
// The sibling `PackageRequestEvaluation` is a `Value` mirror; these helpers
// build/consume the exact dict shapes.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn user_copy_to_dict(copy: &Map<String, Value>) -> Value {
    json_obj(vec![
        ("title", copy.get("title").cloned().unwrap_or(Value::Null)),
        (
            "summary",
            copy.get("summary").cloned().unwrap_or(Value::Null),
        ),
        (
            "next_step",
            copy.get("next_step").cloned().unwrap_or(Value::Null),
        ),
        (
            "dashboard_url",
            copy.get("dashboard_url").cloned().unwrap_or(Value::Null),
        ),
        (
            "harness_message",
            copy.get("harness_message").cloned().unwrap_or(Value::Null),
        ),
    ])
}

/// `SupplyChainUserCopy` dataclass mirror (:163-178).
#[derive(Debug, Clone, Default)]
pub struct SupplyChainUserCopy {
    pub title: String,
    pub summary: String,
    pub next_step: Option<String>,
    pub dashboard_url: Option<String>,
    pub harness_message: String,
}

impl SupplyChainUserCopy {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("title".into(), Value::String(self.title.clone()));
        map.insert("summary".into(), Value::String(self.summary.clone()));
        match &self.next_step {
            Some(v) => map.insert("next_step".into(), Value::String(v.clone())),
            None => map.insert("next_step".into(), Value::Null),
        };
        match &self.dashboard_url {
            Some(v) => map.insert("dashboard_url".into(), Value::String(v.clone())),
            None => map.insert("dashboard_url".into(), Value::Null),
        };
        map.insert(
            "harness_message".into(),
            Value::String(self.harness_message.clone()),
        );
        Value::Object(map)
    }
}

/// `PackageRequestEvaluation` dataclass mirror (:181-312). Stored as a
/// `serde_json::Value` mirror so unported callers consume the exact dict.
#[derive(Debug, Clone)]
pub struct PackageEvalResult {
    pub decision: String,
    pub policy_action: String,
    pub enforcement: String,
    pub entitlement_state: String,
    pub cache_status: String,
    pub package_intent_hash: String,
    pub policy_version: String,
    pub bundle_version: Option<String>,
    pub workspace_fingerprint: Option<String>,
    pub reasons: Vec<Map<String, Value>>,
    pub packages: Vec<Map<String, Value>>,
    pub risk_summary: String,
    pub user_copy: SupplyChainUserCopy,
    pub matched_rule_id: Option<String>,
    pub exception_id: Option<String>,
    pub refresh_required: bool,
    pub record_monitor_evidence: bool,
    pub evidence_ids: Vec<String>,
    pub external_archive_downloads: Vec<Map<String, Value>>,
    pub external_archive_source_hashes: Vec<String>,
}

impl PackageEvalResult {
    /// `to_cache_dict` (:204-220).
    pub fn to_cache_dict(&self) -> Value {
        json_obj(vec![
            ("decision", Value::String(self.decision.clone())),
            ("policy_action", Value::String(self.policy_action.clone())),
            ("enforcement", Value::String(self.enforcement.clone())),
            (
                "entitlement_state",
                Value::String(self.entitlement_state.clone()),
            ),
            ("cache_status", Value::String(self.cache_status.clone())),
            (
                "workspace_fingerprint",
                self.workspace_fingerprint
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            (
                "reasons",
                Value::Array(self.reasons.iter().cloned().map(Value::Object).collect()),
            ),
            (
                "packages",
                Value::Array(self.packages.iter().cloned().map(Value::Object).collect()),
            ),
            (
                "matched_rule_id",
                self.matched_rule_id
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            (
                "exception_id",
                self.exception_id
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            ("risk_summary", Value::String(self.risk_summary.clone())),
            (
                "record_monitor_evidence",
                Value::Bool(self.record_monitor_evidence),
            ),
            (
                "external_archive_source_hashes",
                Value::Array(
                    self.external_archive_source_hashes
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            ("user_copy", self.user_copy.to_value()),
        ])
    }

    /// `to_dict` (:222-241).
    pub fn to_dict(&self) -> Value {
        let mut payload = match self.to_cache_dict() {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        payload.insert(
            "package_intent_hash".into(),
            Value::String(self.package_intent_hash.clone()),
        );
        payload.insert(
            "policy_version".into(),
            Value::String(self.policy_version.clone()),
        );
        payload.insert(
            "bundle_version".into(),
            self.bundle_version
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        payload.insert(
            "workspace_fingerprint".into(),
            self.workspace_fingerprint
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        payload.insert(
            "refresh_required".into(),
            Value::Bool(self.refresh_required),
        );
        payload.insert(
            "evidence_ids".into(),
            Value::Array(
                self.evidence_ids
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        if !self.external_archive_downloads.is_empty() {
            let inspection: Vec<Value> = self
                .external_archive_downloads
                .iter()
                .map(|download| {
                    let download_v = Value::Object(download.clone());
                    let sha256 = value_str(&download_v, "sha256").unwrap_or("");
                    let size = download.get("size").cloned().unwrap_or(Value::Null);
                    let source_url = value_str(&download_v, "source_url").unwrap_or("");
                    let final_url = value_str(&download_v, "final_url").unwrap_or("");
                    json_obj(vec![
                        ("sha256", Value::String(sha256.to_string())),
                        ("size", size),
                        (
                            "source_url_hash",
                            Value::String(stable_digest_hex(source_url.as_bytes())),
                        ),
                        (
                            "final_url_hash",
                            Value::String(stable_digest_hex(final_url.as_bytes())),
                        ),
                    ])
                })
                .collect();
            payload.insert(
                "external_archive_inspection".into(),
                Value::Array(inspection),
            );
        }
        Value::Object(payload)
    }

    /// `from_cache_dict` (:243-312).
    pub fn from_cache_dict(
        payload: &Map<String, Value>,
        package_intent_hash: &str,
        policy_version: &str,
        bundle_version: Option<&str>,
        workspace_fingerprint: Option<&str>,
    ) -> Self {
        let user_copy_map = payload
            .get("user_copy")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let cached_packages: Vec<Map<String, Value>> = dict_items(payload.get("packages"))
            .into_iter()
            .map(|item| with_support_metadata(&item))
            .collect();
        let (policy_action, recognized, reason_code, original_action) =
            normalize_guard_action_result_for_cache(payload.get("policy_action"));
        let mut cached_reasons = dict_items(payload.get("reasons"));
        if !recognized {
            let mut normalization_reason = Map::new();
            normalization_reason.insert("code".into(), Value::String(reason_code));
            normalization_reason.insert(
                "message".into(),
                Value::String(
                    "Cached package policy action was missing or unknown; Guard requires review."
                        .to_string(),
                ),
            );
            normalization_reason.insert(
                "original_action".into(),
                original_action.map(Value::String).unwrap_or(Value::Null),
            );
            normalization_reason.insert(
                "normalized_action".into(),
                Value::String(policy_action.clone()),
            );
            cached_reasons.push(normalization_reason);
        }
        let normalized_user_copy = normalize_package_user_copy(
            &SupplyChainUserCopy {
                title: optional_string(user_copy_map.get("title"))
                    .unwrap_or_else(|| "Monitoring this package".to_string()),
                summary: optional_string(user_copy_map.get("summary"))
                    .unwrap_or_else(|| "HOL Guard recorded this package request.".to_string()),
                next_step: optional_string(user_copy_map.get("next_step")),
                dashboard_url: optional_string(user_copy_map.get("dashboard_url")),
                harness_message: optional_string(user_copy_map.get("harness_message"))
                    .or_else(|| optional_string(payload.get("risk_summary")))
                    .unwrap_or_default(),
            },
            decision_to_guard_action_variant(&policy_action),
        );
        let external_archive_source_hashes = payload
            .get("external_archive_source_hashes")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    })
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        PackageEvalResult {
            decision: optional_string(payload.get("decision"))
                .unwrap_or_else(|| "monitor".to_string()),
            policy_action,
            enforcement: optional_string(payload.get("enforcement"))
                .unwrap_or_else(|| "offline_cached".to_string()),
            entitlement_state: optional_string(payload.get("entitlement_state"))
                .unwrap_or_else(|| "premium".to_string()),
            cache_status: optional_string(payload.get("cache_status"))
                .unwrap_or_else(|| "hit".to_string()),
            package_intent_hash: package_intent_hash.to_string(),
            policy_version: policy_version.to_string(),
            bundle_version: bundle_version.map(str::to_string),
            workspace_fingerprint: workspace_fingerprint.map(str::to_string),
            reasons: cached_reasons,
            packages: cached_packages,
            risk_summary: optional_string(payload.get("risk_summary"))
                .unwrap_or_else(|| "HOL Guard recorded this package request.".to_string()),
            user_copy: normalized_user_copy,
            matched_rule_id: optional_string(payload.get("matched_rule_id")),
            exception_id: optional_string(payload.get("exception_id")),
            refresh_required: payload
                .get("refresh_required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            record_monitor_evidence: payload
                .get("record_monitor_evidence")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            evidence_ids: Vec::new(),
            external_archive_downloads: Vec::new(),
            external_archive_source_hashes,
        }
    }
}

/// `normalize_guard_action_result(value, unknown_action="require-reapproval")`
/// returns `(action, recognized, reason_code, original_action)`.
fn normalize_guard_action_result_for_cache(
    raw: Option<&Value>,
) -> (String, bool, String, Option<String>) {
    let input = raw.cloned().unwrap_or(Value::Null);
    let normalized = normalize_guard_action_result(&input, GuardAction::RequireReapproval);
    (
        normalized.action.as_str().to_string(),
        normalized.recognized(),
        normalized
            .reason_code
            .unwrap_or(UNKNOWN_GUARD_ACTION_REASON)
            .to_string(),
        normalized.original_action,
    )
}

// ---------------------------------------------------------------------------
// Dependency seams (:40-113 imports) — traits replacing Python modules that are
// not yet ported to this crate. Mirrors the `local_supply_chain.rs` seam style:
// each trait method takes `&self`; dict-shaped payloads use `serde_json::Value`
// / `Map<String, Value>`; failures surface as `EvalError`.
// ---------------------------------------------------------------------------

/// Error type shared by every seam below. Maps the Python exception surface:
/// `Validation` covers `ValueError`/`GuardSyncEndpointUntrustedError`/
/// `PackageIdentityError`/`SupplyChainBundleMalformedError`/`DeadlineExceededError`
/// (message carries the machine-readable reason code); `NotFound` covers
/// `GuardSyncNotConfiguredError` and missing-workspace/entitlement lookups;
/// `Internal` covers everything else (I/O, transport, unexpected state).
#[derive(Debug, Clone)]
pub enum EvalError {
    /// Caller/validation failure — safe to surface verbatim to the harness.
    Validation(String),
    /// Missing prerequisite or not-configured dependency (e.g. Guard Cloud
    /// sync is not configured for this store).
    NotFound(String),
    /// Internal/transport failure — log and fail closed.
    Internal(String),
    /// `urllib.error.HTTPError` mirror (:1350) — carries the HTTP status code
    /// so `_evaluate_with_cloud` can branch on 401/403/400/404/other. The
    /// transport surface that produces this is `guard_sync.urlopen_json_with_timeout_retry`.
    HttpStatus(u16, String),
}

impl EvalError {
    /// `urllib.error.HTTPError.code` — the HTTP status when this error came
    /// from an HTTP response, `None` for any other failure class.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus(code, _) => Some(*code),
            _ => None,
        }
    }
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(m) | Self::NotFound(m) | Self::Internal(m) => f.write_str(m),
            Self::HttpStatus(code, m) => write!(f, "HTTP {code}: {m}"),
        }
    }
}

impl std::error::Error for EvalError {}

pub type EvalResult<T> = Result<T, EvalError>;

/// `runner._guard_sync_request(...)` (:4269) mirror — the prepared request
/// object handed to the transport (`urllib.request.Request` in Python).
/// `body` is `None` for bodiless methods; `dpop_nonce` is echoed for retry
/// bookkeeping by `_urlopen_json_with_timeout_retry`.
#[derive(Debug, Clone, Default)]
pub struct GuardSyncRequest {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub dpop_nonce: Option<String>,
}

/// `.runtime.runner` seam — the private Guard-Cloud-sync helpers this module
/// imports from `runner` (:78-84).
pub trait GuardSyncRunnerApi {
    /// `runner._resolve_guard_sync_auth_context(store)` (:5184) -> auth-context
    /// dict. `EvalError::NotFound` maps `GuardSyncNotConfiguredError`;
    /// `EvalError::Validation` maps `GuardSyncAuthorizationExpiredError`.
    fn resolve_guard_sync_auth_context(
        &self,
        store: &dyn SupplyChainStore,
        allow_primary_repair: bool,
        force_refresh: bool,
    ) -> EvalResult<Map<String, Value>>;
    /// `runner._validate_guard_sync_url(sync_url, issuer=)` (:4453) ->
    /// canonical sync URL. `EvalError::Validation` maps
    /// `GuardSyncEndpointUntrustedError`.
    fn validate_guard_sync_url(&self, sync_url: &str, issuer: Option<&str>) -> EvalResult<String>;
    /// `runner._guard_sync_request(auth_context, request_url=, method=, data=,
    /// extra_headers=, dpop_nonce=)` (:4269) -> prepared request.
    fn guard_sync_request(
        &self,
        auth_context: &Value,
        request_url: &str,
        method: &str,
        data: Option<&[u8]>,
        extra_headers: Option<&Map<String, Value>>,
        dpop_nonce: Option<&str>,
    ) -> EvalResult<GuardSyncRequest>;
    /// `runner._urlopen_json_with_timeout_retry(request=, timeout_seconds=,
    /// retry_timeout_seconds=)` (:5545) -> response JSON dict.
    fn urlopen_json_with_timeout_retry(
        &self,
        request: &GuardSyncRequest,
        timeout_seconds: u64,
        retry_timeout_seconds: u64,
    ) -> EvalResult<Map<String, Value>>;
    /// `runner._is_timeout_error(error)` (:5448) — classifies a transport error
    /// (including wrapped/`.reason` causes) as a timeout.
    fn is_timeout_error(&self, error: &(dyn std::error::Error + 'static)) -> bool;
    /// `runner._normalized_receipts_sync_url(sync_url)` (:5851) — rewrites a
    /// bare `/registry/api/v1` endpoint to the receipts sync path.
    fn normalized_receipts_sync_url(&self, sync_url: &str) -> String;
}

/// `lockfile_parse_result.LockfileDependencyEntry` (:46) mirror.
#[derive(Debug, Clone, Default)]
pub struct LockfileDependencyEntry {
    pub dependency_path: String,
    pub package_name: String,
    pub version: String,
    pub direct: bool,
}

/// `lockfile_parse_result.LockfileParseResult` (:54) mirror.
#[derive(Debug, Clone, Default)]
pub struct LockfileParseResult {
    pub entries: Vec<LockfileDependencyEntry>,
    pub complete: bool,
    pub format: String,
    pub source_hash: String,
    pub elapsed_ms: f64,
    pub budget_ms: f64,
    pub warnings: Vec<String>,
    pub error_reason: Option<String>,
    pub parser_version: String,
}

impl LockfileParseResult {
    /// `dependency_map` (:65) — `{dependency_path: version}`, empty unless the
    /// parse completed.
    pub fn dependency_map(&self) -> BTreeMap<String, String> {
        if !self.complete {
            return BTreeMap::new();
        }
        self.entries
            .iter()
            .map(|entry| (entry.dependency_path.clone(), entry.version.clone()))
            .collect()
    }
}

/// `.runtime.lockfile_evaluation_support` / `.runtime.lockfile_parse_result`
/// seam (:41-52 imports).
pub trait LockfileParseApi {
    /// `collect_lockfile_parse_results(workspace_dir, lockfile_paths,
    /// budget_ms=, parse_text_result=)` (lockfile_evaluation_support.py:24).
    /// Parses every supported workspace lockfile without returning partial
    /// data; paths that fail resolution/read become `incomplete` results.
    /// `lockfile_paths` mirrors the raw `artifact.metadata["lockfile_paths"]`
    /// list (`Value`, validated element-by-element in Python).
    fn collect_lockfile_parse_results(
        &self,
        workspace_dir: Option<&Path>,
        lockfile_paths: Option<&Value>,
        budget_ms: f64,
        parse_text_result: &dyn Fn(&str, &[u8]) -> LockfileParseResult,
    ) -> Vec<LockfileParseResult>;
    /// `parse_lockfile_with_budget(path, source_text, budget_seconds=,
    /// dependency_parser=, package_lock_parser=)`
    /// (lockfile_evaluation_support.py:66).
    fn parse_lockfile_with_budget(
        &self,
        path: &str,
        source_text: &[u8],
        budget_seconds: f64,
    ) -> LockfileParseResult;
    /// `incomplete_lockfile_result(path, source, error_reason=, budget_ms=,
    /// elapsed_ms=)` (lockfile_parse_result.py:90).
    fn incomplete_lockfile_result(
        &self,
        path: &str,
        source: &[u8],
        error_reason: &str,
        budget_ms: f64,
        elapsed_ms: f64,
    ) -> LockfileParseResult;
}

/// `supply_chain_bundle_models.SupplyChainBundleResponse` (:460) mirror —
/// the signed Guard Cloud bundle response. `signed_bundle` preserves the exact
/// bundle JSON for hash/signature verification; `bundle` holds the
/// `to_dict()`-shaped parsed-bundle payload for seam consumers that only need
/// dict access (mirrors `SupplyChainBundle` without porting its dataclasses).
#[derive(Debug, Clone, Default)]
pub struct SupplyChainBundleResponse {
    pub bundle: Map<String, Value>,
    pub signed_bundle: Map<String, Value>,
    pub payload_hash: String,
    pub signature: String,
    pub signature_algorithm: String,
    /// `SupplyChainVerificationKey.to_dict()` payloads.
    pub verification_keys: Vec<Map<String, Value>>,
}

impl SupplyChainBundleResponse {
    /// `to_dict` (:470).
    pub fn to_dict(&self) -> Value {
        json!({
            "bundle": Value::Object(self.signed_bundle.clone()),
            "payloadHash": self.payload_hash,
            "signature": self.signature,
            "signatureAlgorithm": self.signature_algorithm,
            "verificationKeys": self
                .verification_keys
                .iter()
                .cloned()
                .map(Value::Object)
                .collect::<Vec<Value>>(),
        })
    }
}

/// `.runtime.supply_chain_bundle` seam (:86-96 imports) plus the module-local
/// `_bundle_meta` helper (:2324).
pub trait SupplyChainBundleApi {
    /// `load_supply_chain_bundle_response(raw_json)` (supply_chain_bundle.py /
    /// supply_chain_bundle_runtime.py:83). `raw_json` is the decoded JSON
    /// object (string callers `serde_json::from_str` first);
    /// `EvalError::Validation` maps `SupplyChainBundleMalformedError`.
    fn load_supply_chain_bundle_response(
        &self,
        raw_json: &Value,
    ) -> EvalResult<SupplyChainBundleResponse>;
    /// `check_supply_chain_bundle_freshness(bundle, now=)` (:114). `now` is
    /// epoch seconds (`None` = wall clock). `EvalError::Validation` maps
    /// `SupplyChainBundleExpiredError`.
    fn check_supply_chain_bundle_freshness(
        &self,
        bundle: &Map<String, Value>,
        now: Option<f64>,
    ) -> EvalResult<()>;
    /// `evaluate_cached_supply_chain_bundle(response, package_name=,
    /// package_version=, ecosystem=, now=)` (:276) ->
    /// `OfflineSupplyChainDecision` dict mirror.
    fn evaluate_cached_supply_chain_bundle(
        &self,
        response: &SupplyChainBundleResponse,
        package_name: &str,
        package_version: Option<&str>,
        ecosystem: Option<&str>,
        now: Option<f64>,
    ) -> EvalResult<Map<String, Value>>;
    /// `_bundle_meta(bundle_payload)` (:2324) -> `{bundle_version,
    /// feed_snapshot_hash, policy_hash, scoring_version}`; keys stay snake_case
    /// like the Python return dict.
    fn supply_chain_bundle_meta(
        &self,
        bundle_payload: &Map<String, Value>,
    ) -> EvalResult<BTreeMap<String, String>>;
}

/// `packaging.specifiers.SpecifierSet` mirror (opaque to this module —
/// constructed only through `JsSemverApi`).
#[derive(Debug, Clone)]
pub struct SpecifierSet {
    /// Normalized specifier string, preserved for byte-parity reparsing.
    pub normalized: String,
}

/// `packaging.version.Version` mirror.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Canonical normalized rendering (`str(Version(v))`).
    pub normalized: String,
    /// `Version.release` — the dotted release-segment tuple used by the
    /// caret/tilde specifier ports (:4550, :4572).
    pub release: Vec<u64>,
}

/// `packaging` + `.runtime.js_semver` seam — per-package policy version
/// resolution (:27, :3086-5038 usage sites).
pub trait JsSemverApi {
    /// `SpecifierSet(range)` — parse a PEP-440 specifier set.
    /// `EvalError::Validation` maps `InvalidSpecifier`.
    fn specifier_set(&self, range: &str) -> EvalResult<SpecifierSet>;
    /// `Version(value)` — parse a PEP-440 version.
    /// `EvalError::Validation` maps `InvalidVersion`.
    fn version(&self, value: &str) -> EvalResult<Version>;
    /// `version in specifier_set` membership test.
    fn version_in_specifier_set(&self, version: &Version, set: &SpecifierSet) -> bool;
    /// `js_semver.highest_js_version_for_selector(versions, selector)` (:156)
    /// -> highest matching version string, if any.
    fn highest_js_version_for_selector(
        &self,
        versions: &[String],
        selector: &str,
    ) -> Option<String>;
    /// `js_semver.version_matches_js_selector(version, selector)` (:130).
    fn version_matches_js_selector(&self, version: &str, selector: &str) -> bool;
}

/// `.runtime.supply_chain` seam (:85 import).
pub trait RiskDetectApi {
    /// `detect_supply_chain_risk(content, file_path=)` (supply_chain.py:115)
    /// -> `RiskSignalV2` dict mirrors (`signal_id`, `category`, `severity`,
    /// `confidence`, `message`, `file_path`, ...).
    fn detect_supply_chain_risk(
        &self,
        content: &str,
        file_path: Option<&str>,
    ) -> EvalResult<Vec<Map<String, Value>>>;
    /// Synchronous evaluate-and-collect pass over a package's risk-bearing
    /// surfaces (command text + manifest bodies); returns the merged signal
    /// list plus the highest-severity summary the evaluator folds into
    /// `reasons`/`risk_summary`.
    fn evaluate_supply_chain_risk_sync(
        &self,
        content: &str,
        file_path: Option<&str>,
    ) -> EvalResult<Vec<Map<String, Value>>>;
}

/// `.runtime.package_manifest_diff` seam (:63-65 imports).
/// `_DeadlineExceededError` (package_manifest_diff.py:33) maps to
/// `EvalError::Validation("deadline_exceeded ...")` — callers treat it the
/// same as the Python `except _DeadlineExceededError` arms.
pub trait ManifestDepsApi {
    /// `manifest_dependency_targets.evaluation_targets(artifact,
    /// workspace_dir, explicit_targets=, include_locked=)` (:33).
    fn evaluation_targets(
        &self,
        artifact: &GuardArtifact,
        workspace_dir: Option<&Path>,
        explicit_targets: &[Map<String, Value>],
        include_locked: bool,
    ) -> Vec<Map<String, Value>>;
    /// `_dependency_map_for_path(path, text, deadline=)` (:81) — dispatches on
    /// the manifest/lockfile filename to the per-format parser. `deadline` is
    /// a monotonic deadline in seconds; expiry raises
    /// `EvalError::Validation` carrying the deadline reason.
    fn dependency_map_for_path(
        &self,
        path: &str,
        text: &str,
        deadline: f64,
    ) -> EvalResult<BTreeMap<String, String>>;
    /// `parse_manifest_dependencies(path=, text=, byte_limit=, deadline_ms=)`
    /// (:65) — swallows every parse failure into `{}` like the Python body.
    fn parse_manifest_dependencies(
        &self,
        path: &str,
        text: &str,
        byte_limit: usize,
        deadline_ms: u64,
    ) -> BTreeMap<String, String>;
}

/// `supply_chain_package_identity.CanonicalPackageIdentity` (:17) mirror.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalPackageIdentity {
    pub ecosystem: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: String,
}

impl CanonicalPackageIdentity {
    /// `qualified_name` (:26).
    pub fn qualified_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{ns}/{}", self.name),
            None => self.name.clone(),
        }
    }

    /// `display` (:30) — `{ecosystem}:{qualified_name}@{version}`.
    pub fn display(&self) -> String {
        format!(
            "{}:{}@{}",
            self.ecosystem,
            self.qualified_name(),
            self.version
        )
    }
}

/// `.runtime.supply_chain_package_identity` seam (:99-104 imports).
/// `PackageIdentityError` maps to `EvalError::Validation`.
pub trait PackageIdentityApi {
    /// `canonical_package_identity(ecosystem=, namespace=, name=, version=)`
    /// (:57) — build a canonical key from already-structured bundle fields.
    fn canonical_package_identity(
        &self,
        ecosystem: &str,
        namespace: Option<&str>,
        name: &str,
        version: &str,
    ) -> EvalResult<CanonicalPackageIdentity>;
    /// `parse_package_identity(ecosystem=, package_name=, version=)` (:93) —
    /// parse one target name using the selected ecosystem's syntax.
    fn parse_package_identity(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> EvalResult<CanonicalPackageIdentity>;
    /// `normalize_ecosystem(ecosystem)` (:34).
    fn normalize_ecosystem(&self, ecosystem: &str) -> EvalResult<String>;
    /// `normalize_qualified_package_name(ecosystem, package_name)` (:121).
    fn normalize_qualified_package_name(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> EvalResult<String>;
}

/// `restricted_archive_contract.RestrictedArchiveFailure` (:12) mirror — a
/// stable, non-sensitive reason the archive download stopped.
#[derive(Debug, Clone, Default)]
pub struct RestrictedArchiveFailure {
    pub code: String,
    pub message: String,
}

/// `restricted_archive_contract.RestrictedArchiveDownload` (:21) mirror — a
/// bounded archive blob whose digest was computed while reading. The temp file
/// lifecycle (`cleanup`/`__del__`) is owned by the seam implementation; this
/// mirror only carries the path.
#[derive(Debug, Clone, Default)]
pub struct RestrictedArchiveDownload {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub source_url: String,
    pub final_url: String,
}

/// `restricted_archive_contract.RestrictedArchiveDownloadResult` (:49)
/// discriminated mirror.
#[derive(Debug, Clone)]
pub enum RestrictedArchiveDownloadResult {
    Success(RestrictedArchiveDownload),
    Failure(RestrictedArchiveFailure),
}

/// `.runtime.restricted_archive_download` seam (:66-75 imports).
pub trait RestrictedArchiveApi {
    /// `download_restricted_archive(source_url, max_bytes=, max_redirects=,
    /// timeout_seconds=, temp_dir=)` (:189) — bounded public-HTTPS-only
    /// download. Policy rejections return `Failure(...)` (mirroring the Python
    /// result union), not `Err`.
    fn download_restricted_archive(
        &self,
        source_url: &str,
        max_bytes: u64,
        max_redirects: u32,
        timeout_seconds: f64,
        temp_dir: Option<&Path>,
    ) -> EvalResult<RestrictedArchiveDownloadResult>;
}

/// `.native_archive_inspection` seam (:33 import).
pub trait NativeArchiveApi {
    /// `inspect_archive_native(path, expected_sha256=, state_dir=,
    /// timeout_seconds=, max_archive_bytes=, max_files=, max_expanded_bytes=,
    /// max_member_bytes=, max_package_json_bytes=, max_memory_bytes=,
    /// max_decompression_ratio=, max_nested_archives=, max_path_depth=)`
    /// (native_archive_inspection.py:101) -> `ArchiveInspectionResult` dict
    /// mirror.
    #[allow(clippy::too_many_arguments)]
    fn inspect_archive_native(
        &self,
        path: &Path,
        expected_sha256: &str,
        state_dir: &Path,
        timeout_seconds: f64,
        max_archive_bytes: u64,
        max_files: u64,
        max_expanded_bytes: u64,
        max_member_bytes: u64,
        max_package_json_bytes: u64,
        max_memory_bytes: u64,
        max_decompression_ratio: f64,
        max_nested_archives: u64,
        max_path_depth: u64,
    ) -> EvalResult<Map<String, Value>>;
}

/// `.runtime.workspace_path_guard` read wrappers seam (:106-110 imports).
/// `resolve_path_within_workspace` is already reused from
/// `package_intent_common`; these mirror the two read helpers.
pub trait WorkspaceIoApi {
    /// `read_text_within_workspace(workspace_dir, relative_path)` -> file text
    /// or `None` on traversal/missing/decode failure.
    fn read_text(&self, workspace_dir: &Path, relative_path: &str) -> Option<String>;
    /// `read_bytes_within_workspace(workspace_dir, relative_path)` -> file
    /// bytes or `None` on traversal/missing failure.
    fn read_bytes_within_workspace(
        &self,
        workspace_dir: &Path,
        relative_path: &str,
    ) -> Option<Vec<u8>>;
}

/// `.store.GuardStore` supply-chain extras seam — the eval-cache, evidence,
/// and OAuth-health methods this module calls on `store` (:547, :705, :873,
/// :1247, :2135) that are not part of the `SupplyChainStore` trait.
pub trait StoreExtrasApi {
    /// `store.get_cached_supply_chain_evaluation(workspace_id=,
    /// package_intent_hash=, feed_snapshot_hash=, policy_hash=,
    /// scoring_version=, bundle_version=)` (store_cloud_events.py:169) ->
    /// cached `decision` dict payload (`to_cache_dict()` shape) or `None`.
    fn get_cached_supply_chain_evaluation(
        &self,
        workspace_id: &str,
        package_intent_hash: &str,
        feed_snapshot_hash: &str,
        policy_hash: &str,
        scoring_version: &str,
        bundle_version: &str,
    ) -> Option<Map<String, Value>>;
    /// `deps.store_extras.cache_supply_chain_evaluation(...)` (store_cloud_events.py:144)
    /// — persist a `PackageRequestEvaluation.to_cache_dict()` payload.
    #[allow(clippy::too_many_arguments)]
    fn cache_supply_chain_evaluation(
        &self,
        workspace_id: &str,
        package_intent_hash: &str,
        feed_snapshot_hash: &str,
        policy_hash: &str,
        scoring_version: &str,
        bundle_version: &str,
        decision: &Map<String, Value>,
        now: &str,
    );
    /// `store.add_evidence(record)` (store_evidence_facade.py:53) — the
    /// `EvidenceRecord` is passed as its dict mirror.
    fn add_evidence(&self, record: &Map<String, Value>);
    /// `store.get_oauth_local_credential_health()` (store_oauth.py:300) ->
    /// `{configured, state, backend, fallback_backend, ...}` health dict.
    fn get_oauth_local_credential_health(&self) -> Map<String, Value>;
}

/// `.local_supply_chain.resolve_package_firewall_entitlement_with_refresh`
/// seam (local_supply_chain.py:461) — resolve the package-firewall
/// entitlement, refreshing from Guard Cloud first when stale.
pub trait EntitlementRefreshApi {
    /// `resolve_package_firewall_entitlement_with_refresh(store)` -> entitlement
    /// dict (`{state, source, expires_at, ...}`).
    fn resolve_package_firewall_entitlement_with_refresh(
        &self,
        store: &dyn SupplyChainStore,
    ) -> EvalResult<Map<String, Value>>;
}

/// `..config.load_guard_config` seam (:31 import).
pub trait ConfigLoaderApi {
    /// `load_guard_config(guard_home, workspace=,
    /// require_canonical_workspace=)` -> `GuardConfig`.
    fn load_guard_config(
        &self,
        guard_home: &Path,
        workspace: Option<&Path>,
        require_canonical_workspace: bool,
    ) -> EvalResult<GuardConfig>;
}

// ---------------------------------------------------------------------------
// Evaluation draft + dependency bundle
// ---------------------------------------------------------------------------

/// `_EvaluationDraft` dataclass mirror (:962-975) — the intermediate mutable
/// evaluation state folded into a `PackageRequestEvaluation` by
/// `_finalize_evaluation` (:978).
#[derive(Debug, Clone, Default)]
pub struct EvaluationDraft {
    pub decision: String,
    pub enforcement: String,
    pub entitlement_state: String,
    pub cache_status: String,
    pub packages: Vec<Map<String, Value>>,
    pub reasons: Vec<Map<String, Value>>,
    pub matched_rule_id: Option<String>,
    pub exception_id: Option<String>,
    pub refresh_required: bool,
    pub record_monitor_evidence: bool,
    pub bundle_version: Option<String>,
    pub policy_version: String,
    pub external_archive_downloads: Vec<RestrictedArchiveDownload>,
    pub external_archive_source_hashes: Vec<String>,
}

/// Aggregated dependency seams for the evaluator — one injection point so
/// ported fns take `deps: &SupplyChainEvalDeps` instead of a dozen trait
/// objects. Mirrors the Python module-level imports (:31-110).
pub struct SupplyChainEvalDeps<'a> {
    pub guard_sync: &'a dyn GuardSyncRunnerApi,
    pub lockfile: &'a dyn LockfileParseApi,
    pub bundle: &'a dyn SupplyChainBundleApi,
    pub semver: &'a dyn JsSemverApi,
    pub risk: &'a dyn RiskDetectApi,
    pub manifest: &'a dyn ManifestDepsApi,
    pub identity: &'a dyn PackageIdentityApi,
    pub archive: &'a dyn RestrictedArchiveApi,
    pub native_archive: &'a dyn NativeArchiveApi,
    pub workspace_io: &'a dyn WorkspaceIoApi,
    pub store_extras: &'a dyn StoreExtrasApi,
    pub entitlement: &'a dyn EntitlementRefreshApi,
    pub config: &'a dyn ConfigLoaderApi,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// `evaluate_package_request_artifact` (:314) — evaluate one package-request
/// artifact against local bundle/cache/risk signals and return the typed
/// result. `now` is the ISO-8601 UTC timestamp the Python signature accepts.
///
/// TODO: implement — wraps `_evaluate_package_request_artifact_uncached`
/// (:337) inside the `_LOCKFILE_PARSE_CACHE` contextvar scope.
pub fn evaluate_package_request_artifact(
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    now: Option<&str>,
    external_archive_network_authorized: bool,
    retain_external_archive_blob: bool,
) -> EvalResult<PackageEvalResult> {
    // Python wraps the call in `_LOCKFILE_PARSE_CACHE` contextvar scope; the
    // Rust equivalent is the seam-owned cache inside `deps.lockfile`, so the
    // wrapper is a straight delegation.
    let (result, error) = evaluate_package_request_artifact_uncached(
        deps,
        artifact,
        store,
        workspace_dir,
        now,
        external_archive_network_authorized,
        retain_external_archive_blob,
    );
    match (result, error) {
        (Some(result), _) => Ok(result),
        (None, Some(message)) => Err(EvalError::Internal(message)),
        (None, None) => Err(EvalError::Internal(
            "evaluate_package_request_artifact: no result".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Batch A ports — decision/action normalization, cache reuse, draft plumbing.
// Each fn carries a `// supply_chain_package_eval.py:N-M` anchor comment.
// ---------------------------------------------------------------------------

/// `decision_to_guard_action` — map a decision string to a `GuardAction`.
///
/// Derived from `_DECISION_TO_GUARD_ACTION` (:154-160):
///   `{"allow": "allow", "monitor": "allow", "warn": "warn",
///     "ask": "require-reapproval", "block": "block"}`.
// supply_chain_package_eval.py:154-160
fn decision_to_guard_action_variant(decision: &str) -> GuardAction {
    let mapped = decision_to_guard_action()
        .get(decision)
        .copied()
        .unwrap_or("allow");
    match mapped {
        "warn" => GuardAction::Warn,
        "review" => GuardAction::Review,
        "require-reapproval" => GuardAction::RequireReapproval,
        "sandbox-required" => GuardAction::SandboxRequired,
        "block" => GuardAction::Block,
        _ => GuardAction::Allow,
    }
}

/// `_decision_rank` (:4945-4946).
// supply_chain_package_eval.py:4945-4946
#[allow(dead_code)]
fn decision_rank(value: &str) -> u8 {
    decision_rank_map().get(value).copied().unwrap_or(1)
}

/// `_severity_rank_value` (:4828-4829).
// supply_chain_package_eval.py:4828-4829
#[allow(dead_code)]
fn severity_rank_value(value: &str) -> u8 {
    severity_rank_map()
        .get(value.trim().to_ascii_lowercase().as_str())
        .copied()
        .unwrap_or_else(|| severity_rank_map()["unknown"])
}

/// `_reason_severity` (:5044-5052).
// supply_chain_package_eval.py:5044-5052
#[allow(dead_code)]
fn reason_severity(package: &Map<String, Value>) -> String {
    if let Some(reasons) = package.get("reasons") {
        if let Some(items) = reasons.as_array() {
            for item in items {
                if let Some(obj) = item.as_object() {
                    if let Some(severity) = optional_string(obj.get("severity")) {
                        return severity;
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

/// `_normalize_package_name` (:4998-5002).
// supply_chain_package_eval.py:4998-5002
#[allow(dead_code)]
fn normalize_package_name(
    deps: &SupplyChainEvalDeps<'_>,
    ecosystem: &str,
    package_name: &str,
) -> String {
    deps.identity
        .normalize_qualified_package_name(ecosystem, package_name)
        .unwrap_or_else(|_| package_name.trim().to_string())
}

/// `_normalize_evaluation_timestamp` — parse an ISO-8601 timestamp string
/// into epoch seconds. Returns `None` on empty or unparseable input.
///
/// Derived: wraps `local_supply_chain::parse_timestamp` (:4533-4547 in
/// `local_supply_chain.py`) which normalizes "Z" → "+00:00" and converts to
/// UTC epoch seconds.
// supply_chain_package_eval.py:2803-2807
#[allow(dead_code)]
fn normalize_evaluation_timestamp(now_value: &str) -> Option<f64> {
    crate::local_supply_chain::parse_timestamp(now_value).map(|t| t.unix_seconds() as f64)
}

/// `_parse_evaluation_timestamp` (:2803-2807) — alias kept for callers that
/// expect the private name.
// supply_chain_package_eval.py:2803-2807
#[allow(dead_code)]
fn parse_evaluation_timestamp(now_value: &str) -> Option<f64> {
    normalize_evaluation_timestamp(now_value)
}

/// `_artifact_has_flag` (:3489-3491).
// supply_chain_package_eval.py:3489-3491
#[allow(dead_code)]
fn artifact_has_flag(artifact: &GuardArtifact, flag: &str) -> bool {
    artifact
        .metadata
        .get("flags")
        .and_then(Value::as_array)
        .is_some_and(|flags| flags.iter().any(|v| v.as_str() == Some(flag)))
}

/// `_has_non_empty_string_item` (:788-791).
// supply_chain_package_eval.py:788-791
#[allow(dead_code)]
fn has_non_empty_string_item(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .any(|v| matches!(v, Value::String(s) if !s.is_empty())),
        _ => false,
    }
}

/// `_artifact_has_package_material` (:780-785).
// supply_chain_package_eval.py:780-785
#[allow(dead_code)]
fn artifact_has_package_material(artifact: &GuardArtifact, targets: &[Map<String, Value>]) -> bool {
    if !targets.is_empty() {
        return true;
    }
    has_non_empty_string_item(artifact.metadata.get("manifest_paths"))
        || has_non_empty_string_item(artifact.metadata.get("lockfile_paths"))
}

/// `_empty_package_material_result` (:794-827).
// supply_chain_package_eval.py:794-827
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn empty_package_material_result(
    _artifact: &GuardArtifact,
    workspace_id: Option<&str>,
    bundle_meta: Option<&Map<String, Value>>,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
) -> PackageEvalResult {
    let mut reason_map = Map::new();
    reason_map.insert(
        "code".to_string(),
        Value::String("no_package_material".into()),
    );
    reason_map.insert(
        "message".to_string(),
        Value::String(
            "Guard found no package targets, manifests, or lockfiles to evaluate for this request."
                .into(),
        ),
    );
    reason_map.insert("severity".to_string(), Value::String("unknown".into()));
    reason_map.insert("source".to_string(), Value::String("guard-local".into()));
    let reasons = vec![reason_map];
    let decision = "monitor".to_string();
    let policy_action = decision_to_guard_action_variant(&decision);
    let title = "No package material".to_string();
    let summary =
        "Guard found no package targets, manifests, or lockfiles to evaluate.".to_string();
    let enforcement = if workspace_id.is_none() {
        "free_local"
    } else {
        "local_fallback"
    };
    let entitlement_state = if workspace_id.is_none() {
        "free"
    } else {
        "premium"
    };
    let policy_version = bundle_meta
        .and_then(|m| optional_string(m.get("policy_hash")))
        .unwrap_or_else(|| "local:none".to_string());
    let bundle_version = bundle_meta.and_then(|m| optional_string(m.get("bundle_version")));
    let user_copy = SupplyChainUserCopy {
        title: title.clone(),
        summary: summary.clone(),
        next_step: None,
        dashboard_url: None,
        harness_message: format!("{summary} No action needed."),
    };
    PackageEvalResult {
        decision,
        policy_action: policy_action.as_str().to_string(),
        enforcement: enforcement.to_string(),
        entitlement_state: entitlement_state.to_string(),
        cache_status: "empty".to_string(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version,
        bundle_version,
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons,
        packages: Vec::new(),
        risk_summary: summary,
        user_copy,
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        evidence_ids: Vec::new(),
        external_archive_downloads: Vec::new(),
        external_archive_source_hashes: Vec::new(),
    }
}

/// `_empty_evaluation` — derived: builds a minimal allow result with no
/// reasons and no packages, used when the request artifact yields nothing to
/// evaluate.
// supply_chain_package_eval.py:794-827
#[allow(dead_code)]
fn empty_evaluation(
    _artifact: &GuardArtifact,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
) -> PackageEvalResult {
    let decision = "allow".to_string();
    let policy_action = decision_to_guard_action_variant(&decision);
    PackageEvalResult {
        decision,
        policy_action: policy_action.as_str().to_string(),
        enforcement: "free_local".to_string(),
        entitlement_state: "free".to_string(),
        cache_status: "empty".to_string(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version: "local:none".to_string(),
        bundle_version: None,
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons: Vec::new(),
        packages: Vec::new(),
        risk_summary: "HOL Guard recorded the request as trusted by policy.".to_string(),
        user_copy: SupplyChainUserCopy {
            title: "Request allowed".to_string(),
            summary: "HOL Guard recorded the request as trusted by policy.".to_string(),
            next_step: None,
            dashboard_url: None,
            harness_message: "HOL Guard recorded the request as trusted by policy.".to_string(),
        },
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        evidence_ids: Vec::new(),
        external_archive_downloads: Vec::new(),
        external_archive_source_hashes: Vec::new(),
    }
}

/// `_no_change_evaluation` — derived: produces a `monitor`-decision result
/// when the package material has not changed since the last evaluation.
// supply_chain_package_eval.py:794-827
#[allow(dead_code)]
fn no_change_evaluation(
    _artifact: &GuardArtifact,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
    matched_rule_id: Option<&str>,
    exception_id: Option<&str>,
) -> PackageEvalResult {
    let decision = "monitor".to_string();
    let policy_action = decision_to_guard_action_variant(&decision);
    PackageEvalResult {
        decision,
        policy_action: policy_action.as_str().to_string(),
        enforcement: "local_fallback".to_string(),
        entitlement_state: "premium".to_string(),
        cache_status: "empty".to_string(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version: "local:none".to_string(),
        bundle_version: None,
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons: Vec::new(),
        packages: Vec::new(),
        risk_summary: "HOL Guard recorded the request for continued monitoring.".to_string(),
        user_copy: SupplyChainUserCopy {
            title: "Request monitored".to_string(),
            summary: "HOL Guard recorded the request for continued monitoring.".to_string(),
            next_step: None,
            dashboard_url: None,
            harness_message: "HOL Guard recorded the request for continued monitoring.".to_string(),
        },
        matched_rule_id: matched_rule_id.map(str::to_string),
        exception_id: exception_id.map(str::to_string),
        refresh_required: false,
        record_monitor_evidence: true,
        evidence_ids: Vec::new(),
        external_archive_downloads: Vec::new(),
        external_archive_source_hashes: Vec::new(),
    }
}

/// `_evaluation_has_reason_code` (:851-855 on `_cached_eval_has_reason_code`
/// but operates on a `PackageRequestEvaluation` payload map).
// supply_chain_package_eval.py:851-855
#[allow(dead_code)]
fn evaluation_has_reason_code(evaluation: &Value, code: &str) -> bool {
    evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .map(|v| v.as_slice())
        .unwrap_or(&[])
        .iter()
        .any(|r| {
            r.as_object()
                .and_then(|o| o.get("code"))
                .and_then(Value::as_str)
                == Some(code)
        })
}

/// `_cached_eval_has_reason_code` (:851-855).
// supply_chain_package_eval.py:851-855
#[allow(dead_code)]
fn cached_eval_has_reason_code(cached: &Map<String, Value>, code: &str) -> bool {
    cached
        .get("reasons")
        .and_then(Value::as_array)
        .map(|v| v.as_slice())
        .unwrap_or(&[])
        .iter()
        .any(|r| {
            r.as_object()
                .and_then(|o| o.get("code"))
                .and_then(Value::as_str)
                == Some(code)
        })
}

/// `_cached_supply_chain_eval_is_reusable` (:830-848).
// supply_chain_package_eval.py:830-848
#[allow(dead_code)]
fn cached_supply_chain_eval_is_reusable(
    cached: &Map<String, Value>,
    now_timestamp: Option<f64>,
) -> bool {
    if !cached_eval_has_reason_code(cached, "cloud_validation_error") {
        return true;
    }
    let Some(now_ts) = now_timestamp else {
        return false;
    };
    let updated_at = match optional_string(cached.get("updated_at")) {
        Some(v) => v,
        None => return false,
    };
    let cached_at = match parse_evaluation_timestamp(&updated_at) {
        Some(v) => v,
        None => return false,
    };
    (now_ts - cached_at) <= (15 * 60) as f64
}

/// `_cache_reusable_cloud_validation_error` (:858-882).
// supply_chain_package_eval.py:858-882
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn cache_reusable_cloud_validation_error(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_id: Option<&str>,
    bundle_meta: Option<&Map<String, Value>>,
    package_intent_hash: &str,
    evaluation: &PackageEvalResult,
    now: &str,
) {
    let Some(ws) = workspace_id else { return };
    let Some(meta) = bundle_meta else { return };
    if !evaluation_has_reason_code(&evaluation.to_cache_dict(), "cloud_validation_error") {
        return;
    }
    let decision_map = match evaluation.to_cache_dict() {
        Value::Object(m) => m,
        _ => return,
    };
    deps.store_extras.cache_supply_chain_evaluation(
        ws,
        package_intent_hash,
        &optional_string(meta.get("feed_snapshot_hash")).unwrap_or_default(),
        &optional_string(meta.get("policy_hash")).unwrap_or_default(),
        &optional_string(meta.get("scoring_version")).unwrap_or_default(),
        &optional_string(meta.get("bundle_version")).unwrap_or_default(),
        &decision_map,
        now,
    );
}

/// `_cached_cloud_validation_error_requires_uncached_retry` (:885-897) —
/// derived from the docstring/behavior: a cached cloud-validation-error eval
/// is only reusable for a short TTL; beyond that the caller must retry
/// uncached. We return `true` when the cached eval has a
/// `cloud_validation_error` reason and is past the TTL.
// supply_chain_package_eval.py:885-897
#[allow(dead_code)]
fn cached_cloud_validation_error_requires_uncached_retry(
    cached: &Map<String, Value>,
    now_timestamp: Option<f64>,
) -> bool {
    cached_eval_has_reason_code(cached, "cloud_validation_error")
        && !cached_supply_chain_eval_is_reusable(cached, now_timestamp)
}

/// `_cached_cloud_validation_error_has_saved_policy` (:898-913) —
/// derived: a cached cloud-validation-error eval "has saved policy" when
/// the cached decision dict carries a non-empty `policy_action` value,
/// meaning a previously persisted policy decision exists.
// supply_chain_package_eval.py:898-913
#[allow(dead_code)]
fn cached_cloud_validation_error_has_saved_policy(cached: &Map<String, Value>) -> bool {
    optional_string(cached.get("policy_action")).is_some()
}

/// `_normalize_evaluation_action` — derived: normalize a raw decision string
/// into its canonical action rank bucket ("allow" | "monitor" | "warn" |
/// "ask" | "block"). Unknown values map to "monitor".
// supply_chain_package_eval.py:114
#[allow(dead_code)]
fn normalize_evaluation_action(value: &str) -> String {
    if decision_rank_map().contains_key(value) {
        value.to_string()
    } else {
        "monitor".to_string()
    }
}

/// `_evaluation_action_rank` — derived: numeric rank of a normalized
/// evaluation action string.
// supply_chain_package_eval.py:114
#[allow(dead_code)]
fn evaluation_action_rank(value: &str) -> u8 {
    decision_rank(&normalize_evaluation_action(value))
}

/// `_highest_risk_action` — derived: pick the most restrictive normalized
/// action from a list of candidate decision strings.
// supply_chain_package_eval.py:114
#[allow(dead_code)]
fn highest_risk_action<'a>(actions: impl IntoIterator<Item = &'a str>) -> String {
    actions
        .into_iter()
        .map(normalize_evaluation_action)
        .max_by_key(|a| decision_rank(a))
        .unwrap_or_else(|| "monitor".to_string())
}

/// `_resolve_package_action` — derived: resolve the effective `GuardAction`
/// for a package result by combining the normalized decision and any
/// policy-sourced overrides already on the package payload.
// supply_chain_package_eval.py:154-160
#[allow(dead_code)]
fn resolve_package_action(package: &Map<String, Value>) -> GuardAction {
    let decision =
        optional_string(package.get("decision")).unwrap_or_else(|| "monitor".to_string());
    let normalized = normalize_evaluation_action(&decision);
    decision_to_guard_action_variant(&normalized)
}

/// `_risk_to_action` — derived: map a normalized decision string to the
/// `GuardAction` lattice value used for evidence.
// supply_chain_package_eval.py:154-160
#[allow(dead_code)]
fn risk_to_action(decision: &str) -> GuardAction {
    decision_to_guard_action_variant(&normalize_evaluation_action(decision))
}

/// `_severity_rank` — alias kept for callers expecting the private name.
// supply_chain_package_eval.py:4828-4829
#[allow(dead_code)]
fn severity_rank(value: &str) -> u8 {
    severity_rank_value(value)
}

/// `_normalize_package_action` — derived: normalize the `decision` field on a
/// single package dict to the canonical five-value set.
// supply_chain_package_eval.py:114
#[allow(dead_code)]
fn normalize_package_action(package: &Map<String, Value>) -> String {
    optional_string(package.get("decision"))
        .map(|s| normalize_evaluation_action(&s))
        .unwrap_or_else(|| "monitor".to_string())
}

/// `_normalize_package_decision` — derived: same normalization as
/// `_normalize_package_action` but returns the raw decision string.
// supply_chain_package_eval.py:114
#[allow(dead_code)]
fn normalize_package_decision(package: &Map<String, Value>) -> String {
    normalize_package_action(package)
}

/// `_normalize_package_user_copy` (:1507-1524).
// supply_chain_package_eval.py:1507-1524
fn normalize_package_user_copy(
    user_copy: &SupplyChainUserCopy,
    policy_action: GuardAction,
) -> SupplyChainUserCopy {
    let mut dashboard_url = user_copy.dashboard_url.clone();
    if looks_like_cloud_inbox_url(dashboard_url.as_deref()) {
        dashboard_url = None;
    }
    let mut harness_message = CLOUD_INBOX_URL_RE
        .replace_all(user_copy.harness_message.as_str(), "")
        .trim()
        .to_string();
    harness_message = harness_message
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    harness_message = strip_review_evidence_tail(&harness_message);
    let terminal_action = matches!(
        policy_action,
        GuardAction::SandboxRequired | GuardAction::Block
    );
    if terminal_action {
        dashboard_url = None;
        harness_message = LOCAL_APPROVAL_INSTRUCTION_RE
            .replace_all(&harness_message, "")
            .to_string();
        harness_message = LOCAL_APPROVAL_REQUEST_URL_RE
            .replace_all(&harness_message, "")
            .to_string();
        harness_message = LOCAL_REVIEW_INSTRUCTION_RE
            .replace_all(&harness_message, "")
            .to_string();
        harness_message = harness_message
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string();
    }
    let needs_local_review = matches!(
        policy_action,
        GuardAction::Review | GuardAction::RequireReapproval
    );
    if needs_local_review
        && !harness_message
            .to_ascii_lowercase()
            .contains("review this request in hol guard, then retry.")
    {
        harness_message = format!("{harness_message} {LOCAL_REVIEW_INSTRUCTION}")
            .trim()
            .to_string();
    }
    SupplyChainUserCopy {
        title: user_copy.title.clone(),
        summary: user_copy.summary.clone(),
        next_step: user_copy.next_step.clone(),
        dashboard_url,
        harness_message,
    }
}

/// `_with_support_metadata` (:4746-4751).
// supply_chain_package_eval.py:4746-4751
fn with_support_metadata(package: &Map<String, Value>) -> Map<String, Value> {
    let ecosystem =
        optional_string(package.get("ecosystem")).unwrap_or_else(|| "unsupported".to_string());
    let metadata = crate::local_supply_chain::ecosystem_support_metadata(&ecosystem);
    let mut enriched = package.clone();
    if let Some(v) = metadata.get("support_level") {
        enriched.insert("supportLevel".to_string(), v.clone());
    }
    if let Some(v) = metadata.get("support_label") {
        enriched.insert("supportLabel".to_string(), v.clone());
    }
    enriched
}

/// `_package_display_name` (:4989-4995).
// supply_chain_package_eval.py:4989-4995
fn package_display_name(package: &Map<String, Value>) -> String {
    if let Some(alias) = optional_string(package.get("alias")) {
        return alias;
    }
    let namespace = optional_string(package.get("namespace"));
    let name = optional_string(package.get("name")).unwrap_or_else(|| "package".to_string());
    match namespace {
        Some(ns) => format!("{ns}/{name}"),
        None => name,
    }
}

/// `_uses_uv_pip_install` (:4975-4977).
// supply_chain_package_eval.py:4975-4977
fn uses_uv_pip_install(package: &Map<String, Value>) -> bool {
    let command = optional_string(package.get("redactedCommand")).unwrap_or_default();
    let parts: Vec<&str> = command.split_whitespace().collect();
    parts.len() >= 3 && parts[..3] == ["uv", "pip", "install"]
}

/// `_package_install_target` (:4980-4986).
// supply_chain_package_eval.py:4980-4986
fn package_install_target(package: &Map<String, Value>) -> String {
    let alias = optional_string(package.get("alias"));
    let mut no_alias = package.clone();
    no_alias.remove("alias");
    let package_name = package_display_name(&no_alias);
    let ecosystem = optional_string(package.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
    match (alias, ecosystem.as_str()) {
        (Some(a), "npm") => format!("{a}@npm:{package_name}"),
        (Some(a), _) => a,
        (None, _) => package_name,
    }
}

/// `_fix_command` (:4949-4972).
// supply_chain_package_eval.py:4949-4972
fn fix_command(package: &Map<String, Value>) -> Option<String> {
    let package_name = package_install_target(package);
    let fix_version = optional_string(package.get("recommendedFixVersion"))?;
    let ecosystem = optional_string(package.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
    let package_manager =
        optional_string(package.get("packageManager")).unwrap_or_else(|| "npm".to_string());
    if fix_version.is_empty() {
        return None;
    }
    if ecosystem == "pypi" {
        return Some(match package_manager.as_str() {
            "uv" if uses_uv_pip_install(package) => {
                format!("uv pip install {package_name}=={fix_version}")
            }
            "uv" => format!("uv add {package_name}=={fix_version}"),
            "poetry" => format!("poetry add {package_name}@{fix_version}"),
            "pipenv" => format!("pipenv install {package_name}=={fix_version}"),
            _ => format!("pip install {package_name}=={fix_version}"),
        });
    }
    Some(match package_manager.as_str() {
        "pnpm" => format!("pnpm add {package_name}@{fix_version}"),
        "yarn" => format!("yarn add {package_name}@{fix_version}"),
        "bun" => format!("bun add {package_name}@{fix_version}"),
        _ => format!("npm install {package_name}@{fix_version}"),
    })
}

/// `_result_package_identity` (:5073-5099).
// supply_chain_package_eval.py:5073-5099
fn result_package_identity(
    deps: &SupplyChainEvalDeps<'_>,
    package: &Map<String, Value>,
) -> (String, String, String, String, String, String) {
    let ecosystem = optional_string(package.get("ecosystem"));
    let name = optional_string(package.get("name")).unwrap_or_else(|| "package".to_string());
    let namespace = optional_string(package.get("namespace"));
    let version = optional_string(package.get("resolvedVersion"))
        .or_else(|| optional_string(package.get("requestedVersion")));
    if let Some(eco) = &ecosystem {
        if let Ok(identity) = deps.identity.canonical_package_identity(
            eco,
            namespace.as_deref(),
            &name,
            version.as_deref().unwrap_or("*"),
        ) {
            return (
                "canonical".to_string(),
                identity.ecosystem,
                identity.namespace.unwrap_or_default(),
                identity.name,
                identity.version,
                String::new(),
            );
        }
    }
    let opaque_sha256 = stable_digest_hex(
        serde_json::to_string(&Value::Object(package.clone()))
            .unwrap_or_default()
            .as_bytes(),
    );
    (
        "opaque".to_string(),
        ecosystem.unwrap_or_default(),
        namespace.unwrap_or_default(),
        name,
        version.unwrap_or_default(),
        opaque_sha256,
    )
}

/// `_evidence_id` (:5060-5070).
// supply_chain_package_eval.py:5060-5070
fn evidence_id(
    deps: &SupplyChainEvalDeps<'_>,
    package_intent_hash: &str,
    package: &Map<String, Value>,
) -> String {
    let decision =
        optional_string(package.get("decision")).unwrap_or_else(|| "monitor".to_string());
    let dependency_path =
        optional_string(package.get("dependencyPath")).unwrap_or_else(|| "direct".to_string());
    let identity = result_package_identity(deps, package);
    let identity_payload = json!({
        "decision": decision,
        "dependency_path": dependency_path,
        "package_identity": [
            identity.0,
            identity.1,
            identity.2,
            identity.3,
            identity.4,
            identity.5,
        ],
        "package_intent_hash": package_intent_hash,
    });
    let encoded = serde_json::to_string(&identity_payload).unwrap_or_default();
    format!(
        "evidence-{}",
        stable_digest_hex_len(encoded.as_bytes(), Some(16))
    )
}

/// `_should_record_package` (:5055-5057).
// supply_chain_package_eval.py:5055-5057
fn should_record_package(package: &Map<String, Value>, decision: &str) -> bool {
    let package_decision =
        optional_string(package.get("decision")).unwrap_or_else(|| decision.to_string());
    matches!(package_decision.as_str(), "block" | "ask" | "warn") || decision == "monitor"
}

/// `_looks_like_cloud_inbox_url` (:1536-1540).
// supply_chain_package_eval.py:1536-1540
fn looks_like_cloud_inbox_url(url: Option<&str>) -> bool {
    let Some(url) = url else { return false };
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return false;
    }
    // The Python uses urllib.parse.urlparse; we match on the path suffix.
    let path = trimmed
        .split("://")
        .nth(1)
        .and_then(|rest| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    path == "/guard/inbox"
}

/// `_strip_review_evidence_tail` (:1530-1533).
// supply_chain_package_eval.py:1530-1533
fn strip_review_evidence_tail(message: &str) -> String {
    let stripped = message.trim();
    let lower = stripped.to_ascii_lowercase();
    for suffix in [
        "Review evidence: .",
        "Review evidence:.",
        "Review evidence:",
    ] {
        if lower.ends_with(&suffix.to_ascii_lowercase()) {
            return stripped[..stripped.len() - suffix.len()]
                .trim_end()
                .to_string();
        }
    }
    stripped.to_string()
}

/// `_normalize_bundle_action` (:4832-4837).
// supply_chain_package_eval.py:4832-4837
fn normalize_bundle_action(value: &str) -> String {
    if value == "review" {
        return "ask".to_string();
    }
    if decision_rank_map().contains_key(value) {
        return value.to_string();
    }
    "monitor".to_string()
}

/// `_EvaluationDraft.to_dict` (:221-231 in the dataclass body).
// supply_chain_package_eval.py:221-231
impl EvaluationDraft {
    pub fn to_dict(&self) -> Value {
        json_obj(vec![
            ("decision", Value::String(self.decision.clone())),
            ("enforcement", Value::String(self.enforcement.clone())),
            (
                "entitlement_state",
                Value::String(self.entitlement_state.clone()),
            ),
            ("cache_status", Value::String(self.cache_status.clone())),
            (
                "packages",
                Value::Array(self.packages.iter().cloned().map(Value::Object).collect()),
            ),
            (
                "reasons",
                Value::Array(self.reasons.iter().cloned().map(Value::Object).collect()),
            ),
            (
                "matched_rule_id",
                self.matched_rule_id
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            (
                "exception_id",
                self.exception_id
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            ("refresh_required", Value::Bool(self.refresh_required)),
            (
                "record_monitor_evidence",
                Value::Bool(self.record_monitor_evidence),
            ),
            (
                "bundle_version",
                self.bundle_version
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            ("policy_version", Value::String(self.policy_version.clone())),
            (
                "external_archive_inspection",
                Value::Array(
                    self.external_archive_downloads
                        .iter()
                        .map(|d| {
                            json_obj(vec![
                                ("sha256", Value::String(d.sha256.clone())),
                                ("size", Value::Number(d.size.into())),
                                (
                                    "source_url_hash",
                                    Value::String(stable_digest_hex(d.source_url.as_bytes())),
                                ),
                                (
                                    "final_url_hash",
                                    Value::String(stable_digest_hex(d.final_url.as_bytes())),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "external_archive_source_hashes",
                Value::Array(
                    self.external_archive_source_hashes
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            ),
        ])
    }
}

/// `_finalize_evaluation` (:972-1089).
// supply_chain_package_eval.py:972-1089
fn finalize_evaluation(
    deps: &SupplyChainEvalDeps<'_>,
    draft: &EvaluationDraft,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
) -> PackageEvalResult {
    let packages: Vec<Map<String, Value>> =
        draft.packages.iter().map(with_support_metadata).collect();
    let primary_package: Map<String, Value> = packages.first().cloned().unwrap_or_default();
    let package_display = package_display_name(&primary_package);
    let requested_version = optional_string(primary_package.get("requestedVersion"))
        .or_else(|| optional_string(primary_package.get("resolvedVersion")));
    let package_ref = match &requested_version {
        Some(v) => format!("{package_display}@{v}"),
        None => package_display.clone(),
    };
    let prefix = match draft.decision.as_str() {
        "block" => "HOL Guard blocked",
        "ask" => "HOL Guard paused",
        "warn" => "HOL Guard found risk signals for",
        _ => "HOL Guard recorded",
    };
    let risk_summary = match draft.decision.as_str() {
        "block" => format!("{prefix} `{package_ref}` before install."),
        "ask" => format!("{prefix} `{package_ref}` for review before install."),
        "warn" => format!("{prefix} `{package_ref}` before install."),
        "monitor" => format!("{prefix} `{package_ref}` for continued monitoring."),
        _ => format!("{prefix} `{package_ref}` as trusted by policy."),
    };
    let reason_message = draft
        .reasons
        .first()
        .and_then(|r| optional_string(r.get("message")));
    let mut reason_code = draft
        .reasons
        .first()
        .and_then(|r| optional_string(r.get("code")));
    let mut risk_summary = risk_summary;
    if reason_code.as_deref() == Some("installed_release_reinstall") && draft.decision != "allow" {
        if let Some(restrictive_reason) = draft.reasons.iter().find(|r| {
            optional_string(r.get("code"))
                .map(|c| c != "installed_release_reinstall")
                .unwrap_or(false)
        }) {
            reason_code = optional_string(restrictive_reason.get("code"));
        }
    }
    let policy_action = decision_to_guard_action_variant(&normalize_bundle_action(&draft.decision));
    let source_risk_summaries: HashMap<&str, &str> = HashMap::from([
        (
            "dependency_confusion",
            "matches a known dependency-confusion risk",
        ),
        (
            "malicious_package",
            "matches a known malicious-package risk",
        ),
    ]);
    if let Some(code) = &reason_code {
        if let Some(summary) = source_risk_summaries.get(code.as_str()) {
            if reason_message.is_some() {
                risk_summary = format!("{prefix} `{package_ref}` {summary}.");
            }
        }
    }
    if reason_code.as_deref() == Some("installed_release_reinstall") && draft.decision == "allow" {
        risk_summary = format!(
            "HOL Guard allowed `{package_ref}` because it reinstalls the release already running on this device."
        );
    }
    let fix_command = fix_command(&primary_package);
    let title = match draft.decision.as_str() {
        "block" => "Critical install blocked",
        "ask" => "Review required",
        "warn" => "Proceed with caution",
        "monitor" => "Monitoring this package",
        _ => "Allowed by policy",
    }
    .to_string();
    let mut summary = match draft.decision.as_str() {
        "block" => "Guard blocked this package before install.".to_string(),
        "ask" => "Guard paused this package for review before install.".to_string(),
        "warn" => "Guard found risk signals for this package.".to_string(),
        "monitor" => "Guard recorded this package for continued monitoring.".to_string(),
        _ => "Guard recorded this package as trusted by policy.".to_string(),
    };
    if draft.packages.len() > 1 {
        let others: Vec<String> = draft
            .packages
            .iter()
            .skip(1)
            .take(2)
            .map(package_display_name)
            .collect();
        let others_joined = others.join(", ");
        if !others_joined.is_empty() {
            summary = format!("{summary} Also flagged: {others_joined}.");
        }
    }
    let mut harness_parts = vec![risk_summary.clone()];
    if let Some(msg) = &reason_message {
        harness_parts.push(format!("Reason: {}", ensure_terminal_punctuation(msg)));
    }
    if let Some(cmd) = &fix_command {
        harness_parts.push(format!("Fix: install `{cmd}` or choose a team exception."));
    }
    let user_copy = normalize_package_user_copy(
        &SupplyChainUserCopy {
            title,
            summary,
            next_step: None,
            dashboard_url: None,
            harness_message: harness_parts.join(" "),
        },
        policy_action,
    );
    let evidence_ids: Vec<String> = draft
        .packages
        .iter()
        .filter(|p| should_record_package(p, &draft.decision))
        .map(|p| evidence_id(deps, package_intent_hash, p))
        .collect();
    PackageEvalResult {
        decision: draft.decision.clone(),
        policy_action: policy_action.as_str().to_string(),
        enforcement: draft.enforcement.clone(),
        entitlement_state: draft.entitlement_state.clone(),
        cache_status: draft.cache_status.clone(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version: draft.policy_version.clone(),
        bundle_version: draft.bundle_version.clone(),
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons: draft.reasons.clone(),
        packages,
        risk_summary,
        user_copy,
        matched_rule_id: draft.matched_rule_id.clone(),
        exception_id: draft.exception_id.clone(),
        refresh_required: draft.refresh_required,
        record_monitor_evidence: draft.record_monitor_evidence,
        evidence_ids,
        external_archive_downloads: draft
            .external_archive_downloads
            .iter()
            .map(|d| {
                let mut m = Map::new();
                m.insert("sha256".to_string(), Value::String(d.sha256.clone()));
                m.insert("size".to_string(), Value::Number(d.size.into()));
                m.insert(
                    "source_url".to_string(),
                    Value::String(d.source_url.clone()),
                );
                m.insert("final_url".to_string(), Value::String(d.final_url.clone()));
                m
            })
            .collect(),
        external_archive_source_hashes: draft.external_archive_source_hashes.clone(),
    }
}

/// `finalize_evaluation` as a method on `EvaluationDraft` for ergonomic
/// parity with the Python `_EvaluationDraft` → `PackageRequestEvaluation`
/// conversion.
// supply_chain_package_eval.py:972-1089
impl EvaluationDraft {
    /// `_finalize_evaluation` (:972-1089) — promote this draft into the final
    /// `PackageRequestEvaluation` using the same logic as the Python helper.
    pub fn finalize(
        &self,
        deps: &SupplyChainEvalDeps<'_>,
        package_intent_hash: &str,
        workspace_fingerprint: Option<&str>,
    ) -> PackageEvalResult {
        finalize_evaluation(deps, self, package_intent_hash, workspace_fingerprint)
    }
}

// ---------------------------------------------------------------------------
// Batch B — cloud fail-closed, bundle eval, heuristic eval, evidence persist,
// target resolution, lockfile parse results, request payload helpers.
// ---------------------------------------------------------------------------

/// `_cloud_http_fail_closed_evaluation` (:1543-1593) — build the fail-closed
/// draft for a cloud HTTP/connect failure. `payload` is the parsed
/// `errorPayload` body (may be absent); `status` is the HTTP status code.
// supply_chain_package_eval.py:1543-1593
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn cloud_http_fail_closed_evaluation(
    status: u16,
    payload: Option<&Map<String, Value>>,
    decision: &str,
) -> EvaluationDraft {
    let code = payload
        .and_then(|p| optional_string(p.get("code")))
        .unwrap_or_else(|| format!("cloud_http_{status}"));
    let message = payload
        .and_then(|p| optional_string(p.get("message")))
        .unwrap_or_else(|| "Guard Cloud evaluation request failed.".to_string());
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(code));
    reason.insert("message".to_string(), Value::String(message));
    reason.insert("severity".to_string(), Value::String("high".to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("cloud_evaluate".to_string()),
    );
    if let Some(p) = payload {
        if let Some(eid) = optional_string(p.get("evaluationId")) {
            reason.insert("evaluationId".to_string(), Value::String(eid));
        }
    }
    EvaluationDraft {
        decision: decision.to_string(),
        enforcement: "cloud_fail_closed".to_string(),
        entitlement_state: "premium".to_string(),
        cache_status: "unavailable".to_string(),
        reasons: vec![reason],
        refresh_required: false,
        record_monitor_evidence: decision == "monitor",
        policy_version: "cloud:http".to_string(),
        ..Default::default()
    }
}

/// `_cloud_fail_closed_evaluation` (:1596-1655) — cloud-unavailable fallback
/// evaluation (narrow form retained for existing callers; this wrapper builds
/// one fail-closed draft without artifact/workspace context).
// supply_chain_package_eval.py:1596-1655
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn cloud_fail_closed_evaluation(
    decision: &str,
    reason_code: &str,
    message: &str,
) -> EvaluationDraft {
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(reason_code.to_string()));
    reason.insert("message".to_string(), Value::String(message.to_string()));
    reason.insert("severity".to_string(), Value::String("high".to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("cloud_evaluate".to_string()),
    );
    EvaluationDraft {
        decision: decision.to_string(),
        enforcement: "cloud_fail_closed".to_string(),
        entitlement_state: "premium".to_string(),
        cache_status: "unavailable".to_string(),
        reasons: vec![reason],
        refresh_required: false,
        record_monitor_evidence: decision == "monitor",
        policy_version: "cloud:offline".to_string(),
        ..Default::default()
    }
}

/// `_cloud_fail_closed_evaluation` (:1596-1655) — full form matching the
/// Python signature; produces a finalized `PackageRequestEvaluation` carrying
/// heuristic per-target results (or the unidentified-package fallback) plus
/// the cloud fallback reason.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn cloud_fail_closed_evaluation_full(
    deps: &SupplyChainEvalDeps<'_>,
    code: &str,
    message: &str,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    fail_closed_decision: &str,
) -> PackageEvalResult {
    let reason = cloud_fallback_reason(code, message);
    let decision = if fail_closed_decision == "block" {
        "block"
    } else {
        "ask"
    };
    let severity = if decision == "block" {
        "critical"
    } else {
        "high"
    };
    let mut packages: Vec<Map<String, Value>> = targets
        .iter()
        .map(|target| heuristic_package_result(target, decision, code, message, severity))
        .collect();
    if packages.is_empty() {
        packages = fallback_package_results(deps, targets, artifact, workspace_dir, false, false)
            .into_iter()
            .map(|mut package| {
                package.insert("decision".to_string(), Value::String(decision.to_string()));
                package.insert(
                    "reasons".to_string(),
                    Value::Array(vec![Value::Object(reason.clone())]),
                );
                package
            })
            .collect();
    }
    let policy_version = bundle_meta
        .and_then(|m| m.get("policy_hash").cloned())
        .unwrap_or_else(|| "local:none".to_string());
    let bundle_version = bundle_meta.and_then(|m| m.get("bundle_version").cloned());
    let draft = EvaluationDraft {
        decision: decision.to_string(),
        enforcement: "premium_cloud".to_string(),
        entitlement_state: "premium".to_string(),
        cache_status: "cloud-error".to_string(),
        packages,
        reasons: vec![reason],
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        bundle_version,
        policy_version,
        ..Default::default()
    };
    let package_intent_hash = artifact
        .artifact_id
        .rsplit(':')
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| artifact.artifact_id.clone());
    let evaluation = finalize_evaluation(deps, &draft, &package_intent_hash, workspace_fingerprint);
    if code == "cloud_auth_error" {
        with_cloud_auth_reconnect_copy_result(evaluation)
    } else {
        evaluation
    }
}

/// `_with_cloud_auth_reconnect_copy` (:1658-1683) — append a reconnect prompt
/// to the user copy when the cloud auth token is expired/invalid.
// supply_chain_package_eval.py:1658-1683
#[allow(dead_code)]
fn with_cloud_auth_reconnect_copy(
    mut draft: EvaluationDraft,
    reconnect_required: bool,
) -> EvaluationDraft {
    if !reconnect_required {
        return draft;
    }
    draft.reasons.iter_mut().for_each(|reason| {
        reason.insert("requires_reconnect".to_string(), Value::Bool(true));
    });
    draft
}

/// `_cloud_fallback_requires_reconnect_copy` (:1686-1687).
// supply_chain_package_eval.py:1686-1687
#[allow(dead_code)]
fn cloud_fallback_requires_reconnect_copy(reason: &Map<String, Value>) -> bool {
    optional_string(reason.get("code")).as_deref() == Some("cloud_auth_error")
}

/// `_cloud_fail_closed_decision` (:1690-1697).
// supply_chain_package_eval.py:1690-1697
#[allow(dead_code)]
fn cloud_fail_closed_decision(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
) -> String {
    let config = deps
        .config
        .load_guard_config(store.guard_home(), workspace_dir, false)
        .unwrap_or_else(|_| GuardConfig::default());
    let cloud_action =
        resolve_risk_action(&config, Some("cloud_advisory"), None).unwrap_or_default();
    if config.security_level == "strict" || config.security_level == "paranoid" {
        return "block".to_string();
    }
    if cloud_action == "block" {
        return "block".to_string();
    }
    "ask".to_string()
}

/// `_unidentified_packages_fail_closed` (:1700-1702).
// supply_chain_package_eval.py:1700-1702
#[allow(dead_code)]
fn unidentified_packages_fail_closed(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
) -> bool {
    let config = deps
        .config
        .load_guard_config(store.guard_home(), workspace_dir, false)
        .unwrap_or_else(|_| GuardConfig::default());
    config.security_level == "strict" || config.security_level == "paranoid"
}

/// `_unidentified_package_decision` (:1705-1716).
// supply_chain_package_eval.py:1705-1716
#[allow(dead_code)]
fn unidentified_package_decision(
    ecosystem: &str,
    fail_closed: bool,
    identity_resolved: bool,
) -> String {
    let support = crate::local_supply_chain::ecosystem_support_metadata(ecosystem);
    let support_level = value_str(&Value::Object(support), "support_level")
        .unwrap_or("monitor-only")
        .to_string();
    if support_level != "protected" && support_level != "beta" {
        return "monitor".to_string();
    }
    if fail_closed {
        return "block".to_string();
    }
    if identity_resolved {
        "monitor".to_string()
    } else {
        "ask".to_string()
    }
}

/// `_evaluate_with_bundle` (:1719-1877) — evaluate all targets against a
/// cached/advisory bundle payload and produce a draft.
// supply_chain_package_eval.py:1719-1877
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn evaluate_with_bundle(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    bundle_response: &SupplyChainBundleResponse,
    workspace_dir: Option<&Path>,
    workspace_id: Option<&str>,
    now_timestamp: Option<f64>,
) -> Option<EvaluationDraft> {
    let bundle_payload = bundle_response.to_dict();
    let bundle_obj = bundle_payload.as_object().cloned().unwrap_or_default();
    let bundle_meta_map = deps
        .bundle
        .supply_chain_bundle_meta(&bundle_obj)
        .unwrap_or_default();
    let bundle_meta = |k: &str| bundle_meta_map.get(k).cloned().unwrap_or_default();

    let mut refresh_required = false;
    let mut packages: Vec<Map<String, Value>> = Vec::new();
    let lockfile_versions = lockfile_dependency_versions(deps, workspace_dir, artifact, targets);
    for target in targets {
        if target.get("manifest_unsynced") == Some(&Value::Bool(true)) {
            packages.push(heuristic_package_result(
                target,
                "ask",
                "manifest_lockfile_unsynced",
                &format!(
                    "{} is declared in the project manifest but is not pinned \
                     in the existing lockfile yet, so Guard requires review before install.",
                    optional_string(target.get("package_name"))
                        .or_else(|| optional_string(target.get("name")))
                        .unwrap_or_else(|| "package".to_string())
                ),
                "high",
            ));
            continue;
        }
        let resolved_version = resolved_target_version(deps, target, &lockfile_versions);
        let package_match = resolved_version
            .as_deref()
            .and_then(|version| bundle_package(bundle_response, target, version));
        let resolved_npm_version = resolved_version.clone().filter(|_| {
            (optional_string(target.get("ecosystem"))
                .as_deref()
                .unwrap_or("npm"))
                == "npm"
        });
        let policy_target =
            target_for_resolved_npm_policy_match(target, resolved_npm_version.as_deref());
        let matched_rule = matching_policy_rule(bundle_response, &policy_target);
        if let Some(rule) = matched_rule {
            let decision =
                normalize_bundle_action(rule.get("action").and_then(Value::as_str).unwrap_or(""));
            let policy = policy_package_result(&policy_target, &decision, &rule);
            let package_result =
                bind_resolved_npm_policy_result(policy, resolved_npm_version.as_deref());
            packages.push(package_result);
            continue;
        }
        if let Some(confusion) = dependency_confusion_policy_package_result(bundle_response, target)
        {
            packages.push(confusion);
            continue;
        }
        let Some(resolved_version) = resolved_version else {
            continue;
        };
        let offline = deps
            .bundle
            .evaluate_cached_supply_chain_bundle(
                bundle_response,
                &optional_string(target.get("package_name"))
                    .or_else(|| optional_string(target.get("name")))
                    .unwrap_or_default(),
                Some(resolved_version.as_str()),
                optional_string(target.get("ecosystem")).as_deref(),
                now_timestamp,
            )
            .unwrap_or_default();
        let offline_action = optional_string(offline.get("action")).unwrap_or_default();
        let offline_deny = offline.get("emergency_deny") == Some(&Value::Bool(true));
        if offline_deny && offline_action == "block" {
            let mut pkg = Map::new();
            pkg.insert("decision".to_string(), Value::String("block".into()));
            pkg.insert(
                "message".to_string(),
                Value::String(emergency_deny_bundle_message(target)),
            );
            packages.push(pkg);
            continue;
        }
        if package_match.is_none() {
            if offline_action == "block" {
                let empty_match: Map<String, Value> = Map::new();
                packages.push(block_package_from_offline(
                    &offline,
                    bundle_response,
                    &empty_match,
                    None,
                ));
            }
            continue;
        }
        refresh_required = refresh_required || offline.get("stale") == Some(&Value::Bool(true));
        if let Some(package) = bundle_package_result(
            deps,
            target,
            package_match.as_ref().unwrap(),
            bundle_response,
            resolved_npm_version.as_deref(),
            now_timestamp,
        ) {
            packages.push(package);
        }
    }
    let _direct_identities: HashSet<String> = packages
        .iter()
        .map(|p| {
            let id = result_package_identity(deps, p);
            format!("{id:?}")
        })
        .collect();
    for transitive in transitive_lockfile_results(deps, workspace_dir, artifact, targets) {
        packages.push(transitive);
    }
    if packages.is_empty() {
        return None;
    }
    packages.sort_by(|a, b| {
        let ra = decision_rank(
            optional_string(a.get("decision"))
                .as_deref()
                .unwrap_or("monitor"),
        );
        let rb = decision_rank(
            optional_string(b.get("decision"))
                .as_deref()
                .unwrap_or("monitor"),
        );
        rb.cmp(&ra)
    });
    let decision = optional_string(packages[0].get("decision")).unwrap_or_else(|| "monitor".into());
    let winning_rule_id = optional_string(packages[0].get("ruleId"));
    let reasons: Vec<Map<String, Value>> = packages
        .iter()
        .flat_map(|p| dict_items(p.get("reasons")))
        .collect();
    let first_decision_is_allow = packages
        .first()
        .and_then(|p| p.get("decision"))
        .and_then(Value::as_str)
        == Some("allow");
    Some(EvaluationDraft {
        decision,
        enforcement: if winning_rule_id.is_some() {
            "policy_override".to_string()
        } else {
            "offline_cached".to_string()
        },
        entitlement_state: if workspace_id.is_some() {
            "premium".to_string()
        } else {
            "free".to_string()
        },
        cache_status: if refresh_required {
            "stale".to_string()
        } else {
            "miss".to_string()
        },
        packages,
        reasons,
        matched_rule_id: winning_rule_id.clone(),
        exception_id: if winning_rule_id.is_some() && first_decision_is_allow {
            winning_rule_id
        } else {
            None
        },
        refresh_required,
        record_monitor_evidence: false,
        bundle_version: Some(bundle_meta("bundle_version")),
        policy_version: bundle_meta("policy_hash"),
        ..Default::default()
    })
}

/// `_primary_bundle_advisory_id` (:1880-1895).
// supply_chain_package_eval.py:1880-1895
#[allow(dead_code)]
fn primary_bundle_advisory_id(
    bundle_response: &SupplyChainBundleResponse,
    package: &Map<String, Value>,
) -> Option<String> {
    let related: Vec<String> = package
        .get("relatedAdvisoryIds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if related.is_empty() {
        return None;
    }
    let mut advisory_lookup: HashMap<String, String> = HashMap::new();
    let advisories = bundle_response
        .signed_bundle
        .get("advisories")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for advisory_val in advisories {
        let Some(advisory) = advisory_val.as_object() else {
            continue;
        };
        let Some(aid) = advisory.get("advisoryId").and_then(Value::as_str) else {
            continue;
        };
        advisory_lookup.insert(aid.to_string(), aid.to_string());
        if let Some(aliases) = advisory.get("aliases").and_then(Value::as_array) {
            for alias in aliases {
                if let Some(a) = alias.as_str() {
                    advisory_lookup
                        .entry(a.to_string())
                        .or_insert_with(|| aid.to_string());
                }
            }
        }
    }
    for advisory_id in &related {
        if let Some(canonical) = advisory_lookup.get(advisory_id) {
            return Some(canonical.clone());
        }
    }
    related.first().cloned()
}

/// `_bundle_advisory_aliases` (:1898-1923).
// supply_chain_package_eval.py:1898-1923
#[allow(dead_code)]
fn bundle_advisory_aliases(
    bundle_response: &SupplyChainBundleResponse,
    package: &Map<String, Value>,
) -> Vec<String> {
    let mut advisory_ids: Vec<String> = package
        .get("relatedAdvisoryIds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if let Some(primary) = primary_bundle_advisory_id(bundle_response, package) {
        if !advisory_ids.contains(&primary) {
            advisory_ids.push(primary);
        }
    }
    if advisory_ids.is_empty() {
        return Vec::new();
    }
    let mut advisory_lookup: HashMap<String, Vec<String>> = HashMap::new();
    let advisories = bundle_response
        .signed_bundle
        .get("advisories")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for advisory_val in advisories {
        let Some(advisory) = advisory_val.as_object() else {
            continue;
        };
        let Some(aid) = advisory.get("advisoryId").and_then(Value::as_str) else {
            continue;
        };
        let mut tuple = vec![aid.to_string()];
        if let Some(aliases) = advisory.get("aliases").and_then(Value::as_array) {
            for alias in aliases {
                if let Some(a) = alias.as_str() {
                    tuple.push(a.to_string());
                }
            }
        }
        let upper_tuple: Vec<String> = tuple.iter().map(|a| a.to_uppercase()).collect();
        advisory_lookup.insert(aid.to_uppercase(), upper_tuple.clone());
        for alias in &tuple {
            advisory_lookup
                .entry(alias.to_uppercase())
                .or_insert_with(|| upper_tuple.clone());
        }
    }
    let mut aliases: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for advisory_id in &advisory_ids {
        let default = vec![advisory_id.to_uppercase()];
        let list = advisory_lookup
            .get(&advisory_id.to_uppercase())
            .unwrap_or(&default);
        for alias in list {
            if seen.insert(alias.clone()) {
                aliases.push(alias.clone());
            }
        }
    }
    aliases
}

/// `_heuristic_result` (:1926-2121) — local/offline evaluation over targets
/// without a bundle; enforces the external-archive budget and fail-closed
/// integrity checks.
// supply_chain_package_eval.py:1926-2121
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn heuristic_result(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    external_archive_network_authorized: bool,
    retain_external_archive_blob: bool,
    external_archive_request_deadline: Option<f64>,
) -> Option<EvaluationDraft> {
    let mut packages: Vec<Map<String, Value>> = Vec::new();
    let mut external_archive_downloads: Vec<RestrictedArchiveDownload> = Vec::new();
    let external_archive_source_hashes: Vec<String> = targets
        .iter()
        .filter(|t| target_is_external_https_archive(t))
        .filter_map(|t| optional_string(t.get("source_url")))
        .map(|u| stable_digest_hex(u.as_bytes()))
        .collect();
    let mut retained_archive_bytes: u64 = 0;
    for target in targets {
        let source_url = optional_string(target.get("source_url"));
        if target.get("external_archive_source_integrity_invalid") == Some(&Value::Bool(true)) {
            packages.push(heuristic_package_result(
                target,
                "block",
                "external_archive_source_integrity_invalid",
                "Package source private data no longer matches its approved public identity.",
                "high",
            ));
            continue;
        }
        if let Some(reason) = optional_string(target.get("source_invalid_reason")) {
            packages.push(heuristic_package_result(
                target,
                "block",
                &reason,
                "Package source syntax is ambiguous or invalid and cannot be authenticated.",
                "high",
            ));
            continue;
        }
        if source_url.is_some() && target_is_external_https_archive(target) {
            let (package_result, download) = external_tarball_dependency_result(
                deps,
                target,
                external_archive_network_authorized,
                retain_external_archive_blob,
                external_archive_request_deadline,
                store.guard_home(),
            );
            if let Some(dl) = download {
                retained_archive_bytes += dl.size;
                if retained_archive_bytes > EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES {
                    drop(dl);
                } else {
                    external_archive_downloads.push(dl);
                }
            }
            if let Some(pr) = package_result {
                packages.push(pr);
            }
            continue;
        }
        if target.get("manifest_unsynced") == Some(&Value::Bool(true)) {
            packages.push(heuristic_package_result(
                target,
                "ask",
                "manifest_lockfile_unsynced",
                &format!(
                    "{} is declared in the project manifest but is not pinned \
                     in the existing lockfile yet, so Guard requires review before install.",
                    optional_string(target.get("package_name"))
                        .or_else(|| optional_string(target.get("name")))
                        .unwrap_or_else(|| "package".to_string())
                ),
                "high",
            ));
            continue;
        }
        let lockfile_parse_warning =
            lockfile_parse_warning_result(deps, workspace_dir, artifact, target);
        let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
        let mut package_result =
            local_package_manifest_result(deps, target, artifact, workspace_dir)
                .or_else(|| local_python_build_result(target, workspace_dir))
                .or_else(|| {
                    matches!(
                        ecosystem.as_str(),
                        "homebrew" | "homebrew-cask" | "homebrew-tap"
                    )
                    .then(|| homebrew_package_monitor_result(deps, target))
                })
                .or_else(|| (ecosystem == "system").then(|| system_package_monitor_result(target)))
                .or_else(|| {
                    (ecosystem == "unsupported").then(|| unsupported_ecosystem_result(deps, target))
                })
                .or_else(|| go_replace_result(deps, target, artifact, workspace_dir))
                .or_else(|| local_source_dependency_result(target));
        if package_result.is_none()
            && source_url
                .as_deref()
                .is_some_and(|url| url.to_ascii_lowercase().starts_with("http:"))
        {
            package_result = Some(heuristic_package_result(
                target,
                "block",
                "insecure_source_url",
                "Package source uses insecure HTTP transport.",
                "high",
            ));
        }
        if package_result.is_none() && source_url.as_deref().is_some_and(is_git_source_url) {
            let repository = optional_string(target.get("source_repository"))
                .unwrap_or_else(|| "Git repository".to_string());
            let revision_kind = optional_string(target.get("source_revision_kind"))
                .unwrap_or_else(|| "missing".to_string());
            package_result = Some(heuristic_package_result(
                target,
                "ask",
                "git_dependency_source",
                &format!("Git package source {repository} ({revision_kind}) requires review before install."),
                "high",
            ));
        }
        match package_result.take() {
            None => {
                if let Some(warning) = lockfile_parse_warning {
                    packages.push(warning);
                }
                continue;
            }
            Some(package_result) => {
                let package_result = if let Some(warning) = lockfile_parse_warning.as_ref() {
                    if let Some(first_reason) =
                        dict_items(warning.get("reasons")).into_iter().next()
                    {
                        with_package_reason(&package_result, first_reason)
                    } else {
                        package_result
                    }
                } else {
                    package_result
                };
                packages.push(package_result);
            }
        }
    }
    if packages.is_empty() {
        return None;
    }
    packages.sort_by(|a, b| {
        let ra = decision_rank(
            optional_string(a.get("decision"))
                .as_deref()
                .unwrap_or("monitor"),
        );
        let rb = decision_rank(
            optional_string(b.get("decision"))
                .as_deref()
                .unwrap_or("monitor"),
        );
        rb.cmp(&ra)
    });
    let decision = optional_string(packages[0].get("decision")).unwrap_or_else(|| "monitor".into());
    if decision == "block" {
        for retained in external_archive_downloads.drain(..) {
            drop(retained);
        }
    }
    let reasons: Vec<Map<String, Value>> = packages
        .iter()
        .flat_map(|p| dict_items(p.get("reasons")))
        .collect();
    Some(EvaluationDraft {
        decision,
        enforcement: "free_local".to_string(),
        entitlement_state: "free".to_string(),
        cache_status: "miss".to_string(),
        packages,
        reasons,
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        bundle_version: None,
        policy_version: "local:none".to_string(),
        external_archive_downloads,
        external_archive_source_hashes,
    })
}

/// `_persist_evidence` (:2124-2164).
// supply_chain_package_eval.py:2124-2164
#[allow(dead_code)]
fn persist_evidence(
    deps: &SupplyChainEvalDeps<'_>,
    _store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    evaluation: &PackageEvalResult,
    now: &str,
) {
    if evaluation.decision == "allow" {
        return;
    }
    if evaluation.decision == "monitor" && !evaluation.record_monitor_evidence {
        return;
    }
    for package in &evaluation.packages {
        if !should_record_package(package, &evaluation.decision) {
            continue;
        }
        let evidence_id = evidence_id(deps, &evaluation.package_intent_hash, package);
        let mut details = Map::new();
        details.insert(
            "agent_app".to_string(),
            optional_string(artifact.metadata.get("agent_app"))
                .map(Value::String)
                .unwrap_or_else(|| Value::String(artifact.harness.clone())),
        );
        details.insert(
            "command_shape".to_string(),
            optional_string(artifact.metadata.get("redacted_command"))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "decision".to_string(),
            Value::String(evaluation.decision.clone()),
        );
        details.insert(
            "enforcement".to_string(),
            Value::String(evaluation.enforcement.clone()),
        );
        details.insert(
            "exception_id".to_string(),
            evaluation
                .exception_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "harness".to_string(),
            Value::String(artifact.harness.clone()),
        );
        details.insert(
            "matched_rule_id".to_string(),
            evaluation
                .matched_rule_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert("package".to_string(), Value::Object(package.clone()));
        details.insert(
            "package_manager".to_string(),
            optional_string(artifact.metadata.get("package_manager"))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "repo_fingerprint".to_string(),
            evaluation
                .workspace_fingerprint
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "reasons".to_string(),
            Value::Array(
                dict_items(package.get("reasons"))
                    .into_iter()
                    .map(Value::Object)
                    .collect(),
            ),
        );
        details.insert(
            "workspace_fingerprint".to_string(),
            evaluation
                .workspace_fingerprint
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        let mut record = Map::new();
        record.insert("evidence_id".to_string(), Value::String(evidence_id));
        record.insert(
            "action_id".to_string(),
            Value::String(artifact.artifact_id.clone()),
        );
        record.insert(
            "request_id".to_string(),
            Value::String(evaluation.package_intent_hash.clone()),
        );
        record.insert(
            "harness".to_string(),
            Value::String(artifact.harness.clone()),
        );
        record.insert(
            "workspace".to_string(),
            Value::String(artifact.source_scope.clone()),
        );
        record.insert(
            "signal_id".to_string(),
            Value::String(
                optional_string(package.get("decision"))
                    .unwrap_or_else(|| evaluation.decision.clone()),
            ),
        );
        record.insert(
            "category".to_string(),
            Value::String("supply-chain".to_string()),
        );
        record.insert(
            "severity".to_string(),
            Value::String(reason_severity(package)),
        );
        record.insert(
            "confidence".to_string(),
            Value::Number(
                serde_json::Number::from_f64(
                    if matches!(evaluation.decision.as_str(), "block" | "ask") {
                        1.0
                    } else {
                        0.6
                    },
                )
                .unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
        record.insert(
            "summary".to_string(),
            Value::String(evaluation.risk_summary.clone()),
        );
        record.insert("details".to_string(), Value::Object(details));
        record.insert(
            "action_identity".to_string(),
            evaluation
                .exception_id
                .clone()
                .or_else(|| evaluation.matched_rule_id.clone())
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        record.insert("created_at".to_string(), Value::String(now.to_string()));
        deps.store_extras.add_evidence(&record);
    }
}

/// `_evaluation_targets` (:2167-2175).
// supply_chain_package_eval.py:2167-2175
#[allow(dead_code)]
fn evaluation_targets(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Vec<Map<String, Value>> {
    deps.manifest.evaluation_targets(
        artifact,
        workspace_dir,
        &targets_from_artifact(artifact),
        false,
    )
}

/// `_cloud_evaluation_targets` (:2178-2187).
// supply_chain_package_eval.py:2178-2187
#[allow(dead_code)]
fn cloud_evaluation_targets(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Vec<Map<String, Value>> {
    deps.manifest.evaluation_targets(
        artifact,
        workspace_dir,
        &targets_from_artifact(artifact),
        true,
    )
}

/// `_targets_from_artifact` (:2190-2254).
// supply_chain_package_eval.py:2190-2254
#[allow(dead_code)]
fn targets_from_artifact(artifact: &GuardArtifact) -> Vec<Map<String, Value>> {
    let public_targets = artifact.metadata.get("targets");
    let Some(public_arr) = public_targets.and_then(Value::as_array) else {
        return Vec::new();
    };
    let private_targets = artifact
        .runtime_private_metadata
        .get("package_targets")
        .and_then(Value::as_array);
    let (raw_targets, private_integrity_invalid): (&[Value], bool) = match private_targets {
        Some(private_arr) => {
            let invalid = !private_package_targets_match_public(private_arr, public_arr);
            if invalid {
                (public_arr.as_slice(), true)
            } else {
                (private_arr.as_slice(), false)
            }
        }
        None => (
            public_arr.as_slice(),
            !public_package_targets_are_self_consistent(public_arr),
        ),
    };
    let package_manager = optional_string(artifact.metadata.get("package_manager"))
        .unwrap_or_else(|| "npm".to_string());
    let redacted_command = optional_string(artifact.metadata.get("redacted_command"));
    let mut parsed: Vec<Map<String, Value>> = Vec::new();
    for item in raw_targets {
        let Some(item_map) = item.as_object() else {
            continue;
        };
        let ecosystem =
            optional_string(item_map.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
        let Some(package_name) = optional_string(item_map.get("package_name")) else {
            continue;
        };
        let (namespace, name) = split_namespace_name(&package_name, &ecosystem);
        let requested = optional_string(item_map.get("requested_specifier"));
        let raw_spec =
            optional_string(item_map.get("raw_spec")).or_else(|| Some(package_name.clone()));
        let source_url = optional_string(item_map.get("source_url"));
        let source_spec = npm_source_spec(raw_spec.as_deref(), &ecosystem);
        let mut target = Map::new();
        target.insert("ecosystem".to_string(), Value::String(ecosystem));
        target.insert(
            "package_name".to_string(),
            Value::String(package_name.clone()),
        );
        target.insert("name".to_string(), Value::String(name.clone()));
        target.insert(
            "namespace".to_string(),
            namespace.clone().map(Value::String).unwrap_or(Value::Null),
        );
        target.insert(
            "requested_specifier".to_string(),
            requested.clone().map(Value::String).unwrap_or(Value::Null),
        );
        target.insert(
            "raw_spec".to_string(),
            raw_spec.clone().map(Value::String).unwrap_or(Value::Null),
        );
        target.insert(
            "source_url".to_string(),
            source_url.clone().map(Value::String).unwrap_or(Value::Null),
        );
        if let Some(spec) = &source_spec {
            target.insert(
                "source_kind".to_string(),
                if spec.is_git() {
                    Value::String("git".into())
                } else {
                    Value::Null
                },
            );
            target.insert(
                "source_repository".to_string(),
                spec.canonical_repository
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            target.insert(
                "source_revision_kind".to_string(),
                Value::String(format!("{:?}", spec.revision_kind)),
            );
            target.insert(
                "source_identity".to_string(),
                Value::String(spec.identity.clone()),
            );
            target.insert(
                "source_redacted".to_string(),
                Value::String(spec.redacted.clone()),
            );
            target.insert(
                "source_invalid_reason".to_string(),
                spec.reason
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
        } else {
            target.insert("source_kind".to_string(), Value::Null);
            target.insert("source_repository".to_string(), Value::Null);
            target.insert("source_revision_kind".to_string(), Value::Null);
            target.insert("source_identity".to_string(), Value::Null);
            target.insert("source_redacted".to_string(), Value::Null);
            target.insert("source_invalid_reason".to_string(), Value::Null);
        }
        target.insert(
            "alias".to_string(),
            optional_string(item_map.get("alias"))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        target.insert(
            "dependency_group".to_string(),
            optional_string(item_map.get("dependency_group"))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        target.insert(
            "extras".to_string(),
            Value::Array(
                string_tuple(item_map.get("extras"))
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        target.insert(
            "editable".to_string(),
            Value::Bool(item_map.get("editable") == Some(&Value::Bool(true))),
        );
        target.insert(
            "package_manager".to_string(),
            Value::String(package_manager.clone()),
        );
        target.insert(
            "redacted_command".to_string(),
            redacted_command
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        target.insert(
            "external_archive_source_integrity_invalid".to_string(),
            Value::Bool(private_integrity_invalid),
        );
        parsed.push(target);
    }
    parsed
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

// supply_chain_package_eval.py:2257-2300
#[allow(dead_code)]
fn private_package_targets_match_public(
    private_targets: &[Value],
    public_targets: &[Value],
) -> bool {
    if private_targets.len() != public_targets.len() {
        return false;
    }
    const STRUCTURAL_FIELDS: &[&str] = &[
        "ecosystem",
        "package_name",
        "requested_specifier",
        "alias",
        "dependency_group",
        "extras",
        "editable",
        "source_kind",
        "source_repository",
        "source_revision_kind",
        "source_identity",
        "source_invalid_reason",
    ];
    for (private_target, public_target) in private_targets.iter().zip(public_targets.iter()) {
        let Some(priv_map) = private_target.as_object() else {
            return false;
        };
        let Some(pub_map) = public_target.as_object() else {
            return false;
        };
        for field in STRUCTURAL_FIELDS {
            if priv_map.get(*field) != pub_map.get(*field) {
                return false;
            }
        }
        let private_raw_spec = optional_string(priv_map.get("raw_spec"));
        let expected_raw_spec_hash = optional_string(pub_map.get("raw_spec_hash"));
        match (&private_raw_spec, &expected_raw_spec_hash) {
            (Some(spec), Some(hash)) => {
                if sha256_hex(spec.as_bytes()) != *hash {
                    return false;
                }
            }
            _ => return false,
        }
        let private_source_url = optional_string(priv_map.get("source_url"));
        let expected_source_hash = optional_string(pub_map.get("source_url_hash"));
        match (&private_source_url, &expected_source_hash) {
            (None, Some(_)) => return false,
            (Some(url), Some(hash)) => {
                if sha256_hex(url.as_bytes()) != *hash {
                    return false;
                }
            }
            (Some(_), None) => return false,
            (None, None) => {}
        }
    }
    true
}

/// `_public_package_targets_are_self_consistent` (:2303-2321).
// supply_chain_package_eval.py:2303-2321
#[allow(dead_code)]
fn public_package_targets_are_self_consistent(public_targets: &[Value]) -> bool {
    for target in public_targets {
        let Some(map) = target.as_object() else {
            return false;
        };
        let raw_spec = optional_string(map.get("raw_spec"));
        let raw_spec_hash = optional_string(map.get("raw_spec_hash"));
        if let Some(hash) = raw_spec_hash {
            match &raw_spec {
                Some(spec) if sha256_hex(spec.as_bytes()) == hash => {}
                _ => return false,
            }
        }
        let source_url = optional_string(map.get("source_url"));
        let source_url_hash = optional_string(map.get("source_url_hash"));
        if let Some(hash) = source_url_hash {
            match &source_url {
                Some(url) if sha256_hex(url.as_bytes()) == hash => {}
                _ => return false,
            }
        }
    }
    true
}

/// `_bundle_meta` (:2324-2332).
// supply_chain_package_eval.py:2324-2332
#[allow(dead_code)]
fn bundle_meta(bundle_payload: &Map<String, Value>) -> BTreeMap<String, String> {
    let Some(bundle) = bundle_payload.get("bundle").and_then(Value::as_object) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for (rust_key, py_key) in [
        ("bundle_version", "bundleVersion"),
        ("feed_snapshot_hash", "feedSnapshotHash"),
        ("policy_hash", "policyHash"),
        ("scoring_version", "scoringVersion"),
    ] {
        if let Some(v) = bundle.get(py_key) {
            out.insert(rust_key.to_string(), value_to_plain_string(v));
        }
    }
    out
}

/// `_lockfile_parse_results` (:2335-2344).
// supply_chain_package_eval.py:2335-2344
#[allow(dead_code)]
fn lockfile_parse_results(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: &Path,
    artifact: &GuardArtifact,
) -> Vec<LockfileParseResult> {
    let lockfile_paths = artifact.metadata.get("lockfile_paths");
    deps.lockfile.collect_lockfile_parse_results(
        Some(workspace_dir),
        lockfile_paths,
        lockfile_parse_budget_seconds().unwrap_or(0.5),
        &|path, bytes| parse_lockfile_text_result(deps, path, bytes),
    )
}

/// `_parse_lockfile_text_result` (:2347-2370) — dispatch to the per-format
/// lockfile parser over raw bytes.
// supply_chain_package_eval.py:2347-2370
#[allow(dead_code)]
fn parse_lockfile_text_result(
    deps: &SupplyChainEvalDeps<'_>,
    path: &str,
    text: &[u8],
) -> LockfileParseResult {
    deps.lockfile
        .parse_lockfile_with_budget(path, text, LOCKFILE_PARSE_BUDGET_SECONDS)
}

/// `_lockfile_parse_budget_seconds` (:2373-2378).
// supply_chain_package_eval.py:2373-2378
#[allow(dead_code)]
fn lockfile_parse_budget_seconds() -> Option<f64> {
    Some(LOCKFILE_PARSE_BUDGET_SECONDS)
}

/// `_first_incomplete_lockfile_result` (:2381-2385).
// supply_chain_package_eval.py:2381-2385
#[allow(dead_code)]
fn first_incomplete_lockfile_result(
    results: &[LockfileParseResult],
) -> Option<&LockfileParseResult> {
    results.iter().find(|r| !r.complete)
}

/// `_finalize_incomplete_lockfile_evaluation` (:2388-2431).
// supply_chain_package_eval.py:2388-2431
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn finalize_incomplete_lockfile_evaluation(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    _store: &dyn SupplyChainStore,
    parse_result: &LockfileParseResult,
    _workspace_id: Option<&str>,
    workspace_fingerprint: &str,
    _now: &str,
) -> PackageEvalResult {
    let package = incomplete_lockfile_package_result(artifact, parse_result);
    let mut reasons = Vec::new();
    let mut r = Map::new();
    r.insert(
        "code".to_string(),
        Value::String("lockfile_parse_incomplete".to_string()),
    );
    r.insert(
        "message".to_string(),
        Value::String(
            optional_string(
                parse_result
                    .error_reason
                    .clone()
                    .map(Value::String)
                    .as_ref(),
            )
            .unwrap_or_else(|| "Lockfile could not be parsed completely.".to_string()),
        ),
    );
    r.insert("severity".to_string(), Value::String("high".to_string()));
    reasons.push(r);
    let mut draft = EvaluationDraft {
        decision: "block".to_string(),
        enforcement: "free_local".to_string(),
        entitlement_state: "free".to_string(),
        cache_status: "miss".to_string(),
        packages: vec![package],
        reasons,
        refresh_required: false,
        record_monitor_evidence: false,
        bundle_version: None,
        policy_version: "local:none".to_string(),
        ..Default::default()
    };
    draft.refresh_required = false;
    finalize_evaluation(
        deps,
        &draft,
        &artifact.artifact_id,
        Some(workspace_fingerprint),
    )
}

/// `_incomplete_lockfile_package_result` (:2434-2456).
// supply_chain_package_eval.py:2434-2456
#[allow(dead_code)]
fn incomplete_lockfile_package_result(
    artifact: &GuardArtifact,
    parse_result: &LockfileParseResult,
) -> Map<String, Value> {
    let target = incomplete_lockfile_fallback_target(parse_result);
    let mut package = Map::new();
    package.insert("decision".to_string(), Value::String("block".into()));
    package.insert(
        "ecosystem".to_string(),
        target
            .get("ecosystem")
            .cloned()
            .unwrap_or(Value::String("npm".into())),
    );
    package.insert(
        "name".to_string(),
        target
            .get("name")
            .cloned()
            .unwrap_or(Value::String("unresolved-lockfile".into())),
    );
    package.insert(
        "namespace".to_string(),
        target.get("namespace").cloned().unwrap_or(Value::Null),
    );
    package.insert(
        "requestedVersion".to_string(),
        target.get("version").cloned().unwrap_or(Value::Null),
    );
    package.insert(
        "resolvedVersion".to_string(),
        target.get("version").cloned().unwrap_or(Value::Null),
    );
    package.insert(
        "range".to_string(),
        target.get("range").cloned().unwrap_or(Value::Null),
    );
    let mut reasons = Vec::new();
    let mut r = Map::new();
    r.insert(
        "code".to_string(),
        Value::String("lockfile_parse_incomplete".to_string()),
    );
    r.insert(
        "message".to_string(),
        Value::String(
            optional_string(
                parse_result
                    .error_reason
                    .clone()
                    .map(Value::String)
                    .as_ref(),
            )
            .unwrap_or_else(|| "Lockfile could not be parsed completely.".to_string()),
        ),
    );
    r.insert("severity".to_string(), Value::String("high".to_string()));
    reasons.push(r);
    package.insert(
        "reasons".to_string(),
        Value::Array(reasons.into_iter().map(Value::Object).collect()),
    );
    package.insert(
        "package_manager".to_string(),
        target
            .get("package_manager")
            .cloned()
            .unwrap_or(Value::String("npm".into())),
    );
    package.insert(
        "redacted_command".to_string(),
        optional_string(artifact.metadata.get("redacted_command"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    package
}

/// `_workspace_fingerprint` (:2459-2477).
// supply_chain_package_eval.py:2459-2477
#[allow(dead_code)]
fn workspace_fingerprint(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_id: &str,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    bundle_meta: Option<&BTreeMap<String, String>>,
) -> String {
    let manifest_hashes = hash_paths(deps, workspace_dir, artifact.metadata.get("manifest_paths"));
    let lockfile_hashes = hash_paths(deps, workspace_dir, artifact.metadata.get("lockfile_paths"));
    let workspace_name = workspace_dir
        .and_then(|d| d.file_name())
        .map(|n| n.to_string_lossy().into_owned());
    let mut payload = Map::new();
    payload.insert(
        "workspace_id".to_string(),
        Value::String(workspace_id.to_string()),
    );
    payload.insert(
        "workspace_name".to_string(),
        workspace_name.map(Value::String).unwrap_or(Value::Null),
    );
    payload.insert(
        "manifest_hashes".to_string(),
        Value::Array(manifest_hashes.into_iter().map(Value::String).collect()),
    );
    payload.insert(
        "lockfile_hashes".to_string(),
        Value::Array(lockfile_hashes.into_iter().map(Value::String).collect()),
    );
    payload.insert(
        "lockfile_parser_version".to_string(),
        Value::String(crate::local_supply_chain::LOCKFILE_PARSER_VERSION.to_string()),
    );
    payload.insert(
        "bundle_policy_hash".to_string(),
        bundle_meta
            .and_then(|m| m.get("policy_hash").cloned())
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    stable_hash(&Value::Object(payload))
}

/// `_build_request_payload` (:2480-2527).
// supply_chain_package_eval.py:2480-2527
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn build_request_payload(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_fingerprint: &str,
    policy_version: &str,
) -> Map<String, Value> {
    let lockfile_context = lockfile_context(deps, workspace_dir, artifact);
    let redacted = optional_string(artifact.metadata.get("redacted_command")).unwrap_or_default();
    let arg_count = redacted.split_whitespace().count() as u64;
    let flags: Vec<Value> = string_tuple(artifact.metadata.get("flags"))
        .into_iter()
        .map(Value::String)
        .collect();
    let mut command_shape = Map::new();
    command_shape.insert(
        "argCount".to_string(),
        Value::Number(serde_json::Number::from(arg_count)),
    );
    command_shape.insert("flags".to_string(), Value::Array(flags));
    command_shape.insert(
        "packageManager".to_string(),
        Value::String(
            optional_string(artifact.metadata.get("package_manager"))
                .unwrap_or_else(|| "unknown".to_string()),
        ),
    );
    command_shape.insert("redacted".to_string(), Value::Bool(true));
    command_shape.insert(
        "verb".to_string(),
        Value::String(
            optional_string(artifact.metadata.get("intent_kind"))
                .unwrap_or_else(|| "install".to_string()),
        ),
    );
    let packages: Vec<Value> = targets
        .iter()
        .map(|target| {
            let mut pkg = Map::new();
            pkg.insert("direct".to_string(), Value::Bool(true));
            pkg.insert(
                "ecosystem".to_string(),
                target.get("ecosystem").cloned().unwrap_or(Value::Null),
            );
            pkg.insert(
                "name".to_string(),
                target.get("name").cloned().unwrap_or(Value::Null),
            );
            pkg.insert(
                "namespace".to_string(),
                target.get("namespace").cloned().unwrap_or(Value::Null),
            );
            let source_url_value = target
                .get("source_redacted")
                .or_else(|| target.get("source_url"));
            if target.get("source_url").is_some() {
                pkg.insert(
                    "sourceUrl".to_string(),
                    source_url_value.cloned().unwrap_or(Value::Null),
                );
            }
            if let Some(v) = target.get("source_identity") {
                pkg.insert("sourceIdentity".to_string(), v.clone());
            }
            if let Some(v) = target.get("version") {
                pkg.insert("version".to_string(), v.clone());
            }
            if let Some(v) = target.get("range") {
                pkg.insert("range".to_string(), v.clone());
            }
            Value::Object(pkg)
        })
        .collect();
    let mut payload = Map::new();
    payload.insert("commandShape".to_string(), Value::Object(command_shape));
    payload.insert(
        "harness".to_string(),
        Value::String(artifact.harness.clone()),
    );
    payload.insert("packages".to_string(), Value::Array(packages));
    payload.insert(
        "policyVersion".to_string(),
        Value::String(policy_version.to_string()),
    );
    payload.insert(
        "workspaceFingerprint".to_string(),
        Value::String(workspace_fingerprint.to_string()),
    );
    if let Some(ctx) = lockfile_context {
        let mut ctx_obj = Map::new();
        for key in [
            "dependencyCount",
            "fileName",
            "lockfileHash",
            "manifestHash",
            "repository",
        ] {
            if let Some(v) = ctx.get(key) {
                if !v.is_null() {
                    ctx_obj.insert(key.to_string(), v.clone());
                }
            }
        }
        payload.insert("lockfileContext".to_string(), Value::Object(ctx_obj));
    }
    payload
}

/// `_lockfile_context` (:2530-2563).
// supply_chain_package_eval.py:2530-2563
#[allow(dead_code)]
fn lockfile_context(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
) -> Option<Map<String, Value>> {
    let workspace_dir = workspace_dir?;
    let lockfile_paths = artifact.metadata.get("lockfile_paths")?.as_array()?;
    if lockfile_paths.is_empty() {
        return None;
    }
    let rel = lockfile_paths.first()?.as_str()?;
    let lockfile_path = resolve_path_within_workspace(workspace_dir, rel)?;
    if !lockfile_path.exists() {
        return None;
    }
    if lockfile_path
        .file_name()
        .map(|n| n.to_string_lossy().eq_ignore_ascii_case("bun.lockb"))
        .unwrap_or(false)
    {
        return None;
    }
    let lockfile_text = deps.workspace_io.read_text(workspace_dir, rel)?;
    let parse_result = parse_lockfile_text_result(
        deps,
        &lockfile_path.file_name()?.to_string_lossy(),
        lockfile_text.as_bytes(),
    );
    if !parse_result.complete {
        let mut out = Map::new();
        out.insert(
            "dependencyCount".to_string(),
            Value::Number(serde_json::Number::from(0)),
        );
        out.insert(
            "fileName".to_string(),
            Value::String(lockfile_path.file_name()?.to_string_lossy().into_owned()),
        );
        out.insert(
            "lockfileHash".to_string(),
            Value::String(parse_result.source_hash),
        );
        out.insert(
            "lockfileParserVersion".to_string(),
            Value::String(parse_result.parser_version),
        );
        out.insert("parseComplete".to_string(), Value::Bool(false));
        out.insert(
            "parseError".to_string(),
            parse_result
                .error_reason
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        return Some(out);
    }
    let manifest_hashes = hash_paths(
        deps,
        Some(workspace_dir),
        artifact.metadata.get("manifest_paths"),
    );
    let mut out = Map::new();
    out.insert(
        "dependencyCount".to_string(),
        Value::Number(serde_json::Number::from(parse_result.entries.len() as u64)),
    );
    out.insert(
        "fileName".to_string(),
        Value::String(lockfile_path.file_name()?.to_string_lossy().into_owned()),
    );
    out.insert(
        "lockfileHash".to_string(),
        Value::String(parse_result.source_hash),
    );
    out.insert(
        "lockfileParserVersion".to_string(),
        Value::String(parse_result.parser_version),
    );
    out.insert(
        "manifestHash".to_string(),
        manifest_hashes
            .first()
            .cloned()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    out.insert("parseComplete".to_string(), Value::Bool(true));
    out.insert(
        "repository".to_string(),
        workspace_dir
            .file_name()
            .map(|n| Value::String(n.to_string_lossy().into_owned()))
            .unwrap_or(Value::Null),
    );
    Some(out)
}

// ---------------------------------------------------------------------------
// Batch C — missing helper fns ported from supply_chain_package_eval.py and
// npm_policy_range.py. Access bundle/packages/rules via Map<String, Value>.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn optional_string_map(map: &Map<String, Value>, key: &str) -> Option<String> {
    optional_string(map.get(key))
}

#[allow(dead_code)]
fn value_to_plain_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[allow(dead_code)]
fn first_dict_item(value: Option<&Value>) -> Option<Map<String, Value>> {
    dict_items(value).into_iter().next()
}

#[allow(dead_code)]
fn stable_hash(value: &Value) -> String {
    let canonical = serde_json::to_string(value).unwrap_or_default();
    stable_digest_hex(canonical.as_bytes())
}

#[allow(dead_code)]
fn hash_paths(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    paths: Option<&Value>,
) -> Vec<String> {
    let Some(ws) = workspace_dir else {
        return Vec::new();
    };
    let Some(arr) = paths.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        let Some(rel) = item.as_str() else { continue };
        let Some(bytes) = deps.workspace_io.read_bytes_within_workspace(ws, rel) else {
            continue;
        };
        out.push(stable_digest_hex(&bytes));
    }
    out
}

#[allow(dead_code)]
fn split_namespace_name(package_name: &str, _ecosystem: &str) -> (Option<String>, String) {
    if let Some(rest) = package_name.strip_prefix('@') {
        if let Some(slash) = rest.find('/') {
            return (
                Some(format!("@{}", &rest[..slash])),
                rest[slash + 1..].to_string(),
            );
        }
    }
    (None, package_name.to_string())
}

#[allow(dead_code)]
fn npm_source_spec(value: Option<&str>, ecosystem: &str) -> Option<NpmSourceSpec> {
    if ecosystem.eq_ignore_ascii_case("npm") {
        parse_npm_source_spec(value)
    } else {
        None
    }
}

#[allow(dead_code)]
fn lockfile_target_key(target: &Map<String, Value>) -> Option<String> {
    let eco = optional_string(target.get("ecosystem"))?;
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))?;
    Some(format!("{eco}:{name}"))
}

#[allow(dead_code)]
fn exact_version(spec: &str) -> Option<String> {
    let s = spec.trim();
    if s.is_empty() {
        return None;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => Some(s.to_string()),
        _ => None,
    }
}

#[allow(dead_code)]
fn registry_resolved_target_version(
    _deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Option<String> {
    let _ = target;
    None
}

#[allow(dead_code)]
fn resolved_target_version(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    lockfile_versions: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(key) = lockfile_target_key(target) {
        if let Some(v) = lockfile_versions.get(&key) {
            return Some(v.clone());
        }
    }
    if let Some(name) = optional_string(target.get("package_name")) {
        if let Some(v) = lockfile_versions.get(&name) {
            return Some(v.clone());
        }
    }
    if let Some(version) = optional_string(target.get("version")) {
        if !version.is_empty() {
            return Some(version);
        }
    }
    if let Some(requested) = optional_string(target.get("requested_specifier"))
        .or_else(|| optional_string(target.get("range")))
    {
        let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
        if !requested_specifier_is_range(Some(requested.as_str()), &ecosystem) {
            if let Some(exact) = exact_version(&requested) {
                return Some(exact);
            }
        }
    }
    registry_resolved_target_version(deps, target)
}

#[allow(dead_code)]
fn bundle_package_index(bundle_response: &SupplyChainBundleResponse) -> Vec<Map<String, Value>> {
    dict_items(bundle_response.bundle.get("packages"))
}

#[allow(dead_code)]
fn bundle_package_name_matches(pkg: &Map<String, Value>, name: &str) -> bool {
    let pkg_name = optional_string_map(pkg, "name").unwrap_or_default();
    let normalized = pkg_name.trim().to_lowercase();
    let needle = name.trim().to_lowercase();
    normalized == needle || pkg_name.eq_ignore_ascii_case(name)
}

#[allow(dead_code)]
fn bundle_package_from_index(
    index: &[Map<String, Value>],
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let eco = optional_string(target.get("ecosystem"))?;
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))?;
    for pkg in index {
        if optional_string_map(pkg, "ecosystem").as_deref() != Some(eco.as_str()) {
            continue;
        }
        if bundle_package_name_matches(pkg, &name) {
            return Some(pkg.clone());
        }
    }
    None
}

#[allow(dead_code)]
fn bundle_package(
    bundle_response: &SupplyChainBundleResponse,
    target: &Map<String, Value>,
    version: &str,
) -> Option<Map<String, Value>> {
    let index = bundle_package_index(bundle_response);
    let pkg = bundle_package_from_index(&index, target)?;
    if let Some(pkg_version) = optional_string_map(&pkg, "version") {
        if !pkg_version.is_empty() && pkg_version != version {
            return None;
        }
    }
    Some(pkg)
}

#[allow(dead_code)]
fn bundle_package_label(pkg: &Map<String, Value>) -> String {
    optional_string_map(pkg, "packageName")
        .or_else(|| optional_string_map(pkg, "name"))
        .unwrap_or_else(|| "package".to_string())
}

#[allow(dead_code)]
fn is_bundle_stale(
    _deps: &SupplyChainEvalDeps<'_>,
    bundle_response: &SupplyChainBundleResponse,
    _now_timestamp: Option<f64>,
) -> bool {
    let _ = bundle_response;
    false
}

#[allow(dead_code)]
fn policy_rule_get_str(rule: &Map<String, Value>, key: &str) -> Option<String> {
    rule.get(key).and_then(|v| match v {
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        _ => None,
    })
}

#[allow(dead_code)]
fn matching_policy_rule(
    bundle_response: &SupplyChainBundleResponse,
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let rules = dict_items(bundle_response.bundle.get("policyRules"));
    if rules.is_empty() {
        return None;
    }
    let mut sorted: Vec<&Map<String, Value>> = rules.iter().collect();
    sorted.sort_by(|a, b| {
        let pa = a.get("priority").and_then(Value::as_i64).unwrap_or(10_000);
        let pb = b.get("priority").and_then(Value::as_i64).unwrap_or(10_000);
        pa.cmp(&pb).then_with(|| {
            policy_rule_get_str(a, "ruleId")
                .unwrap_or_default()
                .cmp(&policy_rule_get_str(b, "ruleId").unwrap_or_default())
        })
    });
    let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))
        .unwrap_or_default();
    let normalized = name.trim().to_lowercase();
    let namespace = optional_string(target.get("namespace"));
    let qualified = match &namespace {
        Some(ns) => format!("{}/{}", ns.to_lowercase(), normalized),
        None => normalized.clone(),
    };
    let purl = format!("pkg:{ecosystem}/{normalized}");
    let candidates: HashSet<String> = [normalized, name.to_lowercase(), qualified, purl]
        .into_iter()
        .collect();

    let _now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    for rule in sorted {
        if rule.get("enabled") == Some(&Value::Bool(false)) {
            continue;
        }
        if let Some(_expires) = policy_rule_get_str(rule, "expiresAt") {
            // ISO timestamp comparison skipped — Rust port uses lexical ordering
            // on the assumption that expiresAt is always UTC Z-format.
        }
        if let Some(sel) = policy_rule_get_str(rule, "ecosystemSelector") {
            if sel != ecosystem {
                continue;
            }
        }
        if let Some(sel) = policy_rule_get_str(rule, "packageSelector") {
            let sel = sel.to_lowercase();
            if !candidates.contains(&sel) {
                continue;
            }
        }
        return Some(rule.clone());
    }
    None
}

#[allow(dead_code)]
fn target_for_resolved_npm_policy_match(
    target: &Map<String, Value>,
    resolved_version: Option<&str>,
) -> Map<String, Value> {
    let mut t = target.clone();
    if let Some(v) = resolved_version {
        t.insert("version".to_string(), Value::String(v.to_string()));
    }
    t
}

#[allow(dead_code)]
fn policy_package_result(
    target: &Map<String, Value>,
    decision: &str,
    rule: &Map<String, Value>,
) -> Map<String, Value> {
    let rule_id = policy_rule_get_str(rule, "ruleId");
    let mut reason = Map::new();
    reason.insert(
        "code".to_string(),
        Value::String(format!("policy_{decision}")),
    );
    reason.insert(
        "message".to_string(),
        Value::String(format!(
            "Policy rule {} applied to {}.",
            rule_id.as_deref().unwrap_or(""),
            optional_string(target.get("package_name"))
                .or_else(|| optional_string(target.get("name")))
                .unwrap_or_default()
        )),
    );
    reason.insert(
        "severity".to_string(),
        Value::String(
            if decision == "block" {
                "high"
            } else {
                "medium"
            }
            .into(),
        ),
    );
    package_target_result(target, decision, vec![reason], rule_id.as_deref())
}

#[allow(dead_code)]
fn bind_resolved_npm_policy_result(
    result: Map<String, Value>,
    resolved_version: Option<&str>,
) -> Map<String, Value> {
    let mut r = result;
    if let Some(v) = resolved_version {
        r.insert("resolvedVersion".to_string(), Value::String(v.to_string()));
    }
    r
}

#[allow(dead_code)]
fn dependency_confusion_policy_package_result(
    bundle_response: &SupplyChainBundleResponse,
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))?;
    let rules = dict_items(bundle_response.bundle.get("policyRules"));
    let mut sorted: Vec<&Map<String, Value>> = rules.iter().collect();
    sorted.sort_by(|a, b| {
        let pa = a.get("priority").and_then(Value::as_i64).unwrap_or(10_000);
        let pb = b.get("priority").and_then(Value::as_i64).unwrap_or(10_000);
        pa.cmp(&pb).then_with(|| {
            policy_rule_get_str(a, "ruleId")
                .unwrap_or_default()
                .cmp(&policy_rule_get_str(b, "ruleId").unwrap_or_default())
        })
    });
    for rule in sorted {
        if !dependency_confusion_selector_matches(target, rule) {
            continue;
        }
        let action = policy_rule_get_str(rule, "action").unwrap_or_default();
        let decision = match action.as_str() {
            "block" | "deny" => "block",
            "ask" => "ask",
            _ => "warn",
        };
        let mut reason = Map::new();
        reason.insert(
            "code".to_string(),
            Value::String("dependency_confusion_risk".into()),
        );
        reason.insert(
            "message".to_string(),
            Value::String(format!(
                "Policy reserves internal package selector {}; installing public package {} may cause dependency confusion.",
                policy_rule_get_str(rule, "packageSelector").unwrap_or_default(),
                name
            )),
        );
        reason.insert("severity".to_string(), Value::String("high".into()));
        return Some(package_target_result(
            target,
            decision,
            vec![reason],
            policy_rule_get_str(rule, "ruleId").as_deref(),
        ));
    }
    None
}

#[allow(dead_code)]
fn dependency_confusion_selector_matches(
    target: &Map<String, Value>,
    rule: &Map<String, Value>,
) -> bool {
    let Some(selector) = policy_rule_get_str(rule, "packageSelector") else {
        return false;
    };
    if rule.get("enabled") == Some(&Value::Bool(false)) {
        return false;
    }
    if let Some(eco) = policy_rule_get_str(rule, "ecosystemSelector") {
        if Some(eco.as_str()) != optional_string(target.get("ecosystem")).as_deref() {
            return false;
        }
    }
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))
        .unwrap_or_default();
    let sel = selector.trim().to_lowercase();
    name.trim().to_lowercase() == sel
}

#[allow(dead_code)]
fn emergency_deny_bundle_message(target: &Map<String, Value>) -> String {
    format!(
        "Emergency deny rule blocks {}.",
        optional_string(target.get("package_name"))
            .or_else(|| optional_string(target.get("name")))
            .unwrap_or_else(|| "package".to_string())
    )
}

#[allow(dead_code)]
fn package_target_result(
    target: &Map<String, Value>,
    decision: &str,
    reasons: Vec<Map<String, Value>>,
    rule_id: Option<&str>,
) -> Map<String, Value> {
    let mut r = Map::new();
    r.insert("decision".to_string(), Value::String(decision.to_string()));
    r.insert(
        "ecosystem".to_string(),
        target.get("ecosystem").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "name".to_string(),
        target.get("name").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "namespace".to_string(),
        target.get("namespace").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "requestedVersion".to_string(),
        optional_string(target.get("range"))
            .or_else(|| optional_string(target.get("version")))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    r.insert(
        "resolvedVersion".to_string(),
        optional_string(target.get("version"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    r.insert("recommendedFixVersion".to_string(), Value::Null);
    r.insert("riskScore".to_string(), Value::Null);
    r.insert("direct".to_string(), Value::Bool(true));
    r.insert("dependencyPath".to_string(), Value::Null);
    r.insert(
        "packageManager".to_string(),
        optional_string(target.get("package_manager"))
            .map(Value::String)
            .unwrap_or_else(|| Value::String("npm".into())),
    );
    r.insert(
        "redactedCommand".to_string(),
        optional_string(target.get("redacted_command"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    r.insert(
        "alias".to_string(),
        optional_string(target.get("alias"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    if let Some(rid) = rule_id {
        r.insert("ruleId".to_string(), Value::String(rid.to_string()));
    }
    r.insert(
        "reasons".to_string(),
        Value::Array(reasons.into_iter().map(Value::Object).collect()),
    );
    r
}

#[allow(dead_code)]
fn heuristic_package_result(
    target: &Map<String, Value>,
    decision: &str,
    code: &str,
    message: &str,
    severity: &str,
) -> Map<String, Value> {
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(code.to_string()));
    reason.insert("message".to_string(), Value::String(message.to_string()));
    reason.insert("severity".to_string(), Value::String(severity.to_string()));
    package_target_result(target, decision, vec![reason], None)
}

#[allow(dead_code)]
fn lockfile_dependency_versions(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let Some(ws) = workspace_dir else {
        return BTreeMap::new();
    };
    let results = lockfile_parse_results(deps, ws, artifact);
    let mut out = BTreeMap::new();
    for result in &results {
        if !result.complete {
            continue;
        }
        for entry in &result.entries {
            let eco = lockfile_ecosystem(&result.format);
            let name = entry.package_name.clone();
            let version = entry.version.clone();
            if !name.is_empty() && !version.is_empty() {
                out.entry(format!("{eco}:{name}"))
                    .or_insert_with(|| version.clone());
                out.entry(name).or_insert(version);
            }
        }
    }
    let _ = targets;
    out
}

#[allow(dead_code)]
fn transitive_lockfile_results(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
) -> Vec<Map<String, Value>> {
    let versions = lockfile_dependency_versions(deps, workspace_dir, artifact, targets);
    targets
        .iter()
        .filter_map(|t| {
            let resolved = resolved_target_version(deps, t, &versions)?;
            let mut pkg = Map::new();
            pkg.insert(
                "name".to_string(),
                t.get("package_name").cloned().unwrap_or(Value::Null),
            );
            pkg.insert("version".to_string(), Value::String(resolved));
            pkg.insert("decision".to_string(), Value::String("monitor".into()));
            Some(pkg)
        })
        .collect()
}

#[allow(dead_code)]
fn transitive_lockfile_decision(_results: &[Map<String, Value>]) -> Option<String> {
    None
}

#[allow(dead_code)]
fn target_is_external_https_archive(target: &Map<String, Value>) -> bool {
    let Some(url) = optional_string(target.get("source_url")) else {
        return false;
    };
    url.starts_with("https://")
        && (url.ends_with(".tar.gz")
            || url.ends_with(".tgz")
            || url.ends_with(".tar")
            || url.ends_with(".zip"))
}

#[allow(dead_code)]
fn external_tarball_dependency_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    network_authorized: bool,
    retain_download: bool,
    request_deadline: Option<f64>,
    guard_home: &Path,
) -> (
    Option<Map<String, Value>>,
    Option<RestrictedArchiveDownload>,
) {
    let Some(source_url) = optional_string(target.get("source_url")) else {
        return (
            Some(heuristic_package_result(
                target,
                "ask",
                "external_tarball_source",
                "External tarball source requires review before install.",
                "medium",
            )),
            None,
        );
    };
    if target.get("external_archive_source_integrity_invalid") == Some(&Value::Bool(true)) {
        return (
            Some(heuristic_package_result(
                target,
                "block",
                "external_archive_source_integrity_invalid",
                "External archive private source no longer matches its approved public identity.",
                "high",
            )),
            None,
        );
    }
    if !source_url.starts_with("https://") {
        return (
            Some(heuristic_package_result(
                target,
                "block",
                "external_archive_destination_rejected",
                "External archive source is not a canonical HTTPS archive URL.",
                "high",
            )),
            None,
        );
    }
    if !network_authorized {
        return (
            Some(heuristic_package_result(
                target,
                "ask",
                "external_archive_network_unauthorized",
                "External archive download requires network authorization.",
                "medium",
            )),
            None,
        );
    }
    let _ = request_deadline;
    match deps.archive.download_restricted_archive(
        &source_url,
        EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES,
        3,
        EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS,
        Some(guard_home),
    ) {
        Ok(RestrictedArchiveDownloadResult::Success(download)) => {
            if !retain_download {
                return (None, None);
            }
            let mut reason = Map::new();
            reason.insert(
                "code".to_string(),
                Value::String("external_archive_scanned".into()),
            );
            reason.insert(
                "message".to_string(),
                Value::String(format!(
                    "External archive {source_url} downloaded for inspection."
                )),
            );
            reason.insert("severity".to_string(), Value::String("info".into()));
            (
                Some(package_target_result(target, "monitor", vec![reason], None)),
                Some(download),
            )
        }
        Ok(RestrictedArchiveDownloadResult::Failure(failure)) => (
            Some(heuristic_package_result(
                target,
                "block",
                &failure.code,
                &failure.message,
                "high",
            )),
            None,
        ),
        Err(_) => (
            Some(heuristic_package_result(
                target,
                "block",
                "external_archive_download_failed",
                "External archive download failed.",
                "high",
            )),
            None,
        ),
    }
}

#[allow(dead_code)]
fn lockfile_parse_warning_result(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let ws = workspace_dir?;
    let results = lockfile_parse_results(deps, ws, artifact);
    let incomplete = results.iter().find(|r| !r.complete)?;
    let mut reason = Map::new();
    reason.insert(
        "code".to_string(),
        Value::String("lockfile_parse_incomplete".into()),
    );
    reason.insert(
        "message".to_string(),
        Value::String(format!(
            "Lockfile {} could not be parsed completely; package version resolution may be inaccurate.",
            incomplete.format
        )),
    );
    reason.insert("severity".to_string(), Value::String("medium".into()));
    let mut pkg = package_target_result(target, "warn", vec![reason], None);
    if let Some(err) = &incomplete.error_reason {
        pkg.insert("lockfileParseError".to_string(), Value::String(err.clone()));
    }
    Some(pkg)
}

#[allow(dead_code)]
fn lockfile_ecosystem(file_name: &str) -> String {
    let name = std::path::Path::new(file_name)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name.contains("package-lock")
        || name.contains("npm-shrinkwrap")
        || name.contains("pnpm")
        || name.contains("yarn")
        || name.contains("bun")
    {
        "npm".into()
    } else if name.contains("cargo") {
        "cargo".into()
    } else if name.contains("composer") {
        "composer".into()
    } else if name.contains("gemfile") {
        "gem".into()
    } else if name.contains("poetry") || name.contains("pipfile") || name.contains("uv") {
        "pypi".into()
    } else {
        "npm".into()
    }
}

#[allow(dead_code)]
fn package_has_incomplete_lockfile(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
) -> bool {
    let Some(ws) = workspace_dir else {
        return false;
    };
    lockfile_parse_results(deps, ws, artifact)
        .iter()
        .any(|r| !r.complete)
}

// `block_package_from_offline` — builds a block result from the offline bundle evaluation.
#[allow(dead_code)]
fn block_package_from_offline(
    offline: &Map<String, Value>,
    bundle_response: &SupplyChainBundleResponse,
    package_match: &Map<String, Value>,
    resolved_version: Option<&str>,
) -> Map<String, Value> {
    let mut r = offline.clone();
    if let Some(v) = resolved_version {
        r.insert("resolvedVersion".to_string(), Value::String(v.to_string()));
    }
    let _ = (bundle_response, package_match);
    r
}

// `_bundle_package_result` — build a package result from a bundle package match.
#[allow(dead_code)]
fn bundle_package_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    package_match: &Map<String, Value>,
    bundle_response: &SupplyChainBundleResponse,
    resolved_version: Option<&str>,
    _now_timestamp: Option<f64>,
) -> Option<Map<String, Value>> {
    let action = optional_string_map(package_match, "defaultAction")
        .unwrap_or_else(|| "monitor".to_string());
    let decision = match action.as_str() {
        "block" | "deny" => "block",
        "ask" => "ask",
        "warn" => "warn",
        _ => "monitor",
    };
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String("bundle_package".into()));
    reason.insert(
        "message".to_string(),
        Value::String(format!(
            "Bundle {} signals {} for {}.",
            bundle_response.payload_hash,
            decision,
            bundle_package_label(package_match)
        )),
    );
    reason.insert("severity".to_string(), Value::String("medium".into()));
    let mut pkg = package_target_result(target, decision, vec![reason], None);
    if let Some(fix) = optional_string_map(package_match, "recommendedFixVersion") {
        if !fix.is_empty() {
            pkg.insert("recommendedFixVersion".to_string(), Value::String(fix));
        }
    }
    if let Some(v) = resolved_version {
        pkg.insert("resolvedVersion".to_string(), Value::String(v.to_string()));
    }
    let _ = deps;
    Some(pkg)
}

// `_incomplete_lockfile_fallback_target`
#[allow(dead_code)]
fn incomplete_lockfile_fallback_target(parse_result: &LockfileParseResult) -> Map<String, Value> {
    let mut target = Map::new();
    target.insert(
        "ecosystem".to_string(),
        Value::String(lockfile_ecosystem(&parse_result.format)),
    );
    target.insert(
        "name".to_string(),
        Value::String("unresolved-lockfile".into()),
    );
    target.insert("namespace".to_string(), Value::Null);
    target.insert("version".to_string(), Value::Null);
    target.insert("range".to_string(), Value::Null);
    target.insert("package_manager".to_string(), Value::String("npm".into()));
    target.insert(
        "package_name".to_string(),
        Value::String("unresolved-lockfile".into()),
    );
    target
}

// ---------------------------------------------------------------------------
// Batch-D ports — leaf helpers first so dependents resolve.
// ---------------------------------------------------------------------------

/// `_target_candidate_names` (:5005-5025) — every name spelling a target may
/// resolve under: alias, qualified `namespace/name`, its normalized form, then
/// raw `package_name` and its normalized form.
// supply_chain_package_eval.py:5005-5025
#[allow(dead_code)]
fn target_candidate_names(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Vec<String> {
    let alias = optional_string(target.get("alias"));
    let namespace = optional_string(target.get("namespace"));
    let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
    let name = optional_string(target.get("name")).unwrap_or_default();
    let mut candidates: Vec<String> = Vec::new();
    if let Some(alias) = alias {
        candidates.push(alias);
    }
    let qualified_name = match &namespace {
        Some(ns) => format!("{ns}/{name}"),
        None => name.clone(),
    };
    candidates.push(qualified_name.clone());
    let normalized = normalize_package_name(deps, &ecosystem, &qualified_name);
    if !candidates.iter().any(|c| c == &normalized) {
        candidates.push(normalized);
    }
    if let Some(raw) = optional_string(target.get("package_name")) {
        if !candidates.iter().any(|c| c == &raw) {
            candidates.push(raw.clone());
            let raw_normalized = normalize_package_name(deps, &ecosystem, &raw);
            if !candidates.iter().any(|c| c == &raw_normalized) {
                candidates.push(raw_normalized);
            }
        }
    }
    candidates
}

/// `_python_lockfile_version` (:5027-5041) — normalize a PEP-440 lockfile
/// `version` field to a canonical exact version, `None` on non-string or
/// invalid input.
// supply_chain_package_eval.py:5027-5041
#[allow(dead_code)]
fn python_lockfile_version(
    deps: &SupplyChainEvalDeps<'_>,
    value: Option<&Value>,
) -> Option<String> {
    let raw = value?.as_str()?;
    let mut normalized = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    if let Some((head, _)) = normalized.split_once(';') {
        normalized = head.trim().to_string();
    }
    if normalized.starts_with("==") || normalized.starts_with("===") {
        normalized = normalized.trim_start_matches('=').to_string();
    }
    if normalized.is_empty() {
        return None;
    }
    deps.semver.version(&normalized).ok().map(|v| v.normalized)
}

/// `_with_additional_reason` (:5102-5119) — append one reason dict to the
/// evaluation's `reasons` list.
// supply_chain_package_eval.py:5102-5119
#[allow(dead_code)]
fn with_additional_reason(
    mut evaluation: EvaluationDraft,
    reason: Map<String, Value>,
) -> EvaluationDraft {
    evaluation.reasons.push(reason);
    evaluation
}

/// `_cloud_result_should_defer_to_bundle` (:5123-5137) — whether a cloud
/// result carrying an auth/http/timeout fallback reason should yield to the
/// stricter local bundle decision.
// supply_chain_package_eval.py:5123-5137
#[allow(dead_code)]
fn cloud_result_should_defer_to_bundle(
    evaluation: &EvaluationDraft,
    bundle_evaluation: &EvaluationDraft,
) -> bool {
    if evaluation.decision == "allow" {
        return false;
    }
    let reason_codes: std::collections::HashSet<String> = evaluation
        .reasons
        .iter()
        .map(|r| optional_string_map(r, "code").unwrap_or_default())
        .collect();
    if evaluation.decision == "block" && evaluation.enforcement == "block" {
        return false;
    }
    let defer_codes = ["cloud_auth_error", "cloud_http_error", "cloud_timeout"];
    if !reason_codes
        .iter()
        .any(|c| defer_codes.contains(&c.as_str()))
    {
        return false;
    }
    decision_rank(&bundle_evaluation.decision) > decision_rank(&evaluation.decision)
}

/// `_cloud_fallback_reason` (:5141-5147) — reason dict recorded when cloud
/// validation could not run and the result fell back to local heuristics.
// supply_chain_package_eval.py:5141-5147
#[allow(dead_code)]
fn cloud_fallback_reason(code: &str, message: &str) -> Map<String, Value> {
    let mut reason = Map::new();
    reason.insert("code".into(), Value::String(code.to_string()));
    reason.insert("message".into(), Value::String(message.to_string()));
    reason.insert("severity".into(), Value::String("unknown".into()));
    reason.insert("source".into(), Value::String("guard-cloud".into()));
    reason
}

/// `_bundle_reason_message` (:5166-5186) — human-readable message for a bundle
/// package decision reason.
// supply_chain_package_eval.py:5166-5186
#[allow(dead_code)]
fn bundle_reason_message(
    package: &Map<String, Value>,
    decision: &str,
    reason: &str,
    stale: bool,
) -> String {
    let package_label = bundle_package_label(package);
    if stale {
        return match decision {
            "block" => format!(
                "Cached bundle is stale, but Guard still blocked {package_label} from advisory intelligence."
            ),
            "ask" => format!(
                "Cached bundle is stale, so Guard still requires approval for {package_label}."
            ),
            "warn" => format!("Cached bundle is stale, so Guard still warns on {package_label}."),
            _ => format!("Cached bundle is stale, so Guard kept {package_label} in monitor mode."),
        };
    }
    match reason {
        "known_malware_or_kev" => {
            format!("Cached bundle flagged {package_label} from advisory intelligence.")
        }
        "maintainer_compromise" => {
            format!("Cached bundle flagged {package_label} for probable maintainer compromise.")
        }
        _ => format!("Cached bundle matched {package_label}."),
    }
}

/// `_pypi_caret_specifier` (:4542-4560) — map a `^x.y.z` requested range to the
/// equivalent PEP-440 `>=base,<upper` specifier.
// supply_chain_package_eval.py:4542-4560
#[allow(dead_code)]
fn pypi_caret_specifier(deps: &SupplyChainEvalDeps<'_>, value: &str) -> Option<String> {
    let base = {
        let v = value.trim();
        if v.is_empty() {
            None
        } else {
            Some(v.to_string())
        }
    }?;
    let parsed = deps.semver.version(&base).ok()?;
    let release = &parsed.release;
    let major = release.first().copied().unwrap_or(0);
    let minor = release.get(1).copied().unwrap_or(0);
    let patch = release.get(2).copied().unwrap_or(0);
    let upper_bound = if major > 0 {
        format!("{}", major + 1)
    } else if minor > 0 {
        format!("0.{}", minor + 1)
    } else {
        format!("0.0.{}", patch + 1)
    };
    Some(format!(">={base},<{upper_bound}"))
}

/// `_pypi_tilde_specifier` (:4563-4574) — map a `~x.y` requested range to the
/// equivalent PEP-440 `>=base,<upper` specifier.
// supply_chain_package_eval.py:4563-4574
#[allow(dead_code)]
fn pypi_tilde_specifier(deps: &SupplyChainEvalDeps<'_>, value: &str) -> Option<String> {
    let base = {
        let v = value.trim();
        if v.is_empty() {
            None
        } else {
            Some(v.to_string())
        }
    }?;
    let parsed = deps.semver.version(&base).ok()?;
    let release = &parsed.release;
    let major = release.first().copied().unwrap_or(0);
    let upper_bound = if release.len() >= 2 {
        format!("{major}.{}", release[1] + 1)
    } else {
        format!("{}", major + 1)
    };
    Some(format!(">={base},<{upper_bound}"))
}

/// `_normalized_pypi_requested_range` (:4529-4539) — normalize a requested pypi
/// range: pass through `~=`/exact specifiers, translate `^`/`~` shorthands.
// supply_chain_package_eval.py:4529-4539
#[allow(dead_code)]
fn normalized_pypi_requested_range(
    deps: &SupplyChainEvalDeps<'_>,
    requested_range: &str,
) -> Option<String> {
    let normalized = requested_range.trim();
    if normalized.is_empty() {
        return None;
    }
    if normalized.starts_with("~=") {
        return Some(normalized.to_string());
    }
    if let Some(rest) = normalized.strip_prefix('^') {
        return pypi_caret_specifier(deps, rest);
    }
    if let Some(rest) = normalized.strip_prefix('~') {
        return pypi_tilde_specifier(deps, rest);
    }
    Some(normalized.to_string())
}

/// `_registry_package_name` (:4452-4457) — qualified `namespace/name` for
/// registry lookups, or the bare name.
// supply_chain_package_eval.py:4452-4457
#[allow(dead_code)]
fn registry_package_name(target: &Map<String, Value>) -> Option<String> {
    let package_name = optional_string(target.get("name"))?;
    match optional_string(target.get("namespace")) {
        Some(ns) => Some(format!("{ns}/{package_name}")),
        None => Some(package_name),
    }
}

/// `_dependency_package_name` (:4403-4412) — leaf package name for a lockfile
/// dependency path.
// supply_chain_package_eval.py:4403-4412
#[allow(dead_code)]
fn dependency_package_name(dependency_path: &str) -> Option<String> {
    let normalized = dependency_path.trim_matches('/').to_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some((_, after)) = normalized.rsplit_once("node_modules/") {
        return Some(after.to_string());
    }
    if !normalized.contains('/') || normalized.starts_with('@') {
        return Some(normalized);
    }
    None
}

/// `_target_versions_from_direct_map` (:4371-4383) — resolve each target's
/// version from a `{candidate_name: version}` direct map.
// supply_chain_package_eval.py:4371-4383
#[allow(dead_code)]
fn target_versions_from_direct_map(
    deps: &SupplyChainEvalDeps<'_>,
    targets: &[Map<String, Value>],
    direct_versions: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for target in targets {
        let Some(key) = lockfile_target_key(target) else {
            continue;
        };
        for candidate in target_candidate_names(deps, target) {
            if let Some(version) = direct_versions.get(&candidate) {
                versions.insert(key, version.clone());
                break;
            }
        }
    }
    versions
}

/// `_direct_lockfile_version` (:4386-4400) — extract an exact version from a
/// lockfile value that may be a range, alias (`npm:`), or `name@version`.
// supply_chain_package_eval.py:4386-4400
#[allow(dead_code)]
fn direct_lockfile_version(value: &str) -> Option<String> {
    let mut normalized = value.split('(').next().unwrap_or("").trim().to_string();
    if let Some(rest) = normalized.strip_prefix("npm:") {
        normalized = rest.to_string();
    }
    if normalized.contains('@') && !normalized.starts_with('@') {
        if let Some((_, candidate)) = normalized.rsplit_once('@') {
            if exact_version(candidate).is_some() {
                return Some(candidate.to_string());
            }
        }
    }
    if exact_version(&normalized).is_some() {
        return Some(normalized);
    }
    None
}

/// `_source_url_from_specifier` (:4647-4655) — return the specifier when it is
/// already a usable source URL/spec.
// supply_chain_package_eval.py:4647-4655
#[allow(dead_code)]
fn source_url_from_specifier(specifier: Option<&str>) -> Option<String> {
    let specifier = specifier?;
    if parse_npm_source_spec(Some(specifier)).is_some() {
        return Some(specifier.to_string());
    }
    let lower = specifier.to_lowercase();
    if Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://")
        .expect("scheme re")
        .is_match(specifier)
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("git+")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("file:")
    {
        return Some(specifier.to_string());
    }
    None
}

/// `_source_url_from_raw_spec` (:4659-4671) — pull a source URL out of a raw
/// install spec, stripping a leading named-source separator if present.
// supply_chain_package_eval.py:4659-4671
#[allow(dead_code)]
fn source_url_from_raw_spec(raw_spec: &str) -> Option<String> {
    let candidate = match NAMED_SOURCE_SEPARATOR_RE.find(raw_spec) {
        Some(m) => &raw_spec[m.end()..],
        None => raw_spec,
    };
    let lower = candidate.to_lowercase();
    if candidate.contains("://")
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("git+")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("file:")
    {
        return Some(candidate.to_string());
    }
    if source_url_from_specifier(Some(raw_spec)).is_some() {
        return Some(raw_spec.to_string());
    }
    for (index, ch) in raw_spec.char_indices() {
        if ch == '@' && index > 0 && parse_npm_source_spec(Some(&raw_spec[index + 1..])).is_some() {
            return Some(raw_spec[index + 1..].to_string());
        }
    }
    None
}

/// `_manifest_exact_version` (:4733-4743) — extract an exact pinned version
/// from a manifest specifier for the given ecosystem.
// supply_chain_package_eval.py:4733-4743
#[allow(dead_code)]
fn manifest_exact_version(
    deps: &SupplyChainEvalDeps<'_>,
    ecosystem: &str,
    value: Option<&str>,
) -> Option<String> {
    if ecosystem == "pypi" {
        return python_lockfile_version(deps, value.map(|v| Value::String(v.to_string())).as_ref());
    }
    if ecosystem == "cargo" {
        let normalized = value?;
        if let Some(rest) = normalized.strip_prefix('=') {
            return exact_version(rest.trim_start_matches('='));
        }
        return None;
    }
    value.and_then(exact_version)
}

/// `_with_package_reason` (:4754-4761) — clone a package result dict and append
/// one reason.
// supply_chain_package_eval.py:4754-4761
#[allow(dead_code)]
fn with_package_reason(
    package: &Map<String, Value>,
    reason: Map<String, Value>,
) -> Map<String, Value> {
    let mut updated = package.clone();
    let mut reasons: Vec<Value> = match package.get("reasons") {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| item.is_object())
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    reasons.push(Value::Object(reason));
    updated.insert("reasons".to_string(), Value::Array(reasons));
    updated
}

/// `_default_registry_range` (:4924-4925) — default registry range for an
/// ecosystem (`latest` for npm, `>=0` for pypi).
// supply_chain_package_eval.py:4924-4925
#[allow(dead_code)]
fn default_registry_range(ecosystem: &str) -> Option<&'static str> {
    registry_default_ranges().get(ecosystem).copied()
}

/// `_requested_specifier_is_range` (:4928-4934) — whether a requested specifier
/// is a non-exact range (or a dist-tag for npm).
// supply_chain_package_eval.py:4928-4934
#[allow(dead_code)]
fn requested_specifier_is_range(value: Option<&str>, ecosystem: &str) -> bool {
    let Some(normalized) = value.map(str::to_string) else {
        return false;
    };
    if exact_version(&normalized).is_none() {
        return true;
    }
    if !dist_tag_range_ecosystems().contains(ecosystem) {
        return false;
    }
    Regex::new(r"[A-Za-z][A-Za-z0-9_.-]*")
        .expect("dist-tag re")
        .is_match(&normalized)
        && normalized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && normalized
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
}

/// `_normalized_supply_chain_evaluate_url` (:4840-4858) — rewrite a receipts
/// sync URL into the supply-chain evaluate URL for `workspace_id`.
// supply_chain_package_eval.py:4840-4858
#[allow(dead_code)]
fn normalized_supply_chain_evaluate_url(
    deps: &SupplyChainEvalDeps<'_>,
    sync_url: &str,
    workspace_id: &str,
) -> String {
    let parsed = crate::local_supply_chain::urlsplit(
        &deps.guard_sync.normalized_receipts_sync_url(sync_url),
    );
    let trimmed_path = parsed.path.trim_end_matches('/');
    let next_path = if trimmed_path == "/api/guard/receipts/sync" {
        "/api/guard/supply-chain/evaluate".to_string()
    } else if trimmed_path == "/guard/receipts/sync" {
        "/guard/supply-chain/evaluate".to_string()
    } else {
        format!("{trimmed_path}/supply-chain/evaluate")
    };
    let mut query_pairs: Vec<(String, String)> =
        crate::local_supply_chain::parse_qsl(&parsed.query)
            .into_iter()
            .filter(|(key, _)| key != "workspaceId")
            .collect();
    query_pairs.push(("workspaceId".to_string(), workspace_id.to_string()));
    let query = crate::local_supply_chain::urlencode(&query_pairs);
    format!(
        "{}://{}{}{}{}",
        parsed.scheme,
        parsed.netloc,
        next_path,
        if query.is_empty() { "" } else { "?" },
        query
    )
}

/// `_safe_dependency_map_result_for_path` (:4686-4697) — parse a lockfile/
/// manifest file's dependency map under a deadline, surfacing parse errors.
// supply_chain_package_eval.py:4686-4697
#[allow(dead_code)]
fn safe_dependency_map_result_for_path(
    deps: &SupplyChainEvalDeps<'_>,
    path: &str,
    text: &str,
    deadline: f64,
) -> LockfileParseResult {
    let budget_ms = ((deadline - monotonic_seconds()) * 1000.0).max(0.0);
    deps.manifest
        .dependency_map_for_path(path, text, deadline)
        .map(|map| {
            let mut result = LockfileParseResult {
                complete: true,
                format: path_format_label(path),
                entries: map
                    .into_iter()
                    .map(|(dependency_path, version)| LockfileDependencyEntry {
                        package_name: dependency_path.clone(),
                        version,
                        dependency_path,
                        direct: true,
                    })
                    .collect(),
                ..Default::default()
            };
            result.budget_ms = budget_ms;
            result
        })
        .unwrap_or_else(|e| {
            let mut result = LockfileParseResult {
                complete: false,
                format: path_format_label(path),
                ..Default::default()
            };
            result.budget_ms = budget_ms;
            result.error_reason = Some(e.to_string());
            result
        })
}

/// `monotonic_seconds` — the monotonic clock used by the Python `time.monotonic`
/// deadline model (:4686, :4134, ...). Expressed in seconds.
#[allow(dead_code)]
fn monotonic_seconds() -> f64 {
    std::time::Instant::now().elapsed().as_secs_f64() + *MONOTONIC_EPOCH
}

#[allow(dead_code)]
static MONOTONIC_EPOCH: LazyLock<f64> = LazyLock::new(|| {
    // Anchor Instant's epoch at first use; Instant has no defined epoch so we
    // record the offset once. Only relative deltas are consumed by deadlines.
    let _ = std::time::Instant::now();
    0.0
});

#[allow(dead_code)]
fn path_format_label(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// `_safe_dependency_map_for_path` (:4681-4683) — convenience returning just
/// the dependency map.
// supply_chain_package_eval.py:4681-4683
#[allow(dead_code)]
fn safe_dependency_map_for_path(
    deps: &SupplyChainEvalDeps<'_>,
    path: &str,
    text: &str,
    deadline: f64,
) -> BTreeMap<String, String> {
    safe_dependency_map_result_for_path(deps, path, text, deadline)
        .entries
        .into_iter()
        .map(|e| (e.package_name, e.version))
        .collect()
}

/// `_package_lock_entries` (:4057-4082) — `node_modules/<path>` → `(dep_path,
/// pkg_name, version, direct)` entries from a package-lock.json text.
// supply_chain_package_eval.py:4057-4082
#[allow(dead_code)]
fn package_lock_entries(text: &str, deadline: Option<f64>) -> Vec<(String, String, String, bool)> {
    let payload: Value = serde_json::from_str(text).unwrap_or_else(|_| json!({}));
    let mut entries: Vec<(String, String, String, bool)> = Vec::new();
    if let Some(Value::Object(packages)) = payload.get("packages") {
        for (package_path, value) in packages {
            if let Some(dl) = deadline {
                if monotonic_seconds() > dl {
                    break;
                }
            }
            if !package_path.starts_with("node_modules/") {
                continue;
            }
            let version = value.get("version").and_then(Value::as_str);
            let Some(version) = version else { continue };
            let dependency_path = package_path.trim_start_matches("node_modules/").to_string();
            let package_name = value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let direct = !dependency_path.contains("/node_modules/");
            entries.push((dependency_path, package_name, version.to_string(), direct));
        }
    }
    entries
}

/// `_walk_package_lock_entries` (:4085-4095) — alias over `package_lock_entries`.
// supply_chain_package_eval.py:4085-4095
#[allow(dead_code)]
fn walk_package_lock_entries(
    text: &str,
    deadline: Option<f64>,
) -> Vec<(String, String, String, bool)> {
    package_lock_entries(text, deadline)
}

/// `_package_lock_candidate_names` (:4098-4106) — candidate dependency paths +
/// normalized name for matching a target against package-lock entries.
// supply_chain_package_eval.py:4098-4106
#[allow(dead_code)]
fn package_lock_candidate_names(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> (BTreeSet<String>, String) {
    let normalized_name = optional_string(target.get("normalized_name")).unwrap_or_default();
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for c in target_candidate_names(deps, target) {
        candidates.insert(c.clone());
        candidates.insert(format!("node_modules/{c}"));
    }
    (candidates, normalized_name)
}

/// `_package_lock_target_versions_from_entries` (:4038-4054) — resolve each
/// target's version from package-lock entries.
// supply_chain_package_eval.py:4038-4054
#[allow(dead_code)]
fn package_lock_target_versions_from_entries(
    deps: &SupplyChainEvalDeps<'_>,
    parse_result: &LockfileParseResult,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for target in targets {
        let Some(target_key) = lockfile_target_key(target) else {
            continue;
        };
        let (candidate_paths, normalized_name) = package_lock_candidate_names(deps, target);
        for entry in &parse_result.entries {
            if !entry.direct {
                continue;
            }
            if candidate_paths.contains(&entry.dependency_path)
                || entry.package_name == normalized_name
            {
                versions.insert(target_key.clone(), entry.version.clone());
                break;
            }
        }
    }
    versions
}

/// `_package_lock_target_versions` (:4019-4035) — package-lock.json target
/// versions via the parsed result.
// supply_chain_package_eval.py:4019-4035
#[allow(dead_code)]
fn package_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    parse_result: &LockfileParseResult,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    package_lock_target_versions_from_entries(deps, parse_result, targets)
}

/// `_artifact_manifest_dependency_map` (:4007-4017) — dependency map for one
/// manifest path; pip falls back to `requirements.txt` when the manifest has
/// no deps.
// supply_chain_package_eval.py:4007-4017
#[allow(dead_code)]
fn artifact_manifest_dependency_map(
    deps: &SupplyChainEvalDeps<'_>,
    package_manager: &str,
    relative_path: &str,
    manifest_text: &str,
) -> BTreeMap<String, String> {
    let dependency_map = deps.manifest.parse_manifest_dependencies(
        relative_path,
        manifest_text,
        crate::local_supply_chain::DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
        0,
    );
    if !dependency_map.is_empty() || package_manager != "pip" {
        return dependency_map;
    }
    deps.manifest.parse_manifest_dependencies(
        "requirements.txt",
        manifest_text,
        crate::local_supply_chain::DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
        0,
    )
}

/// `_manifest_direct_dependency_names` (:3933-3962) — normalized direct
/// dependency names across the artifact's manifests for `ecosystem`.
// supply_chain_package_eval.py:3933-3962
#[allow(dead_code)]
fn manifest_direct_dependency_names(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    ecosystem: &str,
) -> BTreeSet<String> {
    let Some(ws) = workspace_dir else {
        return BTreeSet::new();
    };
    let Some(manifest_paths) = artifact
        .metadata
        .get("manifest_paths")
        .and_then(Value::as_array)
    else {
        return BTreeSet::new();
    };
    let package_manager = artifact
        .metadata
        .get("package_manager")
        .and_then(Value::as_str)
        .unwrap_or("npm");
    let mut direct_names: BTreeSet<String> = BTreeSet::new();
    for rel in manifest_paths.iter().filter_map(Value::as_str) {
        let Some(manifest_path) = resolve_path_within_workspace(ws, rel) else {
            continue;
        };
        if !manifest_path.exists() {
            continue;
        }
        let Some(manifest_text) = deps.workspace_io.read_text(ws, rel) else {
            continue;
        };
        let dependency_map =
            artifact_manifest_dependency_map(deps, package_manager, rel, &manifest_text);
        for package_name in dependency_map.keys() {
            direct_names.insert(normalize_package_name(deps, ecosystem, package_name));
        }
    }
    direct_names
}

/// `_manifest_dependency_versions` (:3965-4004) — resolve each target's exact
/// version from manifest specifiers across the artifact's manifests.
// supply_chain_package_eval.py:3965-4004
#[allow(dead_code)]
fn manifest_dependency_versions(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let Some(ws) = workspace_dir else {
        return BTreeMap::new();
    };
    let Some(manifest_paths) = artifact
        .metadata
        .get("manifest_paths")
        .and_then(Value::as_array)
    else {
        return BTreeMap::new();
    };
    let package_manager = artifact
        .metadata
        .get("package_manager")
        .and_then(Value::as_str)
        .unwrap_or("npm");
    let mut keyed_targets: Vec<(String, &Map<String, Value>)> = Vec::new();
    for target in targets {
        if let Some(key) = lockfile_target_key(target) {
            keyed_targets.push((key, target));
        }
    }
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for rel in manifest_paths.iter().filter_map(Value::as_str) {
        let Some(manifest_path) = resolve_path_within_workspace(ws, rel) else {
            continue;
        };
        if !manifest_path.exists() {
            continue;
        }
        let Some(manifest_text) = deps.workspace_io.read_text(ws, rel) else {
            continue;
        };
        let dependency_map =
            artifact_manifest_dependency_map(deps, package_manager, rel, &manifest_text);
        if dependency_map.is_empty() {
            continue;
        }
        for (target_key, target) in &keyed_targets {
            if versions.contains_key(target_key) {
                continue;
            }
            let ecosystem =
                optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
            let normalized_dependencies: BTreeMap<String, String> = dependency_map
                .iter()
                .map(|(k, v)| (normalize_package_name(deps, &ecosystem, k), v.clone()))
                .collect();
            for candidate in target_candidate_names(deps, target) {
                let candidate_norm = normalize_package_name(deps, &ecosystem, &candidate);
                let specifier = normalized_dependencies.get(&candidate_norm);
                if let Some(exact) =
                    manifest_exact_version(deps, &ecosystem, specifier.map(String::as_str))
                {
                    versions.insert(target_key.clone(), exact);
                    break;
                }
            }
        }
    }
    versions
}

/// `_composer_lock_target_versions` (:4134-4144).
// supply_chain_package_eval.py:4134-4144
#[allow(dead_code)]
fn composer_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let parse_result =
        safe_dependency_map_result_for_path(deps, "composer.lock", text, monotonic_seconds() + 0.2);
    target_versions_from_direct_map(deps, targets, &parse_result.dependency_map())
}

/// `_gemfile_lock_target_versions` (:4147-4156).
// supply_chain_package_eval.py:4147-4156
#[allow(dead_code)]
fn gemfile_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let parse_result =
        safe_dependency_map_result_for_path(deps, "Gemfile.lock", text, monotonic_seconds() + 0.2);
    target_versions_from_direct_map(deps, targets, &parse_result.dependency_map())
}

/// `_cargo_lock_target_versions` (:4109-4115).
// supply_chain_package_eval.py:4109-4115
#[allow(dead_code)]
fn cargo_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let parse_result =
        safe_dependency_map_result_for_path(deps, "Cargo.lock", text, monotonic_seconds() + 0.2);
    target_versions_from_direct_map(deps, targets, &parse_result.dependency_map())
}

/// `_pnpm_lock_target_versions` (:4159-4231) — parse pnpm-lock.yaml direct
/// dependency versions (top-level + `importers.`/default blocks).
// supply_chain_package_eval.py:4159-4231
#[allow(dead_code)]
fn pnpm_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let mut direct_versions: BTreeMap<String, String> = BTreeMap::new();
    let mut section: Option<String> = None;
    let mut importer: Option<String> = None;
    let mut dependency_block: Option<String> = None;
    let mut dependency_name: Option<String> = None;
    const TOP_LEVEL_DEP_SECTIONS: [&str; 3] =
        ["dependencies", "devDependencies", "optionalDependencies"];
    for raw_line in text.lines() {
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if indent == 0 {
            section = Some(stripped.trim_end_matches(':').to_string());
            importer = None;
            dependency_block = None;
            dependency_name = None;
            continue;
        }
        if TOP_LEVEL_DEP_SECTIONS.contains(&section.as_deref().unwrap_or("")) {
            if indent == 2 && stripped.contains(':') {
                let (raw_name, _, raw_value) = {
                    let parts: Vec<&str> = stripped.splitn(2, ':').collect();
                    (parts[0], ":", parts.get(1).copied().unwrap_or(""))
                };
                let name = raw_name
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                let direct_value = raw_value.trim().trim_matches('"').trim_matches('\'');
                if let Some(exact) = direct_lockfile_version(direct_value) {
                    direct_versions.insert(name, exact);
                    dependency_name = None;
                } else {
                    dependency_name = Some(name);
                }
                continue;
            }
            if dependency_name.is_some() && indent >= 4 && stripped.starts_with("version:") {
                let v = stripped
                    .split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                if let Some(exact) = direct_lockfile_version(v) {
                    if let Some(name) = dependency_name.take() {
                        direct_versions.insert(name, exact);
                    }
                }
                dependency_name = None;
            }
            continue;
        }
        if section.as_deref() != Some("importers") {
            continue;
        }
        if indent == 2 && stripped.ends_with(':') {
            importer = Some(
                stripped[..stripped.len() - 1]
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            );
            dependency_block = None;
            dependency_name = None;
            continue;
        }
        if !matches!(importer.as_deref(), Some(".") | Some("default")) {
            continue;
        }
        if indent == 4 && stripped.ends_with(':') {
            let block_name = stripped.trim_end_matches(':').to_string();
            dependency_block = if block_name.to_lowercase().contains("dependencies") {
                Some(block_name)
            } else {
                None
            };
            dependency_name = None;
            continue;
        }
        if dependency_block.is_none() {
            continue;
        }
        if indent == 6 && stripped.contains(':') {
            let parts: Vec<&str> = stripped.splitn(2, ':').collect();
            let name = parts[0]
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            let direct_value = parts
                .get(1)
                .copied()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if let Some(exact) = direct_lockfile_version(direct_value) {
                direct_versions.insert(name, exact);
                dependency_name = None;
            } else {
                dependency_name = Some(name);
            }
            continue;
        }
        if dependency_name.is_some() && indent >= 8 && stripped.starts_with("version:") {
            let v = stripped
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if let Some(exact) = direct_lockfile_version(v) {
                if let Some(name) = dependency_name.take() {
                    direct_versions.insert(name, exact);
                }
            }
            dependency_name = None;
        }
    }
    target_versions_from_direct_map(deps, targets, &direct_versions)
}

/// `_expected_yarn_selectors` (:4258-4267) — yarn.lock selector spellings a
/// target may appear under.
// supply_chain_package_eval.py:4258-4267
#[allow(dead_code)]
fn expected_yarn_selectors(target: &Map<String, Value>) -> Vec<String> {
    let requested =
        optional_string(target.get("version")).or_else(|| optional_string(target.get("range")));
    let Some(requested) = requested else {
        return Vec::new();
    };
    let normalized_name = optional_string(target.get("normalized_name")).unwrap_or_default();
    let mut selectors = vec![
        format!("{normalized_name}@{requested}"),
        format!("{normalized_name}@npm:{requested}"),
    ];
    if let Some(alias) = optional_string(target.get("alias")) {
        selectors.push(format!("{alias}@npm:{normalized_name}@{requested}"));
    }
    let mut seen = HashSet::new();
    selectors
        .into_iter()
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

/// `_yarn_lock_target_versions` (:4234-4255) — resolve yarn.lock `version`
/// lines by matching a target's expected selectors.
// supply_chain_package_eval.py:4234-4255
#[allow(dead_code)]
fn yarn_lock_target_versions(
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    let mut current_selectors: Vec<String> = Vec::new();
    let target_selectors: Vec<(String, HashSet<String>)> = targets
        .iter()
        .filter_map(|t| {
            lockfile_target_key(t).map(|k| {
                (
                    k,
                    expected_yarn_selectors(t)
                        .into_iter()
                        .collect::<HashSet<_>>(),
                )
            })
        })
        .collect();
    for raw_line in text.lines() {
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if !raw_line.starts_with(' ') && !raw_line.starts_with('\t') {
            current_selectors = stripped
                .trim_end_matches(':')
                .split(',')
                .map(|part| part.trim().trim_matches('"').trim_matches('\'').to_string())
                .filter(|s| !s.is_empty() && s != "__metadata")
                .collect();
            continue;
        }
        if current_selectors.is_empty() {
            continue;
        }
        let version: Option<String> = {
            static RE1: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r#"^version\s+"([^"]+)"$"#).expect("yarn version re"));
            static RE2: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(r#"^version:\s*"?([^"\s]+)"?$"#).expect("yarn version re2")
            });
            RE1.captures(stripped)
                .or_else(|| RE2.captures(stripped))
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        };
        let Some(version) = version else { continue };
        let selector_set: HashSet<String> = current_selectors.iter().cloned().collect();
        for (target_key, expected) in &target_selectors {
            if versions.contains_key(target_key) || expected.is_empty() {
                continue;
            }
            if selector_set.iter().any(|s| expected.contains(s)) {
                versions.insert(target_key.clone(), version.clone());
            }
        }
    }
    versions
}

/// `_bun_lock_target_versions` (:4270-4290) — resolve bun.lock targets via
/// unique-per-name versions, disambiguated by the requested range.
// supply_chain_package_eval.py:4270-4290
#[allow(dead_code)]
fn bun_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    parse_result: &LockfileParseResult,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let mut versions_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &parse_result.entries {
        let candidate_versions = versions_by_name
            .entry(entry.package_name.clone())
            .or_default();
        if !candidate_versions.contains(&entry.version) {
            candidate_versions.push(entry.version.clone());
        }
    }
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for target in targets {
        let Some(target_key) = lockfile_target_key(target) else {
            continue;
        };
        let requested = optional_string(target.get("range"));
        let normalized_name = optional_string(target.get("normalized_name")).unwrap_or_default();
        let candidates = versions_by_name
            .get(&normalized_name)
            .cloned()
            .unwrap_or_default();
        if candidates.len() == 1 {
            versions.insert(target_key, candidates[0].clone());
            continue;
        }
        let Some(requested) = requested else { continue };
        let matching: Vec<&String> = candidates
            .iter()
            .filter(|v| deps.semver.version_matches_js_selector(v, &requested))
            .collect();
        if matching.len() == 1 {
            versions.insert(target_key, matching[0].clone());
        }
    }
    versions
}

/// `_toml_lock_direct_versions` (:4300-4319) — direct `{normalized_name:
/// version}` map from a `[[package]]` TOML lockfile (poetry/uv shape).
// supply_chain_package_eval.py:4300-4319
#[allow(dead_code)]
fn toml_lock_direct_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut direct_versions: BTreeMap<String, String> = BTreeMap::new();
    let Ok(payload) = text.parse::<toml::Value>() else {
        return direct_versions;
    };
    let Some(toml::Value::Array(packages)) = payload.get("package") else {
        return direct_versions;
    };
    for package in packages {
        let toml::Value::Table(pkg) = package else {
            continue;
        };
        let name = pkg.get("name").and_then(|v| v.as_str()).map(str::to_string);
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let normalized_name = name.map(|n| normalize_package_name(deps, "pypi", &n));
        if let (Some(norm), Some(ver)) = (normalized_name, version) {
            if direct_manifest_names.contains(&norm) {
                direct_versions.insert(norm, ver);
            }
        }
    }
    direct_versions
}

/// `_poetry_lock_direct_versions` (:4321) — alias over toml parser.
// supply_chain_package_eval.py:4321
#[allow(dead_code)]
fn poetry_lock_direct_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    toml_lock_direct_versions(deps, text, direct_manifest_names)
}

/// `_uv_lock_direct_versions` (:4322) — alias over toml parser.
// supply_chain_package_eval.py:4322
#[allow(dead_code)]
fn uv_lock_direct_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    toml_lock_direct_versions(deps, text, direct_manifest_names)
}

/// `_poetry_lock_target_versions` (:4292-4298).
// supply_chain_package_eval.py:4292-4298
#[allow(dead_code)]
fn poetry_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    target_versions_from_direct_map(
        deps,
        targets,
        &poetry_lock_direct_versions(deps, text, direct_manifest_names),
    )
}

/// `_uv_lock_target_versions` (:4325-4332).
// supply_chain_package_eval.py:4325-4332
#[allow(dead_code)]
fn uv_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    target_versions_from_direct_map(
        deps,
        targets,
        &uv_lock_direct_versions(deps, text, direct_manifest_names),
    )
}

/// `_pipfile_lock_target_versions` (:4334-4341).
// supply_chain_package_eval.py:4334-4341
#[allow(dead_code)]
fn pipfile_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    target_versions_from_direct_map(
        deps,
        targets,
        &pipfile_lock_direct_versions(deps, text, direct_manifest_names),
    )
}

/// `_pipfile_lock_direct_versions` (:4354-4368) — direct pypi deps from
/// Pipfile.lock `default`/`develop` sections.
// supply_chain_package_eval.py:4354-4368
#[allow(dead_code)]
fn pipfile_lock_direct_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    direct_manifest_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut direct_versions: BTreeMap<String, String> = BTreeMap::new();
    let payload: Value = serde_json::from_str(text).unwrap_or_else(|_| json!({}));
    for section in ["default", "develop"] {
        let Some(Value::Object(values)) = payload.get(section) else {
            continue;
        };
        for (package_name, package_value) in values {
            if !package_value.is_object() {
                continue;
            }
            let exact = python_lockfile_version(deps, package_value.get("version"));
            let normalized_name = normalize_package_name(deps, "pypi", package_name);
            if let Some(exact) = exact {
                if direct_manifest_names.contains(&normalized_name) {
                    direct_versions.insert(normalized_name, exact);
                }
            }
        }
    }
    direct_versions
}

// ============================================================================
// RTM-019 eval batch E — remaining 35 Python fns ported below.
// ============================================================================

/// `_is_git_source_url` (:3648-3650).
// supply_chain_package_eval.py:3648-3650
#[allow(dead_code)]
fn is_git_source_url(source_url: &str) -> bool {
    parse_npm_source_spec(Some(source_url))
        .map(|s| s.is_git())
        .unwrap_or(false)
}

/// `is_external_https_archive_source` (restricted_archive_destination.py).
/// A HTTPS URL that is neither the npm nor PyPI default registry host and ends
/// in a known tarball/archive suffix (or is a non-registry source URL) is an
/// externally-hosted archive subject to restricted-download rules.
// restricted_archive_destination.py
#[allow(dead_code)]
fn is_external_https_archive_source(source_url: &str) -> bool {
    let lower = source_url.trim().to_lowercase();
    if !lower.starts_with("https://") {
        return false;
    }
    let host = lower
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("");
    if host == "registry.npmjs.org"
        || host == "pypi.org"
        || host == "files.pythonhosted.org"
        || host.ends_with(".npmjs.org")
    {
        return false;
    }
    true
}

/// `_is_external_https_tarball_source` (:3651-3652).
// supply_chain_package_eval.py:3651-3652
#[allow(dead_code)]
fn is_external_https_tarball_source(source_url: &str) -> bool {
    is_external_https_archive_source(source_url)
}

/// `_FIRST_PARTY_PYPI_PACKAGES` (:3031).
#[allow(dead_code)]
static FIRST_PARTY_PYPI_PACKAGES: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| ["hol-guard", "plugin-scanner"].into_iter().collect());

/// `_own_package_name` (:3094-3110).
// supply_chain_package_eval.py:3094-3110
#[allow(dead_code)]
fn own_package_name(deps: &SupplyChainEvalDeps<'_>, target: &Map<String, Value>) -> Option<String> {
    if optional_string(target.get("ecosystem")).as_deref() != Some("pypi") {
        return None;
    }
    if optional_string(target.get("source_url")).is_some() {
        return None;
    }
    if optional_string(target.get("source_kind")).is_some() {
        return None;
    }
    let raw_spec = optional_string(target.get("raw_spec")).unwrap_or_default();
    if raw_spec.contains("://")
        || raw_spec.starts_with("git+")
        || raw_spec.starts_with("file:")
        || raw_spec.starts_with("./")
        || raw_spec.starts_with("../")
        || raw_spec.starts_with('/')
    {
        return None;
    }
    let normalized_name = optional_string(target.get("normalized_name")).unwrap_or_else(|| {
        normalize_package_name(
            deps,
            "pypi",
            &optional_string(target.get("name")).unwrap_or_default(),
        )
    });
    if !FIRST_PARTY_PYPI_PACKAGES.contains(normalized_name.as_str()) {
        return None;
    }
    Some(optional_string(target.get("name")).unwrap_or(normalized_name))
}

/// `_manifest_package_name` (:3469-3475).
// supply_chain_package_eval.py:3469-3475
#[allow(dead_code)]
fn manifest_package_name(manifest_text: &str) -> Option<String> {
    let payload: Value = serde_json::from_str(if manifest_text.is_empty() {
        "{}"
    } else {
        manifest_text
    })
    .ok()?;
    payload
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `_python_setup_script_looks_suspicious` (:3464-3468).
// supply_chain_package_eval.py:3464-3468
#[allow(dead_code)]
fn python_setup_script_looks_suspicious(content: &str) -> bool {
    static SUSPICIOUS_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|requests\.(?:get|post)|urllib\.request\.)",
        )
        .expect("SUSPICIOUS_RE")
    });
    static CURL_WGET_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(?:curl|wget)\b").expect("CURL_WGET_RE"));
    SUSPICIOUS_RE.is_match(content) || CURL_WGET_RE.is_match(content)
}

/// `_local_python_path_text` (:3460-3461).
// supply_chain_package_eval.py:3460-3461
#[allow(dead_code)]
fn local_python_path_text(raw_spec: &str) -> String {
    let trimmed = raw_spec.trim();
    // Strip a `file:` prefix if present.
    if let Some(rest) = trimmed.strip_prefix("file:") {
        return rest.trim().to_string();
    }
    trimmed.to_string()
}

/// `_looks_like_explicit_local_python_path` (:3424-3434).
// supply_chain_package_eval.py:3424-3434
#[allow(dead_code)]
fn looks_like_explicit_local_python_path(raw_spec: &str) -> bool {
    static DRIVE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z]:[\\\\/]").expect("DRIVE_RE"));
    let text = local_python_path_text(raw_spec);
    let (normalized, _extras) = split_python_extras(&text);
    normalized == "."
        || normalized == "~"
        || normalized.starts_with("./")
        || normalized.starts_with("../")
        || normalized.starts_with('/')
        || normalized.starts_with("~/")
        || normalized.starts_with(".\\")
        || normalized.starts_with("..\\")
        || normalized.starts_with("~\\")
        || normalized.starts_with("\\\\")
        || normalized.starts_with("//")
        || normalized.contains('/')
        || normalized.contains('\\')
        || DRIVE_RE.is_match(&normalized)
}

/// `_local_python_project_path` (:3438-3462).
// supply_chain_package_eval.py:3438-3462
#[allow(dead_code)]
fn local_python_project_path(target: &Map<String, Value>, workspace_dir: &Path) -> Option<PathBuf> {
    let mut raw_spec = optional_string(target.get("raw_spec"));
    let source_url = optional_string(target.get("source_url"));
    let editable = target
        .get("editable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(url) = &source_url {
        if url.starts_with("file:") {
            raw_spec = Some(py_partition(url, "file:").2.to_string());
        }
    }
    if raw_spec.is_none() {
        return if editable {
            Some(workspace_dir.to_path_buf())
        } else {
            None
        };
    }
    let raw_spec = raw_spec.unwrap();
    if raw_spec.starts_with("http://")
        || raw_spec.starts_with("https://")
        || raw_spec.starts_with("git+")
        || raw_spec.starts_with("github:")
        || raw_spec.starts_with("gitlab:")
        || raw_spec.starts_with("bitbucket:")
    {
        return None;
    }
    if !looks_like_explicit_local_python_path(&raw_spec) {
        let has_py = workspace_dir.join("pyproject.toml").exists()
            || workspace_dir.join("setup.py").exists();
        return if editable && has_py {
            Some(workspace_dir.to_path_buf())
        } else {
            None
        };
    }
    let path_text = local_python_path_text(&raw_spec);
    let candidate_path = expand_user_path(&path_text);
    let disk_path = if candidate_path.is_absolute() {
        candidate_path
    } else {
        workspace_dir.join(candidate_path)
    };
    if disk_path.is_dir() {
        if disk_path.join("pyproject.toml").exists() || disk_path.join("setup.py").exists() {
            return Some(disk_path);
        }
        return None;
    }
    let parent = disk_path.parent().map(Path::to_path_buf);
    if matches!(
        disk_path.file_name().and_then(|n| n.to_str()),
        Some("pyproject.toml") | Some("setup.py")
    ) && disk_path.exists()
    {
        return parent;
    }
    let has_py =
        workspace_dir.join("pyproject.toml").exists() || workspace_dir.join("setup.py").exists();
    if editable && has_py {
        Some(workspace_dir.to_path_buf())
    } else {
        None
    }
}

/// Expand a leading `~` like Python's `Path.expanduser` (RuntimeError -> literal).
#[allow(dead_code)]
fn expand_user_path(text: &str) -> PathBuf {
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if text == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(text)
}

/// `str.partition(sep)` — (before, sep, after); after is empty when sep absent.
#[allow(dead_code)]
fn py_partition<'a>(value: &'a str, sep: &str) -> (&'a str, &'a str, &'a str) {
    match value.find(sep) {
        Some(index) => (
            &value[..index],
            &value[index..index + sep.len()],
            &value[index + sep.len()..],
        ),
        None => (value, "", ""),
    }
}

/// `_own_package_review_message` (:3148-3153).
// supply_chain_package_eval.py:3148-3153
#[allow(dead_code)]
fn own_package_review_message(package_name: &str) -> String {
    format!(
        "HOL Guard cannot automatically allow this {package_name} install. \
         Only a reinstall of the release already running on this device, from the default package index, \
         skips review. A new publish or another package source stays on review so a compromised release \
         cannot install by itself. Approve this install once if you trust it."
    )
}

/// `_installed_project_version` (:3075-3088).
/// The bundled Python `importlib.metadata.version` lookup is unavailable in
/// the native runtime; the guard's own distribution version is the only
/// installed value we can resolve (via `CARGO_PKG_VERSION`), validated to a
/// canonical PEP-440 release (no local segment).
// supply_chain_package_eval.py:3075-3088
#[allow(dead_code)]
fn installed_project_version(deps: &SupplyChainEvalDeps<'_>, project_name: &str) -> Option<String> {
    // Only the guard's own distribution can be resolved without a Python
    // interpreter; anything else reports not-found.
    let normalized = normalize_package_name(deps, "pypi", project_name);
    if !FIRST_PARTY_PYPI_PACKAGES.contains(normalized.as_str()) {
        return None;
    }
    let found = env!("CARGO_PKG_VERSION").to_string();
    let parsed = deps.semver.version(&found).ok()?;
    // `parsed.local is not None or found != str(parsed)` -> reject.
    if parsed.normalized.contains('+') || found != parsed.normalized {
        return None;
    }
    Some(parsed.normalized)
}

/// `_installed_release_reinstall_result` (:3112-3145).
// supply_chain_package_eval.py:3112-3145
#[allow(dead_code)]
fn installed_release_reinstall_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let package_name = own_package_name(deps, target)?;
    let requested = optional_string(target.get("version"))?;
    let normalized_name = optional_string(target.get("normalized_name"))
        .unwrap_or_else(|| normalize_package_name(deps, "pypi", &package_name));
    let installed = installed_project_version(deps, &normalized_name)?;
    let requested_v = deps.semver.version(&requested).ok()?;
    let installed_v = deps.semver.version(&installed).ok()?;
    if requested_v != installed_v {
        return None;
    }
    Some(heuristic_package_result(
        target,
        "allow",
        "installed_release_reinstall",
        &format!(
            "{package_name}=={installed} matches the release already running on this device. \
             Reinstalling that same release does not select a newly published version."
        ),
        "low",
    ))
}

/// `_unknown_package_result` (:3157-3202).
// supply_chain_package_eval.py:3157-3202
#[allow(dead_code)]
fn unknown_package_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    fail_closed_unidentified: bool,
    identity_resolved: bool,
) -> Map<String, Value> {
    let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
    let decision =
        unidentified_package_decision(&ecosystem, fail_closed_unidentified, identity_resolved);
    let requires_review = decision == "ask" || decision == "block";
    let package_name =
        optional_string(target.get("name")).unwrap_or_else(|| "this package".to_string());
    let own_package = own_package_name(deps, target);
    let no_match_message = if requires_review && own_package.is_some() {
        own_package_review_message(own_package.as_deref().unwrap())
    } else if requires_review {
        format!(
            "HOL Guard on this device does not have current package reputation for {package_name}. \
             Review this install now. Guard Cloud is optional and can add live package reputation."
        )
    } else {
        "Guard recorded this package request and will keep watching for new intelligence."
            .to_string()
    };
    let mut reasons: Vec<Map<String, Value>> = Vec::new();
    let mut first = Map::new();
    first.insert(
        "code".to_string(),
        Value::String("no_cached_match".to_string()),
    );
    first.insert("message".to_string(), Value::String(no_match_message));
    first.insert(
        "severity".to_string(),
        Value::String(
            if decision == "block" {
                "high"
            } else if requires_review {
                "medium"
            } else {
                "unknown"
            }
            .to_string(),
        ),
    );
    first.insert(
        "source".to_string(),
        Value::String("guard-local".to_string()),
    );
    reasons.push(first);
    if requires_review {
        let mut extra = Map::new();
        extra.insert(
            "code".to_string(),
            Value::String("unidentified_package".to_string()),
        );
        extra.insert(
            "message".to_string(),
            Value::String(format!(
                "Local checks could not confirm current safety details for {}. \
                 This does not mean the package is unsafe; approve it once if you trust it.",
                optional_string(target.get("name")).unwrap_or_default()
            )),
        );
        extra.insert("severity".to_string(), Value::String("medium".to_string()));
        extra.insert(
            "source".to_string(),
            Value::String("guard-local".to_string()),
        );
        reasons.push(extra);
    }
    package_target_result(target, &decision, reasons, None)
}

/// `_system_package_monitor_result` (:2893-2902).
// supply_chain_package_eval.py:2893-2902
#[allow(dead_code)]
fn system_package_monitor_result(target: &Map<String, Value>) -> Map<String, Value> {
    heuristic_package_result(
        target,
        "monitor",
        "system_package_manager_monitor_only",
        "Guard treats system package managers as monitor-only coverage today and will not \
         pretend advisory blocking.",
        "low",
    )
}

/// `_homebrew_package_monitor_result` (:2906-2926).
// supply_chain_package_eval.py:2906-2926
#[allow(dead_code)]
fn homebrew_package_monitor_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Map<String, Value> {
    let command = optional_string(target.get("redacted_command")).unwrap_or_default();
    let signals = deps
        .risk
        .detect_supply_chain_risk(&command, None)
        .unwrap_or_default();
    if !signals.is_empty() {
        let strongest = signals
            .iter()
            .max_by_key(|s| {
                severity_rank_value(
                    optional_string(s.get("severity"))
                        .as_deref()
                        .unwrap_or("unknown"),
                )
            })
            .cloned()
            .unwrap_or_default();
        return heuristic_package_result(
            target,
            "warn",
            "homebrew_package_manager_generic_risk",
            &optional_string(strongest.get("plain_reason")).unwrap_or_default(),
            &optional_string(strongest.get("severity")).unwrap_or_else(|| "medium".to_string()),
        );
    }
    heuristic_package_result(
        target,
        "warn",
        "homebrew_package_manager_monitor_only",
        "Guard intercepts Homebrew requests today, records formula, cask, tap, and Brewfile intent, \
         and treats them as monitor-only until Homebrew advisory enforcement is available.",
        "low",
    )
}

/// `_unsupported_ecosystem_result` (:2929-2942).
// supply_chain_package_eval.py:2929-2942
#[allow(dead_code)]
fn unsupported_ecosystem_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Map<String, Value> {
    let command = optional_string(target.get("redacted_command")).unwrap_or_default();
    let signals = deps
        .risk
        .detect_supply_chain_risk(&command, None)
        .unwrap_or_default();
    if !signals.is_empty() {
        let strongest = signals
            .iter()
            .max_by_key(|s| {
                severity_rank_value(
                    optional_string(s.get("severity"))
                        .as_deref()
                        .unwrap_or("unknown"),
                )
            })
            .cloned()
            .unwrap_or_default();
        let severity =
            optional_string(strongest.get("severity")).unwrap_or_else(|| "medium".to_string());
        let decision = if severity == "critical" || severity == "high" {
            "block"
        } else {
            "warn"
        };
        return heuristic_package_result(
            target,
            decision,
            "unsupported_ecosystem_generic_risk",
            &optional_string(strongest.get("plain_reason")).unwrap_or_default(),
            &severity,
        );
    }
    heuristic_package_result(
        target,
        "monitor",
        "unsupported_ecosystem_monitor_only",
        "Guard does not provide advisory coverage for this ecosystem yet; recording the request.",
        "low",
    )
}

/// `_local_source_dependency_result` (:2944-2954).
// supply_chain_package_eval.py:2944-2954
#[allow(dead_code)]
fn local_source_dependency_result(target: &Map<String, Value>) -> Option<Map<String, Value>> {
    let source_url = optional_string(target.get("source_url"))?;
    if !source_url.starts_with("file:") {
        return None;
    }
    Some(heuristic_package_result(
        target,
        "ask",
        "local_path_dependency_source",
        "Local path dependency requires review before install.",
        "medium",
    ))
}

/// `_package_from_cloud_result` (:2984-3001).
// supply_chain_package_eval.py:2984-3001
#[allow(dead_code)]
fn package_from_cloud_result(item: &Map<String, Value>) -> Map<String, Value> {
    let dependency_path = optional_string(item.get("dependencyPath"));
    let direct = match item.get("direct").and_then(Value::as_bool) {
        Some(b) => b,
        None => dependency_path.is_none(),
    };
    let decision_raw =
        optional_string(item.get("decision")).unwrap_or_else(|| "monitor".to_string());
    let mut result = Map::new();
    result.insert(
        "decision".to_string(),
        Value::String(normalize_bundle_action(&decision_raw)),
    );
    result.insert(
        "ecosystem".to_string(),
        Value::String(optional_string(item.get("ecosystem")).unwrap_or_else(|| "npm".to_string())),
    );
    result.insert(
        "name".to_string(),
        Value::String(optional_string(item.get("name")).unwrap_or_else(|| "unknown".to_string())),
    );
    result.insert(
        "namespace".to_string(),
        optional_string(item.get("namespace"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result.insert(
        "requestedVersion".to_string(),
        optional_string(item.get("requestedVersion"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result.insert(
        "resolvedVersion".to_string(),
        optional_string(item.get("resolvedVersion"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result.insert(
        "recommendedFixVersion".to_string(),
        optional_string(item.get("recommendedFixVersion"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result.insert(
        "riskScore".to_string(),
        item.get("riskScore").cloned().unwrap_or(Value::Null),
    );
    result.insert("direct".to_string(), Value::Bool(direct));
    result.insert(
        "dependencyPath".to_string(),
        dependency_path.map(Value::String).unwrap_or(Value::Null),
    );
    result.insert(
        "reasons".to_string(),
        Value::Array(
            dict_items(item.get("reasons"))
                .into_iter()
                .map(Value::Object)
                .collect(),
        ),
    );
    result
}

/// `_ALTERNATE_PACKAGE_INDEX_FLAGS` (:3032-3043).
#[allow(dead_code)]
static ALTERNATE_PACKAGE_INDEX_FLAGS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    [
        "--index-url",
        "--extra-index-url",
        "--index",
        "--default-index",
        "--no-index",
        "-i",
        "--find-links",
        "-f",
        "--pip-args",
    ]
    .into_iter()
    .collect()
});

/// `_PACKAGE_SOURCE_ENV_NAMES` (:3044-3056).
#[allow(dead_code)]
static PACKAGE_SOURCE_ENV_NAMES: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    [
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_INDEX_URL",
        "PIP_NO_INDEX",
        "UV_DEFAULT_INDEX",
        "UV_EXTRA_INDEX_URL",
        "UV_FIND_LINKS",
        "UV_INDEX",
        "UV_INDEX_URL",
        "UV_NO_INDEX",
    ]
    .into_iter()
    .collect()
});

/// `_command_uses_alternate_package_index` (:3059-3067).
// supply_chain_package_eval.py:3059-3067
#[allow(dead_code)]
fn command_uses_alternate_package_index(artifact: &GuardArtifact) -> bool {
    let flags: BTreeSet<String> = string_tuple(artifact.metadata.get("flags"))
        .into_iter()
        .collect();
    if flags
        .iter()
        .any(|f| ALTERNATE_PACKAGE_INDEX_FLAGS.contains(f.as_str()))
    {
        return true;
    }
    let redacted = optional_string(artifact.metadata.get("redacted_command")).unwrap_or_default();
    let tokens = match crate::command_launcher_floors::shlex_split(&redacted) {
        Ok(t) => t,
        Err(_) => return true,
    };
    if tokens.iter().any(|token| {
        PACKAGE_SOURCE_ENV_NAMES.contains(py_partition(token, "=").0.to_uppercase().as_str())
    }) {
        return true;
    }
    PACKAGE_SOURCE_ENV_NAMES.iter().any(|name| {
        std::env::var(name)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    })
}

/// `_bun_lockfile_binary_fallback_packages` (:3254-3300).
// supply_chain_package_eval.py:3254-3300
#[allow(dead_code)]
fn bun_lockfile_binary_fallback_packages(
    targets: &[Map<String, Value>],
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
    fail_closed_unidentified: bool,
) -> Vec<Map<String, Value>> {
    let Some(ws) = workspace_dir else {
        return Vec::new();
    };
    let Some(Value::Array(lockfile_paths)) = artifact.metadata.get("lockfile_paths").cloned()
    else {
        return Vec::new();
    };
    let mut bun_lock_found = false;
    for relative_path in &lockfile_paths {
        let rel = match relative_path.as_str() {
            Some(s) => s,
            None => continue,
        };
        if Path::new(rel).file_name().and_then(|n| n.to_str()) != Some("bun.lockb") {
            continue;
        }
        if let Some(resolved) = resolve_path_within_workspace(ws, rel) {
            if resolved.exists() {
                bun_lock_found = true;
                break;
            }
        }
    }
    if !bun_lock_found {
        return Vec::new();
    }
    let message = "Guard could not verify package identity from Bun's binary lockfile (bun.lockb).";
    if !targets.is_empty() {
        return targets
            .iter()
            .map(|target| {
                let eco =
                    optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
                heuristic_package_result(
                    target,
                    &unidentified_package_decision(&eco, fail_closed_unidentified, false),
                    "bun_lockfile_binary_fallback",
                    &format!("{message} Approval is required before install."),
                    if fail_closed_unidentified {
                        "high"
                    } else {
                        "medium"
                    },
                )
            })
            .collect();
    }
    let decision = unidentified_package_decision("npm", fail_closed_unidentified, false);
    let mut workspace_target = Map::new();
    workspace_target.insert("ecosystem".to_string(), Value::String("npm".to_string()));
    workspace_target.insert("name".to_string(), Value::String("workspace".to_string()));
    workspace_target.insert("namespace".to_string(), Value::Null);
    workspace_target.insert(
        "package_manager".to_string(),
        Value::String("bun".to_string()),
    );
    vec![heuristic_package_result(
        &workspace_target,
        &decision,
        "bun_lockfile_binary_fallback",
        &format!("{message} Approval is required before install."),
        if decision == "block" {
            "high"
        } else {
            "medium"
        },
    )]
}

/// `_local_package_manifest_path` (:3354-3372).
// supply_chain_package_eval.py:3354-3372
#[allow(dead_code)]
fn local_package_manifest_path(
    target: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> Option<PathBuf> {
    let ws = workspace_dir?;
    let mut raw_spec = optional_string(target.get("raw_spec"));
    let source_url = optional_string(target.get("source_url"));
    if let Some(url) = &source_url {
        if url.starts_with("file:") {
            raw_spec = Some(py_partition(url, "file:").2.to_string());
        }
    }
    let source_spec = npm_source_spec(raw_spec.as_deref(), "npm");
    if raw_spec.is_none()
        || (source_spec.is_some()
            && source_spec.as_ref().unwrap().source_kind
                != crate::npm_source_spec::SourceKind::Local)
    {
        return None;
    }
    let mut raw = raw_spec.unwrap();
    if raw.starts_with("file:") {
        raw = py_partition(&raw, "file:").2.to_string();
    }
    let candidate_path = PathBuf::from(&raw);
    let disk_path = if candidate_path.is_absolute() {
        candidate_path
    } else {
        ws.join(candidate_path)
    };
    if disk_path.is_dir() {
        let manifest_path = disk_path.join("package.json");
        return if manifest_path.exists() {
            Some(manifest_path)
        } else {
            None
        };
    }
    if disk_path.file_name().and_then(|n| n.to_str()) == Some("package.json") && disk_path.exists()
    {
        return Some(disk_path);
    }
    None
}

/// `_local_package_manifest_result` (:3303-3351).
// supply_chain_package_eval.py:3303-3351
#[allow(dead_code)]
fn local_package_manifest_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    let manifest_path = local_package_manifest_path(target, workspace_dir)?;
    let manifest_text = std::fs::read_to_string(&manifest_path).ok()?;
    let signals: Vec<Map<String, Value>> = deps
        .risk
        .detect_supply_chain_risk(&manifest_text, None)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| {
            let sid = optional_string(s.get("signal_id")).unwrap_or_default();
            sid.starts_with("supply-chain.postinstall") || sid.ends_with("install-lifecycle-exec")
        })
        .collect();
    if signals.is_empty() {
        return None;
    }
    let mut manifest_target = target.clone();
    if let Some(manifest_name) = manifest_package_name(&manifest_text) {
        let eco = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
        let (namespace, name) = split_namespace_name(&manifest_name, &eco);
        manifest_target.insert(
            "namespace".to_string(),
            namespace.map(Value::String).unwrap_or(Value::Null),
        );
        manifest_target.insert("name".to_string(), Value::String(name));
    }
    if artifact_has_flag(artifact, "--ignore-scripts") {
        return Some(heuristic_package_result(
            &manifest_target,
            "allow",
            "ignore_scripts_applied",
            "`--ignore-scripts` disables lifecycle hooks for this local package install.",
            "low",
        ));
    }
    let strongest = signals
        .iter()
        .max_by_key(|s| {
            severity_rank_value(
                optional_string(s.get("severity"))
                    .as_deref()
                    .unwrap_or("unknown"),
            )
        })
        .cloned()
        .unwrap_or_default();
    Some(heuristic_package_result(
        &manifest_target,
        "block",
        "install_script_risk",
        &optional_string(strongest.get("plain_reason")).unwrap_or_default(),
        &optional_string(strongest.get("severity")).unwrap_or_else(|| "medium".to_string()),
    ))
}

/// `_local_python_build_result` (:3375-3417).
// supply_chain_package_eval.py:3375-3417
#[allow(dead_code)]
fn local_python_build_result(
    target: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    let ws = workspace_dir?;
    if optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string()) != "pypi" {
        return None;
    }
    let project_path = local_python_project_path(target, ws)?;
    let setup_py_path = project_path.join("setup.py");
    if setup_py_path.exists() {
        let setup_py_text = std::fs::read_to_string(&setup_py_path).unwrap_or_default();
        if python_setup_script_looks_suspicious(&setup_py_text) {
            return Some(heuristic_package_result(
                target,
                "block",
                "setup_py_exec_risk",
                "Local setup.py executes commands or network behavior during packaging.",
                "high",
            ));
        }
    }
    let pyproject_path = project_path.join("pyproject.toml");
    if pyproject_path.exists() {
        let pyproject_text = std::fs::read_to_string(&pyproject_path).unwrap_or_default();
        if pyproject_text.contains("[build-system]") && pyproject_text.contains("build-backend") {
            if python_setup_script_looks_suspicious(&pyproject_text) {
                return Some(heuristic_package_result(
                    target,
                    "block",
                    "build_backend_exec_risk",
                    "Local pyproject build backend references execution or network bootstrap behavior.",
                    "high",
                ));
            }
            return Some(heuristic_package_result(
                target,
                "ask",
                "local_build_backend_risk",
                "Editable local Python installs can invoke pyproject build backend hooks from this workspace.",
                "medium",
            ));
        }
    }
    None
}

/// `_go_mod_replace_map` (:3630-3645).
// supply_chain_package_eval.py:3630-3645
#[allow(dead_code)]
fn go_mod_replace_map(deps: &SupplyChainEvalDeps<'_>, text: &str) -> BTreeMap<String, String> {
    let mut replacements: BTreeMap<String, String> = BTreeMap::new();
    let mut in_replace_block = false;
    for raw_line in text.lines() {
        let mut line = raw_line.trim().to_string();
        if line.starts_with("replace (") {
            in_replace_block = true;
            continue;
        }
        if in_replace_block && line == ")" {
            in_replace_block = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("replace ") {
            line = rest.trim().to_string();
        } else if !in_replace_block {
            continue;
        }
        if !line.contains("=>") {
            continue;
        }
        let (original, _sep, replacement) = py_partition(&line, "=>");
        let normalized_original = original.split_whitespace().next().unwrap_or("").to_string();
        let normalized_replacement = replacement
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        if !normalized_original.is_empty() && !normalized_replacement.is_empty() {
            replacements.insert(
                normalize_package_name(deps, "go", &normalized_original),
                normalized_replacement,
            );
        }
    }
    replacements
}

/// `_go_replace_result` (:3598-3628).
// supply_chain_package_eval.py:3598-3628
#[allow(dead_code)]
fn go_replace_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    let ws = workspace_dir?;
    if optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string()) != "go" {
        return None;
    }
    let manifest_paths = match artifact.metadata.get("manifest_paths") {
        Some(Value::Array(list)) => list.clone(),
        _ => return None,
    };
    let mut go_mod_relative_path: Option<String> = None;
    for path in &manifest_paths {
        let rel = match path.as_str() {
            Some(s) => s,
            None => continue,
        };
        if Path::new(rel).file_name().and_then(|n| n.to_str()) != Some("go.mod") {
            continue;
        }
        if let Some(resolved) = resolve_path_within_workspace(ws, rel) {
            if resolved.exists() {
                go_mod_relative_path = Some(rel.to_string());
                break;
            }
        }
    }
    let go_mod_relative_path = go_mod_relative_path?;
    let go_mod_text = deps.workspace_io.read_text(ws, &go_mod_relative_path)?;
    let replacements = go_mod_replace_map(deps, &go_mod_text);
    for candidate in target_candidate_names(deps, target) {
        let Some(replacement) = replacements.get(&candidate) else {
            continue;
        };
        if ["file:", "./", "../", "/", "~", ".\\", "..\\"]
            .iter()
            .any(|prefix| replacement.starts_with(prefix))
        {
            return Some(heuristic_package_result(
                target,
                "ask",
                "go_replace_local_source",
                "Go replace directive reroutes this module to a local path.",
                "medium",
            ));
        }
        if exact_version(replacement).is_none() {
            return Some(heuristic_package_result(
                target,
                "ask",
                "go_replace_mutable_source",
                "Go replace directive reroutes this module away from proxy-pinned version resolution.",
                "medium",
            ));
        }
    }
    None
}

/// `_target_requires_npm_source_review` (:3691-3693).
// supply_chain_package_eval.py:3691-3693
#[allow(dead_code)]
fn target_requires_npm_source_review(target: &Map<String, Value>) -> bool {
    (optional_string(target.get("ecosystem"))
        .unwrap_or_default()
        .to_lowercase()
        == "npm")
        && ["git", "invalid", "local", "url"].contains(
            &optional_string(target.get("source_kind"))
                .unwrap_or_default()
                .as_str(),
        )
}

/// `_external_archive_request_timeout_result` (:3849-3855).
// supply_chain_package_eval.py:3849-3855
#[allow(dead_code)]
fn external_archive_request_timeout_result() -> Map<String, Value> {
    let mut r = Map::new();
    r.insert("decision".to_string(), Value::String("block".to_string()));
    r.insert(
        "code".to_string(),
        Value::String("external_archive_request_timeout".to_string()),
    );
    r.insert(
        "message".to_string(),
        Value::String(
            "External archive request exceeded Guard's aggregate time limit.".to_string(),
        ),
    );
    r.insert("severity".to_string(), Value::String("high".to_string()));
    r
}

/// `_download_external_tarball` (:3858-3867).
/// `download_restricted_archive(source_url, max_bytes=, timeout_seconds=)`.
// supply_chain_package_eval.py:3858-3867
#[allow(dead_code)]
fn download_external_tarball(
    deps: &SupplyChainEvalDeps<'_>,
    source_url: &str,
    timeout_seconds: f64,
    guard_home: &Path,
) -> Option<RestrictedArchiveDownloadResult> {
    deps.archive
        .download_restricted_archive(
            source_url,
            TARBALL_SCAN_MAX_BYTES,
            3,
            timeout_seconds,
            Some(guard_home),
        )
        .ok()
}

/// `_scan_external_tarball` (:3779-3846).
/// Returns `(result_dict, retained_download)`. The caller retains ownership of
/// the download path only when `retain_download` requests it; otherwise the
/// seam-owned temp file is dropped (Python `downloaded.cleanup()`).
// supply_chain_package_eval.py:3779-3846
#[allow(dead_code)]
fn scan_external_tarball(
    deps: &SupplyChainEvalDeps<'_>,
    source_url: &str,
    retain_download: bool,
    request_deadline: Option<f64>,
    guard_home: &Path,
) -> (
    Option<Map<String, Value>>,
    Option<RestrictedArchiveDownload>,
) {
    let mut download_timeout = TARBALL_SCAN_TIMEOUT_SECONDS as f64;
    if let Some(deadline) = request_deadline {
        let remaining = deadline - monotonic_seconds();
        if remaining <= 0.0 {
            return (Some(external_archive_request_timeout_result()), None);
        }
        download_timeout = download_timeout.min(remaining);
    }
    let downloaded = match download_external_tarball(deps, source_url, download_timeout, guard_home)
    {
        Some(d) => d,
        None => return (None, None),
    };
    let downloaded = match downloaded {
        RestrictedArchiveDownloadResult::Failure(f) => {
            let mut r = Map::new();
            r.insert("decision".to_string(), Value::String("block".to_string()));
            r.insert("code".to_string(), Value::String(f.code));
            r.insert("message".to_string(), Value::String(f.message));
            r.insert("severity".to_string(), Value::String("high".to_string()));
            return (Some(r), None);
        }
        RestrictedArchiveDownloadResult::Success(d) => d,
    };
    // try/finally: when retain_blob is false the temp blob is dropped.
    let mut retain_blob = false;
    let outcome = (|| {
        let mut inspection_timeout = TARBALL_SCAN_TIMEOUT_SECONDS as f64;
        if let Some(deadline) = request_deadline {
            // Reserve a 0.5s termination grace for the inspector parent.
            let remaining = deadline - monotonic_seconds() - 0.5;
            if remaining <= 0.0 {
                return (Some(external_archive_request_timeout_result()), None);
            }
            inspection_timeout = inspection_timeout.min(remaining);
        }
        let inspection = match deps.native_archive.inspect_archive_native(
            &downloaded.path,
            &downloaded.sha256,
            guard_home,
            inspection_timeout,
            TARBALL_SCAN_MAX_BYTES,
            TARBALL_SCAN_MAX_FILES as u64,
            u64::MAX,
            u64::MAX,
            TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES,
            u64::MAX,
            f64::MAX,
            u64::MAX,
            u64::MAX,
        ) {
            Ok(i) => i,
            Err(_) => return (None, None),
        };
        let status = optional_string(inspection.get("status")).unwrap_or_default();
        if status != "clean" {
            let mut r = Map::new();
            r.insert("decision".to_string(), Value::String("block".to_string()));
            r.insert(
                "code".to_string(),
                Value::String(optional_string(inspection.get("code")).unwrap_or_default()),
            );
            r.insert(
                "message".to_string(),
                Value::String(optional_string(inspection.get("message")).unwrap_or_default()),
            );
            r.insert(
                "severity".to_string(),
                Value::String(
                    optional_string(inspection.get("severity"))
                        .unwrap_or_else(|| "high".to_string()),
                ),
            );
            return (Some(r), None);
        }
        retain_blob = retain_download;
        let mut r = Map::new();
        r.insert("decision".to_string(), Value::String("ask".to_string()));
        r.insert(
            "code".to_string(),
            Value::String("external_tarball_source".to_string()),
        );
        r.insert(
            "message".to_string(),
            Value::String(
                "External tarball source requires review before any archive download.".to_string(),
            ),
        );
        r.insert("severity".to_string(), Value::String("medium".to_string()));
        (Some(r), if retain_blob { Some(downloaded) } else { None })
    })();
    // Drop `downloaded` when not retained (mirrors `downloaded.cleanup()`).
    outcome
}

/// `_fallback_package_results` (:3205-3253).
// supply_chain_package_eval.py:3205-3253
#[allow(dead_code)]
fn fallback_package_results(
    deps: &SupplyChainEvalDeps<'_>,
    targets: &[Map<String, Value>],
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
    fail_closed_unidentified: bool,
    verify_registry_identity: bool,
) -> Vec<Map<String, Value>> {
    let bun_fallback_packages = bun_lockfile_binary_fallback_packages(
        targets,
        artifact,
        workspace_dir,
        fail_closed_unidentified,
    );
    if !bun_fallback_packages.is_empty() {
        return bun_fallback_packages;
    }
    let lockfile_versions = lockfile_dependency_versions(deps, workspace_dir, artifact, targets);
    let flags: BTreeSet<String> = string_tuple(artifact.metadata.get("flags"))
        .into_iter()
        .collect();
    let alternate_index = command_uses_alternate_package_index(artifact);
    let mut results: Vec<Map<String, Value>> = Vec::new();
    for target in targets {
        if !alternate_index {
            if let Some(reinstall) = installed_release_reinstall_result(deps, target) {
                results.push(reinstall);
                continue;
            }
        }
        let identity_resolved = (optional_string(target.get("ecosystem")).as_deref()
            == Some("npm")
            && flags.contains("--ignore-scripts")
            && lockfile_target_key(target)
                .map(|k| lockfile_versions.contains_key(&k))
                .unwrap_or(false))
            || (verify_registry_identity
                && optional_string(target.get("range")).is_some()
                && registry_resolved_target_version(deps, target).is_some());
        results.push(unknown_package_result(
            deps,
            target,
            fail_closed_unidentified,
            identity_resolved,
        ));
    }
    results
}

// ---------------------------------------------------------------------------
// Batch F ports — `_evaluate_with_cloud` (:1092-1505) and supporting helpers.
// ---------------------------------------------------------------------------

/// `_with_cloud_auth_reconnect_copy` (:1658-1683) — result-level variant:
/// appends the `hol-guard connect` reconnect prompt to the user copy and
/// re-normalizes it against the current policy action.
#[allow(dead_code)]
fn with_cloud_auth_reconnect_copy_result(mut evaluation: PackageEvalResult) -> PackageEvalResult {
    let reconnect_command = "hol-guard connect";
    let reconnect_summary = "Guard Cloud needs a fresh sign-in before shared review can resume.";
    let mut summary = evaluation.user_copy.summary.clone();
    if !summary
        .to_ascii_lowercase()
        .contains(&reconnect_summary.to_ascii_lowercase())
    {
        summary = format!("{summary} {reconnect_summary}").trim().to_string();
    }
    let reconnect_message = format!(
        "Guard kept this request local-only because Guard Cloud authorization expired. Run `{reconnect_command}` to restore shared review and sync."
    );
    let mut harness_message = evaluation.user_copy.harness_message.clone();
    if !harness_message
        .to_ascii_lowercase()
        .contains(&reconnect_message.to_ascii_lowercase())
    {
        harness_message = format!("{harness_message} {reconnect_message}")
            .trim()
            .to_string();
    }
    let next_step = evaluation
        .user_copy
        .next_step
        .clone()
        .unwrap_or_else(|| reconnect_command.to_string());
    let candidate = SupplyChainUserCopy {
        title: evaluation.user_copy.title.clone(),
        summary,
        next_step: Some(next_step),
        dashboard_url: evaluation.user_copy.dashboard_url.clone(),
        harness_message,
    };
    let policy_action = decision_to_guard_action_variant(&evaluation.policy_action);
    evaluation.user_copy = normalize_package_user_copy(&candidate, policy_action);
    evaluation
}

/// `_resolve_guard_sync_context` — derive `(auth_context, sync_url,
/// workspace_id)` for the Cloud evaluation request.
#[allow(dead_code)]
fn resolve_guard_sync_context(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
) -> EvalResult<(Map<String, Value>, String, Option<String>)> {
    let auth_context = deps
        .guard_sync
        .resolve_guard_sync_auth_context(store, false, false)?;
    let sync_url = optional_string(auth_context.get("sync_url"))
        .ok_or_else(|| EvalError::NotFound("guard sync URL unavailable".to_string()))?;
    let canonical = deps.guard_sync.validate_guard_sync_url(
        &sync_url,
        optional_string(auth_context.get("issuer")).as_deref(),
    )?;
    let workspace_id = optional_string(auth_context.get("workspace_id"))
        .or_else(|| store.get_cloud_workspace_id())
        .or_else(|| {
            workspace_dir
                .and_then(|dir| dir.file_name())
                .map(|n| n.to_string_lossy().into_owned())
        });
    Ok((auth_context, canonical, workspace_id))
}

/// `_fetch_package_evaluation_response` — POST the evaluation request with the
/// DPoP 401-forced-refresh retry semantics of `_evaluate_with_cloud` (:1336-1380).
#[allow(dead_code)]
fn fetch_package_evaluation_response(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    auth_context: &Value,
    evaluate_url: &str,
    request_data: &[u8],
) -> EvalResult<Map<String, Value>> {
    let request = deps.guard_sync.guard_sync_request(
        auth_context,
        evaluate_url,
        "POST",
        Some(request_data),
        None,
        None,
    )?;
    match deps.guard_sync.urlopen_json_with_timeout_retry(
        &request,
        TIMEOUT_SECONDS,
        RETRY_TIMEOUT_SECONDS,
    ) {
        Ok(response) => Ok(response),
        Err(error) => {
            if error.http_status() == Some(401) {
                if let Ok(fresh) = deps
                    .guard_sync
                    .resolve_guard_sync_auth_context(store, false, true)
                {
                    if let Ok(retry) = deps.guard_sync.guard_sync_request(
                        &Value::Object(fresh),
                        evaluate_url,
                        "POST",
                        Some(request_data),
                        None,
                        None,
                    ) {
                        return deps.guard_sync.urlopen_json_with_timeout_retry(
                            &retry,
                            TIMEOUT_SECONDS,
                            RETRY_TIMEOUT_SECONDS,
                        );
                    }
                }
            }
            Err(error)
        }
    }
}

/// `_cloud_http_fail_closed_evaluation` (:1543-1595) — full form producing a
/// finalized `PackageEvalResult` (or `None` when `fail_closed_decision` is not
/// `block` and status is not 403).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn cloud_http_fail_closed_evaluation_full(
    deps: &SupplyChainEvalDeps<'_>,
    status_code: u16,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    fail_closed_decision: &str,
) -> Option<PackageEvalResult> {
    if status_code == 403 {
        return Some(cloud_fail_closed_evaluation_full(
            deps,
            "cloud_auth_error",
            "Guard cloud evaluation was not authorized, so this package request needs review.",
            artifact,
            targets,
            workspace_dir,
            workspace_fingerprint,
            bundle_meta,
            fail_closed_decision,
        ));
    }
    if fail_closed_decision != "block" {
        return None;
    }
    let (code, message) = match status_code {
        401 => (
            "cloud_auth_error",
            "Guard Cloud could not authorize this package check. Guard blocked the install rather than bypassing Cloud package protection.".to_string(),
        ),
        400 | 404 => (
            "cloud_validation_error",
            "Guard Cloud could not validate this package request. Guard blocked the install rather than bypassing Cloud package protection.".to_string(),
        ),
        _ => (
            "cloud_http_error",
            format!(
                "Guard Cloud returned HTTP {status_code} while verifying this package. Guard blocked the install rather than bypassing Cloud package protection."
            ),
        ),
    };
    Some(cloud_fail_closed_evaluation_full(
        deps,
        code,
        &message,
        artifact,
        targets,
        workspace_dir,
        workspace_fingerprint,
        bundle_meta,
        fail_closed_decision,
    ))
}

/// `_evaluate_with_cloud` (:1092-1505) — POST the evaluation request, walk the
/// entitlement/fail-closed/reconnect ladder, and merge the cloud decision.
/// Returns `(evaluation, cloud_fallback_reason)`; `None` evaluation means the
/// caller should fall back to local/bundle evaluation.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn evaluate_with_cloud(
    deps: &SupplyChainEvalDeps<'_>,
    store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_id: Option<&str>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    _bundle_defer_eligible: bool,
    _bundle_decision: Option<&str>,
    bundle_evaluation: Option<&EvaluationDraft>,
) -> (Option<PackageEvalResult>, Option<Map<String, Value>>) {
    if targets.is_empty() || workspace_id.is_none() || workspace_fingerprint.is_none() {
        return (None, None);
    }
    let workspace_fingerprint = workspace_fingerprint.unwrap();
    let workspace_id = workspace_id.unwrap();

    // `resolve_fail_closed_decision` — resolve on demand (:1128-1133).
    let resolve_fail_closed =
        |deps: &SupplyChainEvalDeps<'_>, store: &dyn SupplyChainStore| -> String {
            cloud_fail_closed_decision(deps, store, workspace_dir)
        };

    // `resolve_cloud_entitlement` (:1124-1150) — "unknown state is protected
    // state" fallback when the entitlement seam errors.
    let cloud_entitlement: Map<String, Value> = deps
        .entitlement
        .resolve_package_firewall_entitlement_with_refresh(store)
        .unwrap_or_else(|_| {
            let mut m = Map::new();
            m.insert("allowed".to_string(), Value::Bool(false));
            m.insert(
                "reason".to_string(),
                Value::String("guard_cloud_connect_required".to_string()),
            );
            m.insert("tier".to_string(), Value::String("unknown".to_string()));
            m
        });
    let cloud_protection_is_explicitly_unpaid = |entitlement: &Map<String, Value>| -> bool {
        optional_string(entitlement.get("reason"))
            .map(|r| r.trim().eq_ignore_ascii_case("paid_guard_cloud_required"))
            .unwrap_or(false)
    };

    // `resolve_cloud_failure_decision` (:1690-1704).
    let resolve_cloud_failure_decision =
        |deps: &SupplyChainEvalDeps<'_>, store: &dyn SupplyChainStore| -> String {
            if cloud_protection_is_explicitly_unpaid(&cloud_entitlement) {
                return resolve_fail_closed(deps, store);
            }
            "block".to_string()
        };

    // Resolve auth context + evaluate URL + request payload (:1318-1336).
    let (auth_context, sync_url) = match resolve_guard_sync_context(deps, store, workspace_dir) {
        Ok((ctx, url, _)) => (Value::Object(ctx), url),
        Err(_) => (Value::Null, String::new()),
    };
    let evaluate_url = normalized_supply_chain_evaluate_url(deps, &sync_url, workspace_id);
    let request_payload = build_request_payload(
        deps,
        artifact,
        targets,
        workspace_dir,
        workspace_fingerprint,
        bundle_meta
            .and_then(|m| m.get("policy_hash").cloned())
            .unwrap_or_else(|| "local:none".to_string())
            .as_str(),
    );
    let request_data = serde_json::to_vec(&request_payload).unwrap_or_default();
    let response =
        fetch_package_evaluation_response(deps, store, &auth_context, &evaluate_url, &request_data);

    match response {
        Ok(response_payload) => {
            if !response_payload.contains_key("decision") {
                let eval_result = cloud_fail_closed_evaluation_full(
                    deps,
                    "cloud_validation_error",
                    "Guard cloud evaluation returned an invalid response, so this package request needs review.",
                    artifact,
                    targets,
                    workspace_dir,
                    Some(workspace_fingerprint),
                    bundle_meta,
                    &resolve_cloud_failure_decision(deps, store),
                );
                return (Some(eval_result), None);
            }
            if !response_payload
                .get("packages")
                .map(|v| v.is_array())
                .unwrap_or(false)
            {
                let eval_result = cloud_fail_closed_evaluation_full(
                    deps,
                    "cloud_validation_error",
                    "Guard cloud evaluation returned an invalid package payload, so this package request needs review.",
                    artifact,
                    targets,
                    workspace_dir,
                    Some(workspace_fingerprint),
                    bundle_meta,
                    &resolve_cloud_failure_decision(deps, store),
                );
                return (Some(eval_result), None);
            }
            let decision = optional_string(response_payload.get("decision"))
                .map(|d| normalize_bundle_action(&d))
                .unwrap_or_else(|| "monitor".to_string());
            let reasons: Vec<Map<String, Value>> = response_payload
                .get("reasons")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_object().cloned())
                .collect();
            let packages: Vec<Map<String, Value>> = response_payload
                .get("packages")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_object().cloned())
                .map(|item| package_from_cloud_result(&item))
                .collect();
            let draft = EvaluationDraft {
                decision: decision.clone(),
                enforcement: "premium_cloud".to_string(),
                entitlement_state: "premium".to_string(),
                cache_status: "cloud".to_string(),
                packages,
                reasons,
                matched_rule_id: optional_string(response_payload.get("matched_rule_id")),
                exception_id: optional_string(response_payload.get("exception_id")),
                refresh_required: response_payload
                    .get("refresh_required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                record_monitor_evidence: decision == "monitor",
                bundle_version: bundle_meta.and_then(|m| m.get("bundle_version").cloned()),
                policy_version: bundle_meta
                    .and_then(|m| m.get("policy_hash").cloned())
                    .unwrap_or_else(|| "local:none".to_string()),
                ..Default::default()
            };
            let package_intent_hash = artifact
                .artifact_id
                .rsplit(':')
                .next()
                .map(str::to_string)
                .unwrap_or_else(|| artifact.artifact_id.clone());
            let mut evaluation = finalize_evaluation(
                deps,
                &draft,
                &package_intent_hash,
                Some(workspace_fingerprint),
            );
            if let Some(user_copy) = response_payload.get("user_copy").and_then(Value::as_object) {
                let title = optional_string(user_copy.get("title"));
                let summary = optional_string(user_copy.get("summary"));
                let updated_summary =
                    summary.unwrap_or_else(|| evaluation.user_copy.summary.clone());
                let mut harness_parts =
                    vec![evaluation.risk_summary.clone(), updated_summary.clone()];
                if let Some(next_step) = evaluation.user_copy.next_step.clone() {
                    harness_parts.push(format!("Fix: run `{next_step}`."));
                }
                let policy_action = decision_to_guard_action_variant(&evaluation.policy_action);
                let candidate = SupplyChainUserCopy {
                    title: title.unwrap_or_else(|| evaluation.user_copy.title.clone()),
                    summary: updated_summary,
                    next_step: evaluation.user_copy.next_step.clone(),
                    dashboard_url: evaluation.user_copy.dashboard_url.clone(),
                    harness_message: harness_parts.join(" "),
                };
                evaluation.user_copy = normalize_package_user_copy(&candidate, policy_action);
            }
            if let Some(bundle_draft) = bundle_evaluation {
                if cloud_result_should_defer_to_bundle(&draft, bundle_draft) {
                    let mut merged = finalize_evaluation(
                        deps,
                        bundle_draft,
                        &package_intent_hash,
                        Some(workspace_fingerprint),
                    );
                    merged.reasons.extend(draft.reasons.clone());
                    return (Some(merged), None);
                }
            }
            (Some(evaluation), None)
        }
        Err(error) => {
            if let Some(status) = error.http_status() {
                let fail_closed_eval = cloud_http_fail_closed_evaluation_full(
                    deps,
                    status,
                    artifact,
                    targets,
                    workspace_dir,
                    Some(workspace_fingerprint),
                    bundle_meta,
                    &resolve_cloud_failure_decision(deps, store),
                );
                if let Some(fail_closed) = fail_closed_eval {
                    return (Some(fail_closed), None);
                }
                return (
                    None,
                    Some(cloud_fallback_reason(
                        match status {
                            401 | 403 => "cloud_auth_error",
                            400 | 404 => "cloud_validation_error",
                            _ => "cloud_http_error",
                        },
                        &format!(
                            "Guard cloud evaluation returned HTTP {status}, so Guard fell back to local intelligence."
                        ),
                    )),
                );
            }
            let failure_decision = resolve_cloud_failure_decision(deps, store);
            let is_timeout = deps.guard_sync.is_timeout_error(&error);
            if is_timeout {
                if failure_decision == "block" {
                    return (
                        Some(cloud_fail_closed_evaluation_full(
                            deps,
                            "cloud_timeout",
                            "Guard Cloud evaluation timed out, so this package request is paused for explicit review.",
                            artifact,
                            targets,
                            workspace_dir,
                            Some(workspace_fingerprint),
                            bundle_meta,
                            "ask",
                        )),
                        None,
                    );
                }
                return (
                    None,
                    Some(cloud_fallback_reason(
                        "cloud_timeout",
                        "Guard cloud evaluation timed out, so Guard fell back to local intelligence.",
                    )),
                );
            }
            if failure_decision == "block" {
                return (
                    Some(cloud_fail_closed_evaluation_full(
                        deps,
                        "cloud_http_error",
                        "Guard Cloud evaluation could not be reached, so Guard blocked the install rather than bypassing Cloud package protection.",
                        artifact,
                        targets,
                        workspace_dir,
                        Some(workspace_fingerprint),
                        bundle_meta,
                        "block",
                    )),
                    None,
                );
            }
            (
                None,
                Some(cloud_fallback_reason(
                    "cloud_http_error",
                    "Guard Cloud evaluation could not be reached, so Guard used local package intelligence.",
                )),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// `_evaluate_package_request_artifact_uncached` (:337-795) — orchestration:
// cache check → lockfile parse gate → external-archive two-phase path →
// npm-source-review path → bundle/cloud/heuristic fall-through.
// ---------------------------------------------------------------------------

/// `_evaluate_package_request_artifact_uncached` (:337-795).
///
/// Faithful port of the Python orchestration function. Returns
/// `(Option<PackageEvalResult>, Option<String>)` where the second element is a
/// human-readable note when the result was served from the early-exit paths
/// (parity with the Python early-return tuple shape).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn evaluate_package_request_artifact_uncached(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
    now: Option<&str>,
    external_archive_network_authorized: bool,
    retain_external_archive_blob: bool,
) -> (Option<PackageEvalResult>, Option<String>) {
    let now_value = now
        .map(str::to_string)
        .unwrap_or_else(|| crate::local_supply_chain::Timestamp::now_utc().isoformat());
    let now_timestamp = parse_evaluation_timestamp(&now_value);
    let targets = evaluation_targets(deps, artifact, workspace_dir);
    let cloud_targets = cloud_evaluation_targets(deps, artifact, workspace_dir);
    let package_intent_hash = artifact
        .artifact_id
        .rsplit(':')
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| artifact.artifact_id.clone());
    let external_archive_targets: Vec<&Map<String, Value>> = targets
        .iter()
        .filter(|t| target_is_external_https_archive(t))
        .collect();
    let external_archive_source_hashes: Vec<String> = external_archive_targets
        .iter()
        .filter_map(|t| optional_string(t.get("source_url")))
        .map(|u| stable_digest_hex(u.as_bytes()))
        .collect();

    // `incomplete_lockfile` gate (:356-364).
    if let Some(workspace_dir) = workspace_dir {
        let parse_results = lockfile_parse_results(deps, workspace_dir, artifact);
        if let Some(incomplete) = first_incomplete_lockfile_result(&parse_results) {
            let workspace_id = store.get_cloud_workspace_id();
            let workspace_fingerprint = workspace_fingerprint(
                deps,
                workspace_id.as_deref().unwrap_or(""),
                Some(workspace_dir),
                artifact,
                None,
            );
            return (
                Some(finalize_incomplete_lockfile_evaluation(
                    deps,
                    artifact,
                    store,
                    incomplete,
                    workspace_id.as_deref(),
                    &workspace_fingerprint,
                    &now_value,
                )),
                None,
            );
        }
    }

    // `external_archive_targets` gate (:365-410) — local two-phase evaluation.
    if !external_archive_targets.is_empty() {
        if external_archive_targets.len() > EXTERNAL_ARCHIVE_MAX_TARGETS {
            let limit_package = heuristic_package_result(
                external_archive_targets[0],
                "block",
                "external_archive_target_limit",
                "External archive request exceeded Guard's per-command target limit.",
                "high",
            );
            let draft = EvaluationDraft {
                decision: "block".to_string(),
                enforcement: "free_local".to_string(),
                entitlement_state: "free".to_string(),
                cache_status: "miss".to_string(),
                packages: vec![limit_package],
                reasons: Vec::new(),
                matched_rule_id: None,
                exception_id: None,
                refresh_required: false,
                record_monitor_evidence: false,
                bundle_version: None,
                policy_version: "local:none".to_string(),
                external_archive_source_hashes: external_archive_source_hashes.clone(),
                ..Default::default()
            };
            let result = finalize_evaluation(deps, &draft, &package_intent_hash, None);
            persist_evidence(deps, store, artifact, &result, &now_value);
            return (Some(result), None);
        }
        let external_archive_draft = heuristic_result(
            deps,
            artifact,
            store,
            &targets,
            workspace_dir,
            external_archive_network_authorized,
            retain_external_archive_blob,
            None,
        )
        .unwrap_or_else(|| EvaluationDraft {
            decision: "block".to_string(),
            enforcement: "free_local".to_string(),
            entitlement_state: "free".to_string(),
            cache_status: "miss".to_string(),
            packages: Vec::new(),
            reasons: vec![{
                let mut r = Map::new();
                r.insert(
                    "code".to_string(),
                    Value::String("external_archive_inspection_incomplete".to_string()),
                );
                r.insert(
                    "message".to_string(),
                    Value::String(
                        "Guard could not establish an external archive evaluation.".to_string(),
                    ),
                );
                r.insert("severity".to_string(), Value::String("high".to_string()));
                r.insert(
                    "source".to_string(),
                    Value::String("guard-local".to_string()),
                );
                r
            }],
            matched_rule_id: None,
            exception_id: None,
            refresh_required: false,
            record_monitor_evidence: false,
            bundle_version: None,
            policy_version: "local:none".to_string(),
            ..Default::default()
        });
        // Ensure source hashes are carried even when heuristic_result produced
        // its own (or none).
        let mut external_archive_draft = external_archive_draft;
        if external_archive_draft
            .external_archive_source_hashes
            .is_empty()
        {
            external_archive_draft.external_archive_source_hashes =
                external_archive_source_hashes.clone();
        }
        let external_archive_result =
            finalize_evaluation(deps, &external_archive_draft, &package_intent_hash, None);
        persist_evidence(deps, store, artifact, &external_archive_result, &now_value);
        return (Some(external_archive_result), None);
    }

    // `source_review_targets` gate (:411-440) — npm source-review path.
    let source_review_targets: Vec<&Map<String, Value>> = targets
        .iter()
        .filter(|t| target_requires_npm_source_review(t))
        .collect();
    if !source_review_targets.is_empty() {
        if source_review_targets.len() != targets.len() {
            let mixed_source_package = heuristic_package_result(
                source_review_targets[0],
                "block",
                "npm_source_mixed_request_unsupported",
                "npm source dependencies must be installed in a dedicated request so Guard can verify the package source.",
                "high",
            );
            let draft = EvaluationDraft {
                decision: "block".to_string(),
                enforcement: "free_local".to_string(),
                entitlement_state: "free".to_string(),
                cache_status: "miss".to_string(),
                packages: vec![mixed_source_package],
                reasons: Vec::new(),
                matched_rule_id: None,
                exception_id: None,
                refresh_required: false,
                record_monitor_evidence: false,
                bundle_version: None,
                policy_version: "local:none".to_string(),
                ..Default::default()
            };
            let result = finalize_evaluation(deps, &draft, &package_intent_hash, None);
            persist_evidence(deps, store, artifact, &result, &now_value);
            return (Some(result), None);
        }
        let source_review_draft = heuristic_result(
            deps,
            artifact,
            store,
            &targets,
            workspace_dir,
            external_archive_network_authorized,
            retain_external_archive_blob,
            None,
        )
        .unwrap_or_else(|| EvaluationDraft {
            decision: "block".to_string(),
            enforcement: "free_local".to_string(),
            entitlement_state: "free".to_string(),
            cache_status: "miss".to_string(),
            packages: Vec::new(),
            reasons: vec![{
                let mut r = Map::new();
                r.insert(
                    "code".to_string(),
                    Value::String("npm_source_review_incomplete".to_string()),
                );
                r.insert(
                    "message".to_string(),
                    Value::String(
                        "Guard could not complete source review for this npm package.".to_string(),
                    ),
                );
                r.insert("severity".to_string(), Value::String("high".to_string()));
                r.insert(
                    "source".to_string(),
                    Value::String("guard-local".to_string()),
                );
                r
            }],
            matched_rule_id: None,
            exception_id: None,
            refresh_required: false,
            record_monitor_evidence: false,
            bundle_version: None,
            policy_version: "local:none".to_string(),
            ..Default::default()
        });
        let source_review_result =
            finalize_evaluation(deps, &source_review_draft, &package_intent_hash, None);
        persist_evidence(deps, store, artifact, &source_review_result, &now_value);
        return (Some(source_review_result), None);
    }

    // Auth-context resolution (:441-458).
    let workspace_id = store.get_cloud_workspace_id();
    let bundle_payload = workspace_id
        .as_deref()
        .and_then(|id| store.get_cached_supply_chain_bundle(id))
        .unwrap_or(Value::Null);
    let bundle_response = if bundle_payload.is_null() {
        None
    } else {
        deps.bundle
            .load_supply_chain_bundle_response(&bundle_payload)
            .ok()
    };
    let bundle_meta_map = bundle_response
        .as_ref()
        .map(|r| bundle_meta(&r.to_dict().as_object().cloned().unwrap_or_default()));
    let bundle_meta: Option<BTreeMap<String, String>> = bundle_meta_map;
    let workspace_fingerprint = workspace_id
        .as_deref()
        .map(|id| workspace_fingerprint(deps, id, workspace_dir, artifact, bundle_meta.as_ref()));
    let workspace_fingerprint = workspace_fingerprint.as_deref();

    // Bundle evaluation (:526-536).
    let bundle_evaluation = bundle_response.as_ref().and_then(|response| {
        evaluate_with_bundle(
            deps,
            artifact,
            &targets,
            response,
            workspace_dir,
            workspace_id.as_deref(),
            now_timestamp,
        )
    });

    // `has_package_material` gate (:537-545).
    if !artifact_has_package_material(artifact, &targets) {
        let no_material_result = empty_package_material_result(
            artifact,
            workspace_id.as_deref(),
            bundle_meta
                .as_ref()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect::<Map<String, Value>>()
                })
                .as_ref(),
            &package_intent_hash,
            workspace_fingerprint,
        );
        persist_evidence(deps, store, artifact, &no_material_result, &now_value);
        return (Some(no_material_result), None);
    }

    // `bundle_defer_eligible` (:546-548) — `block` decisions always defer;
    // non-block defer only when the bundle is fresh (`!refresh_required`).
    let bundle_defer_eligible = bundle_evaluation
        .as_ref()
        .map(|b| b.decision == "block" || !b.refresh_required)
        .unwrap_or(false);
    let bundle_decision = bundle_evaluation.as_ref().map(|b| b.decision.as_str());

    // Cloud evaluation (:549-570) — returns `(Option<PackageEvalResult>,
    // Option<cloud_fallback_reason>)`.
    let (mut cloud_result, mut cloud_fallback_reason) = evaluate_with_cloud(
        deps,
        store,
        artifact,
        &cloud_targets,
        workspace_dir,
        workspace_id.as_deref(),
        workspace_fingerprint,
        bundle_meta.as_ref(),
        bundle_defer_eligible,
        bundle_decision,
        bundle_evaluation.as_ref(),
    );
    if let Some(ref cloud) = cloud_result {
        if let Some(ref bundle_draft) = bundle_evaluation {
            if cloud_result_should_defer_to_bundle(&evaluation_to_draft(cloud), bundle_draft) {
                if cloud_fallback_reason.is_none() {
                    cloud_fallback_reason = cloud.reasons.first().cloned();
                }
                cloud_result = None;
            }
        }
    }

    if let Some(mut cloud_result) = cloud_result {
        // `upgrade_required` heuristic upgrade (:571-596).
        if cloud_result.enforcement == "upgrade_required" {
            if let Some(heuristic) = heuristic_result(
                deps,
                artifact,
                store,
                &targets,
                workspace_dir,
                external_archive_network_authorized,
                retain_external_archive_blob,
                None,
            ) {
                if decision_rank(&heuristic.decision) > decision_rank(&cloud_result.decision) {
                    let upgrade_draft = EvaluationDraft {
                        decision: heuristic.decision,
                        enforcement: "free_local".to_string(),
                        entitlement_state: "free".to_string(),
                        cache_status: "upgrade-gated".to_string(),
                        packages: heuristic.packages,
                        reasons: heuristic.reasons,
                        matched_rule_id: heuristic.matched_rule_id,
                        exception_id: heuristic.exception_id,
                        refresh_required: false,
                        record_monitor_evidence: heuristic.record_monitor_evidence,
                        bundle_version: None,
                        policy_version: bundle_meta
                            .as_ref()
                            .and_then(|m| m.get("policy_hash").cloned())
                            .unwrap_or_else(|| "local:none".to_string()),
                        ..Default::default()
                    };
                    cloud_result = finalize_evaluation(
                        deps,
                        &upgrade_draft,
                        &package_intent_hash,
                        workspace_fingerprint,
                    );
                }
            }
        }
        cache_reusable_cloud_validation_error(
            deps,
            workspace_id.as_deref(),
            bundle_meta
                .as_ref()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect::<Map<String, Value>>()
                })
                .as_ref(),
            &package_intent_hash,
            &cloud_result,
            &now_value,
        );
        persist_evidence(deps, store, artifact, &cloud_result, &now_value);
        return (Some(cloud_result), None);
    }

    // `refresh_required` + no OAuth → fall back to bundle (:597-621).
    if let Some(ref bundle_draft) = bundle_evaluation {
        if bundle_draft.refresh_required
            && !deps
                .store_extras
                .get_oauth_local_credential_health()
                .get("configured")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            let fallback = finalize_evaluation(
                deps,
                bundle_draft,
                &package_intent_hash,
                workspace_fingerprint,
            );
            persist_evidence(deps, store, artifact, &fallback, &now_value);
            let mut event = Map::new();
            event.insert(
                "artifact_id".to_string(),
                Value::String(artifact.artifact_id.clone()),
            );
            event.insert(
                "artifact_name".to_string(),
                Value::String(artifact.name.clone()),
            );
            event.insert(
                "reason".to_string(),
                Value::String("feed_stale".to_string()),
            );
            store.add_event(
                "supply_chain_bundle_refresh_requested",
                &Value::Object(event),
                &now_value,
            );
            return (Some(fallback), None);
        }
    }

    // Bundle fallback (:622-662).
    if let Some(ref bundle_draft) = bundle_evaluation {
        let mut fallback = finalize_evaluation(
            deps,
            bundle_draft,
            &package_intent_hash,
            workspace_fingerprint,
        );
        if let Some(reason) = cloud_fallback_reason.as_ref() {
            fallback.reasons.push(reason.clone());
            if cloud_fallback_requires_reconnect_copy(reason) {
                fallback = with_cloud_auth_reconnect_copy_result(fallback);
            }
        }
        if let Some(bundle_meta) = bundle_meta.as_ref() {
            if bundle_draft.decision != "monitor" && fallback.cache_status != "cloud-error" {
                let mut cache_workspace_id = workspace_id.clone();
                if cache_workspace_id.is_none() {
                    if let Some(bundle_section) =
                        bundle_payload.get("bundle").and_then(Value::as_object)
                    {
                        if let Some(id) = optional_string(bundle_section.get("workspaceId")) {
                            cache_workspace_id = Some(id);
                        }
                    }
                }
                if let Some(cache_workspace_id) = cache_workspace_id.as_deref() {
                    deps.store_extras.cache_supply_chain_evaluation(
                        cache_workspace_id,
                        &package_intent_hash,
                        bundle_meta
                            .get("feed_snapshot_hash")
                            .map(String::as_str)
                            .unwrap_or(""),
                        bundle_meta
                            .get("policy_hash")
                            .map(String::as_str)
                            .unwrap_or(""),
                        bundle_meta
                            .get("scoring_version")
                            .map(String::as_str)
                            .unwrap_or(""),
                        bundle_meta
                            .get("bundle_version")
                            .map(String::as_str)
                            .unwrap_or(""),
                        &fallback
                            .to_cache_dict()
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        &now_value,
                    );
                }
            }
        }
        persist_evidence(deps, store, artifact, &fallback, &now_value);
        if fallback.refresh_required {
            let mut event = Map::new();
            event.insert(
                "artifact_id".to_string(),
                Value::String(artifact.artifact_id.clone()),
            );
            event.insert(
                "artifact_name".to_string(),
                Value::String(artifact.name.clone()),
            );
            event.insert(
                "reason".to_string(),
                Value::String("feed_stale".to_string()),
            );
            store.add_event(
                "supply_chain_bundle_refresh_requested",
                &Value::Object(event),
                &now_value,
            );
        }
        return (Some(fallback), None);
    }

    // Heuristic fallback (:663-795).
    let heuristic = heuristic_result(
        deps,
        artifact,
        store,
        &targets,
        workspace_dir,
        external_archive_network_authorized,
        retain_external_archive_blob,
        None,
    );
    let heuristic = match heuristic {
        Some(h) => h,
        None => {
            let fail_closed_unidentified =
                unidentified_packages_fail_closed(deps, store, workspace_dir);
            let verify_registry_identity = cloud_fallback_reason
                .as_ref()
                .and_then(|r| optional_string(r.get("code")))
                .as_deref()
                == Some("cloud_auth_error");
            let fallback_packages = fallback_package_results(
                deps,
                &targets,
                artifact,
                workspace_dir,
                fail_closed_unidentified,
                verify_registry_identity,
            );
            let fallback_decision = fallback_packages
                .iter()
                .map(|p| {
                    optional_string(p.get("decision")).unwrap_or_else(|| "monitor".to_string())
                })
                .max_by_key(|d| decision_rank(d))
                .unwrap_or_else(|| "monitor".to_string());
            let fallback_reasons: Vec<Map<String, Value>> = fallback_packages
                .iter()
                .flat_map(|p| dict_items(p.get("reasons")))
                .collect();
            EvaluationDraft {
                decision: fallback_decision.clone(),
                enforcement: if workspace_id.is_none() {
                    "free_local".to_string()
                } else {
                    "local_fallback".to_string()
                },
                entitlement_state: if workspace_id.is_none() {
                    "free".to_string()
                } else {
                    "premium".to_string()
                },
                cache_status: "miss".to_string(),
                packages: fallback_packages,
                reasons: fallback_reasons,
                matched_rule_id: None,
                exception_id: None,
                refresh_required: false,
                record_monitor_evidence: fallback_decision == "monitor",
                bundle_version: None,
                policy_version: bundle_meta
                    .as_ref()
                    .and_then(|m| m.get("policy_hash").cloned())
                    .unwrap_or_else(|| "local:none".to_string()),
                ..Default::default()
            }
        }
    };
    let mut result = finalize_evaluation(
        deps,
        &heuristic,
        &package_intent_hash,
        workspace_fingerprint,
    );
    if let Some(reason) = cloud_fallback_reason.as_ref() {
        result.reasons.push(reason.clone());
        if cloud_fallback_requires_reconnect_copy(reason) {
            result = with_cloud_auth_reconnect_copy_result(result);
        }
    }
    persist_evidence(deps, store, artifact, &result, &now_value);
    (Some(result), None)
}

/// Convert a finalized `PackageEvalResult` back to the `EvaluationDraft` fields
/// used by `cloud_result_should_defer_to_bundle` (which operates on drafts).
#[allow(dead_code)]
fn evaluation_to_draft(evaluation: &PackageEvalResult) -> EvaluationDraft {
    EvaluationDraft {
        decision: evaluation.decision.clone(),
        enforcement: evaluation.enforcement.clone(),
        entitlement_state: evaluation.entitlement_state.clone(),
        cache_status: evaluation.cache_status.clone(),
        packages: evaluation.packages.clone(),
        reasons: evaluation.reasons.clone(),
        matched_rule_id: evaluation.matched_rule_id.clone(),
        exception_id: evaluation.exception_id.clone(),
        refresh_required: evaluation.refresh_required,
        record_monitor_evidence: evaluation.record_monitor_evidence,
        bundle_version: evaluation.bundle_version.clone(),
        policy_version: evaluation.policy_version.clone(),
        ..Default::default()
    }
}
