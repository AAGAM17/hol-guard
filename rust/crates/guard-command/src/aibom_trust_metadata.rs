//! Port of `src/codex_plugin_scanner/guard/aibom_trust_metadata.py` (RTM-027).
//!
//! Attach local HCS trust domain evidence to AIBOM inventory metadata.
//!
//! TODO(deps): Python lazily resolves `.inventory_contract`
//! (`_normalize_inventory_datetime`), `..checks.skill_security`
//! (`resolve_skill_security_context`), `..trust_instruction_scoring`
//! (`build_instruction_domain`), `..trust_mcp_scoring`
//! (`build_mcp_domain`, `build_mcp_surface_domain`),
//! `..trust_plugin_scoring` (`build_plugin_domain`),
//! `..trust_skill_scoring` (`build_skill_domain`), `.runtime.evidence_hash`
//! (`guard_evidence_hash`), and `.trust_metadata_boundary`
//! (`separate_untrusted_adapter_trust_metadata`). Until those ports land, the
//! module keeps those surfaces behind the `TrustScoringApi`,
//! `GuardEvidenceHashApi`, and `TrustMetadataBoundaryApi` seams plus a local
//! mirror of the inventory-contract datetime normalizer.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Dependency mirrors — duck-typed `getattr` objects become `Map` payloads and
// typed dataclasses become structs, matching `local_supply_chain`'s seam
// convention.
// ---------------------------------------------------------------------------

/// `ScanOptions` mirror — only the fields consumed by the trust pipeline.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub cisco_skill_scan: String,
    pub cisco_mcp_scan: String,
    pub cisco_policy: String,
    pub ecosystem: String,
    pub extra: Map<String, Value>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            cisco_skill_scan: "auto".into(),
            cisco_mcp_scan: "auto".into(),
            cisco_policy: "balanced".into(),
            ecosystem: "auto".into(),
            extra: Map::new(),
        }
    }
}

impl ScanOptions {
    /// `_INVENTORY_TRUST_SCAN_OPTIONS` = `ScanOptions(cisco_skill_scan="off")`.
    pub fn inventory_trust_scan_options() -> Self {
        Self {
            cisco_skill_scan: "off".into(),
            ..ScanOptions::default()
        }
    }
}

/// `Severity` enum mirror — `isinstance(value, Severity)` / `value.value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// `Severity.value` — lowercase wire token.
    pub fn value(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// `trust_models.TrustComponentScore` mirror.
#[derive(Debug, Clone, Default)]
pub struct TrustComponentScore {
    pub key: String,
    pub score: f64,
    pub rationale: String,
    pub evidence: Vec<String>,
}

/// `trust_models.TrustAdapterScore` mirror.
#[derive(Debug, Clone, Default)]
pub struct TrustAdapterScore {
    pub adapter_id: String,
    pub label: String,
    pub weight: f64,
    pub contribution_mode: String,
    pub applicable: bool,
    pub emitted: bool,
    pub included_in_denominator: bool,
    pub score: f64,
    pub components: Vec<TrustComponentScore>,
}

/// `trust_models.TrustDomainScore` mirror.
#[derive(Debug, Clone, Default)]
pub struct TrustDomainScore {
    pub domain: String,
    pub label: String,
    pub spec_id: String,
    pub spec_version: String,
    pub spec_path: String,
    pub derived_from: Vec<String>,
    pub profile_id: String,
    pub profile_version: String,
    pub score: f64,
    pub adapters: Vec<TrustAdapterScore>,
}

/// `checks.skill_security.SkillSecurityContext` mirror — opaque payload until
/// the real port lands; the scoring seam produces/consumes it.
#[derive(Debug, Clone, Default)]
pub struct SkillSecurityContext {
    pub value: Value,
}

// ---------------------------------------------------------------------------
// Dependency seams.
// ---------------------------------------------------------------------------

/// `trust_*_scoring` + `checks.skill_security` seam.
pub trait TrustScoringApi {
    fn resolve_skill_security_context(
        &self,
        plugin_dir: &Path,
        options: &ScanOptions,
    ) -> SkillSecurityContext;
    fn build_plugin_domain(&self, plugin_dir: &Path) -> Option<TrustDomainScore>;
    fn build_skill_domain(
        &self,
        plugin_dir: &Path,
        context: &SkillSecurityContext,
    ) -> Option<TrustDomainScore>;
    fn build_mcp_domain(&self, plugin_dir: &Path) -> Option<TrustDomainScore>;
    fn build_mcp_surface_domain(
        &self,
        name: Option<&str>,
        command: Option<&str>,
        url: Option<&str>,
        transport: Option<&str>,
    ) -> Option<TrustDomainScore>;
    fn build_instruction_domain(
        &self,
        path: &Path,
        role: &str,
        item_kind: &str,
    ) -> Option<TrustDomainScore>;
}

/// `.runtime.evidence_hash` seam — `guard_evidence_hash(payload)`.
pub trait GuardEvidenceHashApi {
    fn guard_evidence_hash(&self, payload: &Map<String, Value>) -> String;
}

/// `.trust_metadata_boundary` seam.
pub trait TrustMetadataBoundaryApi {
    fn separate_untrusted_adapter_trust_metadata(
        &self,
        metadata: Map<String, Value>,
    ) -> Map<String, Value>;
}

/// Bundled seams so every public function takes a single `impl` reference.
pub struct TrustDeps<'a> {
    pub scoring: &'a dyn TrustScoringApi,
    pub evidence_hash: &'a dyn GuardEvidenceHashApi,
    pub boundary: &'a dyn TrustMetadataBoundaryApi,
}

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

/// `_LOCAL_BASELINE_ITEM_KINDS`
pub static LOCAL_BASELINE_ITEM_KINDS: &[&str] = &[
    "agent",
    "daemon_plugin",
    "hook",
    "mcp_server",
    "mcp_tool",
    "overlay",
    "plugin",
    "policy",
    "prompt_pack",
    "skill",
];

/// `_INSTRUCTION_BASELINE_ITEM_KINDS`
pub static INSTRUCTION_BASELINE_ITEM_KINDS: &[&str] = &[
    "agent",
    "daemon_plugin",
    "hook",
    "overlay",
    "policy",
    "prompt_pack",
];

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/// `round()` — Python banker's rounding (round-half-to-even) to integer.
fn py_round(value: f64) -> i64 {
    if !value.is_finite() {
        return 0;
    }
    let floor = value.floor();
    let diff = value - floor;
    let base = floor as i64;
    if diff < 0.5 {
        base
    } else if diff > 0.5 {
        base + 1
    } else if base % 2 == 0 {
        base
    } else {
        base + 1
    }
}

/// `getattr(artifact, key, None)` returning a `&str` for a JSON object mirror.
fn a_str<'a>(artifact: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    artifact.get(key).and_then(Value::as_str)
}

/// `metadata.get(key)` → non-empty `str` or `None` (`_metadata_string`).
fn meta_str<'a>(metadata: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn run_meta(run: &Map<String, Value>) -> Option<&Map<String, Value>> {
    run.get("metadata").and_then(Value::as_object)
}

fn run_findings(run: &Map<String, Value>) -> &[Value] {
    run.get("findings")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// `getattr(finding, key, None)` on a finding `Map`.
fn finding_str<'a>(finding: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    finding.get(key).and_then(Value::as_str)
}

// ---------------------------------------------------------------------------
// `_normalize_inventory_datetime` — local mirror of the inventory_contract
// helper (UTC `Z` ISO-8601 emission, verbatim fallback on parse failure).
// ---------------------------------------------------------------------------

pub fn normalize_inventory_datetime(value: &Value) -> Value {
    let text = match value.as_str() {
        Some(t) if !t.trim().is_empty() => t,
        _ => return value.clone(),
    };
    parse_iso8601(text).map_or_else(|| value.clone(), Value::String)
}

fn parse_iso8601(value: &str) -> Option<String> {
    let text = value.trim().replace(['Z', 'z'], "+00:00");
    let (date_part, time_part) = match text.split_once('T').or_else(|| text.split_once(' ')) {
        Some((d, t)) => (d, t),
        None => (text.as_str(), ""),
    };
    let mut date_seg = date_part.split('-');
    let year: i32 = date_seg.next()?.parse().ok()?;
    let month: i32 = date_seg.next()?.parse().ok()?;
    let day: i32 = date_seg.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if time_part.is_empty() {
        return Some(format!("{year:04}-{month:02}-{day:02}T00:00:00Z"));
    }
    let (time_core, tz) = split_iso8601_tz(time_part);
    let mut time_seg = time_core.split(':');
    let hour: i32 = time_seg.next()?.parse().ok()?;
    let minute: i32 = time_seg.next()?.parse().ok()?;
    let sec_raw = time_seg.next().unwrap_or("0");
    let (sec_s, frac_s) = sec_raw
        .split_once('.')
        .map_or((sec_raw, ""), |(s, f)| (s, f));
    let second: i32 = sec_s.parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let offset_minutes = match tz {
        Some(tz_raw) => {
            let sign = if tz_raw.starts_with('-') { -1 } else { 1 };
            let digits: String = tz_raw
                .chars()
                .skip(1)
                .filter(|c| c.is_ascii_digit())
                .collect();
            let (oh, om) = if digits.len() >= 4 {
                (
                    digits[..2].parse::<i32>().ok()?,
                    digits[2..4].parse::<i32>().ok()?,
                )
            } else if digits.len() == 2 {
                (digits.parse::<i32>().ok()?, 0)
            } else {
                (0, 0)
            };
            sign * (oh * 60 + om)
        }
        None => 0,
    };
    let total = hour * 3600 + minute * 60 + second - offset_minutes * 60;
    let (day_shift, secs) = if total < 0 {
        (-1, total + 86400)
    } else if total >= 86400 {
        (1, total - 86400)
    } else {
        (0, total)
    };
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (mut y, mut mo, mut d) = (year, month, day);
    if day_shift != 0 {
        let jd = days_from_civil(y, mo, d) + day_shift;
        let (ny, nmo, nd) = civil_from_days(jd);
        y = ny;
        mo = nmo;
        d = nd;
    }
    let frac = if frac_s.is_empty() {
        String::new()
    } else {
        let padded: String = frac_s
            .chars()
            .chain(std::iter::repeat('0'))
            .take(6)
            .collect();
        let micros: u32 = padded.parse().unwrap_or(0);
        if micros == 0 {
            String::new()
        } else {
            format!(".{micros:06}")
        }
    };
    Some(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}{frac}Z"))
}

fn days_from_civil(y: i32, m: i32, d: i32) -> i32 {
    let ya = if m <= 2 { y - 1 } else { y };
    let era = if ya >= 0 { ya } else { ya - 399 } / 400;
    let yoe = ya - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i32) -> (i32, i32, i32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn split_iso8601_tz(time_part: &str) -> (&str, Option<&str>) {
    for (idx, ch) in time_part.char_indices() {
        if (ch == '+' || ch == '-') && idx > 0 {
            return (&time_part[..idx], Some(&time_part[idx..]));
        }
    }
    (time_part, None)
}

// ---------------------------------------------------------------------------
// defmap order
// ---------------------------------------------------------------------------

/// `trust_resolution_from_domain(domain, *, captured_at)`
pub fn trust_resolution_from_domain(
    domain: &TrustDomainScore,
    deps: &TrustDeps<'_>,
    captured_at: &str,
) -> Map<String, Value> {
    let trust_components = _trust_components_from_domain(domain);
    let normalized_captured_at =
        normalize_inventory_datetime(&Value::String(captured_at.to_string()));
    let evidence =
        _local_baseline_evidence_payload(domain, &normalized_captured_at, &trust_components);
    let metadata = json!({
        "profileId": domain.profile_id,
        "profileVersion": domain.profile_version,
        "scorer": "hol-guard-local",
        "specId": domain.spec_id,
        "specVersion": domain.spec_version,
        "trustDomain": domain.domain,
        "attestationStatus": "unsigned",
        "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "evidence": evidence,
        "evidenceHash": _trust_evidence_hash(&evidence, deps),
    });
    let mut out = Map::new();
    out.insert("resolutionSource".into(), json!("local"));
    out.insert("status".into(), json!("local"));
    out.insert("evidenceAuthority".into(), json!("device_claim"));
    out.insert("affectsV4Score".into(), json!(false));
    out.insert("trustScore".into(), json!(py_round(domain.score)));
    out.insert(
        "trustComponents".into(),
        Value::Array(trust_components.into_iter().map(Value::Object).collect()),
    );
    out.insert("capturedAt".into(), normalized_captured_at);
    out.insert(
        "provenance".into(),
        Value::Object(_local_claim_provenance("hol-guard-local-baseline")),
    );
    out.insert("metadata".into(), metadata);
    out
}

/// `apply_local_trust_metadata(artifact, *, captured_at, item_kind, metadata, workspace_dir, cisco_runs=())`
pub fn apply_local_trust_metadata(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    captured_at: &str,
    item_kind: &str,
    metadata: Map<String, Value>,
    workspace_dir: Option<&Path>,
    cisco_runs: &[Map<String, Value>],
) -> Map<String, Value> {
    let mut enriched = deps
        .boundary
        .separate_untrusted_adapter_trust_metadata(metadata);
    let mut trust_layers: Vec<Map<String, Value>> = Vec::new();

    if LOCAL_BASELINE_ITEM_KINDS.contains(&item_kind) {
        let domain =
            _local_trust_domain_for_artifact(artifact, deps, item_kind, &enriched, workspace_dir);
        if let Some(domain) = domain {
            enriched.insert(
                "trustResolution".into(),
                Value::Object(trust_resolution_from_domain(&domain, deps, captured_at)),
            );
            trust_layers.push(_trust_layer_from_domain(&domain, deps, captured_at));
        }
    }

    trust_layers.extend(_cisco_trust_layers_for_artifact(
        artifact,
        deps,
        item_kind,
        captured_at,
        cisco_runs,
        workspace_dir,
    ));

    let local_security = _local_security_for_artifact(
        artifact,
        deps,
        item_kind,
        &enriched,
        captured_at,
        cisco_runs,
        workspace_dir,
    );
    if let Some(local_security) = local_security {
        enriched.insert("localSecurity".into(), Value::Object(local_security));
    }

    if !trust_layers.is_empty() {
        enriched.insert(
            "trustLayers".into(),
            Value::Array(_merge_trust_layers(None, trust_layers)),
        );
    }
    enriched
}

/// `_local_security_for_artifact(...)`
fn _local_security_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    metadata: &Map<String, Value>,
    captured_at: &str,
    cisco_runs: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    let skill_security = _local_skill_security_for_artifact(
        artifact,
        deps,
        item_kind,
        metadata,
        captured_at,
        cisco_runs,
        workspace_dir,
    );
    if skill_security.is_some() {
        return skill_security;
    }
    _local_mcp_security_for_artifact(
        artifact,
        deps,
        item_kind,
        captured_at,
        cisco_runs,
        workspace_dir,
    )
}

/// `_cisco_local_security_payload(run, findings, *, captured_at, scripts_total, extra_safety_fields=None)`
///
/// Returns `(status, normalized_captured_at, findings, safety, metadata_payload)`.
#[allow(clippy::type_complexity)]
fn _cisco_local_security_payload(
    run: &Map<String, Value>,
    mut findings: Vec<Map<String, Value>>,
    _deps: &TrustDeps<'_>,
    captured_at: &str,
    scripts_total: i64,
    extra_safety_fields: Option<Map<String, Value>>,
) -> (
    String,
    Value,
    Vec<Map<String, Value>>,
    Option<Map<String, Value>>,
    Map<String, Value>,
) {
    let status = a_str(run, "status").map_or_else(|| "unknown".to_string(), str::to_string);
    let normalized_captured_at =
        normalize_inventory_datetime(&Value::String(captured_at.to_string()));
    findings.sort_by(|a, b| {
        let key = |f: &Map<String, Value>| {
            (
                f.get("file")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                f.get("ruleId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                f.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        };
        key(a).cmp(&key(b))
    });
    let severity_counts = _cisco_severity_counts(run);
    let analyzers_used = _cisco_analyzers_used(run);
    let score: Option<i64> = if status == "enabled" {
        Some(_cisco_layer_score(&severity_counts, &analyzers_used))
    } else {
        None
    };
    let mut safety: Option<Map<String, Value>> = None;
    if let Some(score) = score {
        let high_findings = findings
            .iter()
            .filter(|f| f.get("severity").and_then(Value::as_str) == Some("high"))
            .count() as i64;
        let mut s = Map::new();
        s.insert("score".into(), json!(score));
        s.insert("label".into(), json!(_local_skill_security_label(score)));
        s.insert("findingsTotal".into(), json!(findings.len() as i64));
        s.insert("highFindings".into(), json!(high_findings));
        s.insert("scriptsTotal".into(), json!(scripts_total));
        if let Some(extra) = extra_safety_fields {
            for (k, v) in extra {
                s.insert(k, v);
            }
        }
        s.insert("permissionsMissing".into(), json!([]));
        safety = Some(s);
    }

    let mut metadata_payload = Map::new();
    metadata_payload.insert(
        "scannerSource".into(),
        json!(a_str(run, "source").map_or("unknown", |s| s)),
    );
    metadata_payload.insert(
        "message".into(),
        json!(a_str(run, "message").map_or("", |s| s)),
    );
    metadata_payload.insert(
        "findingsBySeverity".into(),
        Value::Object(severity_counts.clone()),
    );
    metadata_payload.insert("totalFindings".into(), json!(findings.len() as i64));
    if let Some(d) = run.get("duration_ms").and_then(Value::as_i64) {
        metadata_payload.insert("durationMs".into(), json!(d));
    }
    (
        status,
        normalized_captured_at,
        findings,
        safety,
        metadata_payload,
    )
}

/// `_local_skill_security_for_artifact(...)`
fn _local_skill_security_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    metadata: &Map<String, Value>,
    captured_at: &str,
    cisco_runs: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    if item_kind != "skill" || metadata.get("artifactType").and_then(Value::as_str) != Some("skill")
    {
        return None;
    }

    let trust_root = _trust_root_for_artifact(artifact, item_kind, workspace_dir)?;
    let run = cisco_runs.iter().find(|candidate| {
        a_str(candidate, "source") == Some("cisco-skill-scanner")
            && _matches_skill_cisco_run(artifact, item_kind, candidate, workspace_dir)
    })?;

    let (status, normalized_captured_at, findings, safety, mut metadata_payload) =
        _cisco_local_security_payload(
            run,
            _local_skill_security_findings(run, &trust_root),
            deps,
            captured_at,
            _local_skill_scripts_total(run),
            None,
        );

    if let Some(run_metadata) = run_meta(run) {
        for key in [
            "analyzersUsed",
            "policyName",
            "mode",
            "skillsScanned",
            "skillsSkipped",
        ] {
            if let Some(value) = run_metadata.get(key) {
                metadata_payload.insert(key.into(), value.clone());
            }
        }
    }

    let evidence_for_hash = json!({
        "capturedAt": normalized_captured_at,
        "entityType": "skill",
        "findings": findings,
        "provider": "cisco-skill-scanner",
        "safety": safety,
        "source": "local_indexed",
        "status": status,
    });
    let evidence_map = evidence_for_hash.as_object().cloned().unwrap_or_default();
    metadata_payload.insert(
        "evidenceHash".into(),
        json!(deps.evidence_hash.guard_evidence_hash(&evidence_map)),
    );

    let mut out = Map::new();
    out.insert("entityType".into(), json!("skill"));
    out.insert("source".into(), json!("local_indexed"));
    out.insert("provider".into(), json!("cisco-skill-scanner"));
    out.insert("status".into(), json!(status));
    out.insert("capturedAt".into(), normalized_captured_at);
    match safety {
        Some(s) => {
            out.insert("safety".into(), Value::Object(s));
        }
        None => {
            out.insert("safety".into(), Value::Null);
        }
    }
    out.insert(
        "findings".into(),
        Value::Array(findings.into_iter().map(Value::Object).collect()),
    );
    out.insert("metadata".into(), Value::Object(metadata_payload));
    Some(out)
}

/// `_local_mcp_security_for_artifact(...)`
fn _local_mcp_security_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    captured_at: &str,
    cisco_runs: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    if !(item_kind == "mcp_server" || item_kind == "mcp_tool")
        || !matches!(
            a_str(artifact, "artifact_type"),
            Some("mcp_server" | "mcp_tool")
        )
    {
        return None;
    }

    let trust_root = _trust_root_for_artifact(artifact, item_kind, workspace_dir)?;
    let run = cisco_runs.iter().find(|candidate| {
        a_str(candidate, "source") == Some("cisco-mcp-scanner")
            && _matches_mcp_cisco_run(artifact, candidate)
    })?;

    let scan_root = _cisco_run_target_path(run).unwrap_or_else(|| trust_root.clone());
    let targets_total = _local_mcp_targets_total(run);
    let mut extra = Map::new();
    extra.insert("targetsScanned".into(), json!(targets_total));
    let (status, normalized_captured_at, findings, safety, mut metadata_payload) =
        _cisco_local_security_payload(
            run,
            _local_mcp_security_findings(run, &scan_root),
            deps,
            captured_at,
            targets_total,
            Some(extra),
        );

    if let Some(run_metadata) = run_meta(run) {
        for key in ["analyzersUsed", "scanMode", "mode", "targetsScanned"] {
            if let Some(value) = run_metadata.get(key) {
                metadata_payload.insert(key.into(), value.clone());
            }
        }
    }

    let evidence_for_hash = json!({
        "capturedAt": normalized_captured_at,
        "entityType": item_kind,
        "findings": findings,
        "provider": "cisco-mcp-scanner",
        "safety": safety,
        "source": "local_indexed",
        "status": status,
    });
    let evidence_map = evidence_for_hash.as_object().cloned().unwrap_or_default();
    metadata_payload.insert(
        "evidenceHash".into(),
        json!(deps.evidence_hash.guard_evidence_hash(&evidence_map)),
    );

    let mut out = Map::new();
    out.insert("entityType".into(), json!(item_kind));
    out.insert("source".into(), json!("local_indexed"));
    out.insert("provider".into(), json!("cisco-mcp-scanner"));
    out.insert("status".into(), json!(status));
    out.insert("capturedAt".into(), normalized_captured_at);
    match safety {
        Some(s) => {
            out.insert("safety".into(), Value::Object(s));
        }
        None => {
            out.insert("safety".into(), Value::Null);
        }
    }
    out.insert(
        "findings".into(),
        Value::Array(findings.into_iter().map(Value::Object).collect()),
    );
    out.insert("metadata".into(), Value::Object(metadata_payload));
    Some(out)
}

/// `_local_mcp_security_findings(run, *, scan_root)`
fn _local_mcp_security_findings(
    run: &Map<String, Value>,
    scan_root: &Path,
) -> Vec<Map<String, Value>> {
    let resolved_scan_root = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());
    let mut results = Vec::new();
    for finding in run_findings(run) {
        let finding = match finding.as_object() {
            Some(f) => f,
            None => continue,
        };
        let file_path = finding_str(finding, "file_path");
        let relative_file = if let Some(file_path) = file_path {
            if file_path.trim().is_empty() {
                ".mcp.json".to_string()
            } else {
                let raw = PathBuf::from(file_path);
                let path = if raw.is_absolute() {
                    raw
                } else {
                    scan_root.join(raw)
                };
                if !_paths_related(scan_root, &path) {
                    continue;
                }
                let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
                resolved
                    .strip_prefix(&resolved_scan_root)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| {
                        path.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.to_string_lossy().into_owned())
                    })
            }
        } else {
            ".mcp.json".to_string()
        };
        let mut row = Map::new();
        row.insert(
            "ruleId".into(),
            json!(finding_str(finding, "rule_id").map_or("unknown", |s| s)),
        );
        row.insert(
            "severity".into(),
            json!(_local_skill_security_severity(
                finding.get("severity").and_then(Value::as_str)
            )),
        );
        row.insert("file".into(), json!(relative_file));
        row.insert(
            "message".into(),
            json!(_local_mcp_security_message(finding)),
        );
        results.push(row);
    }
    results
}

/// `_local_mcp_security_message(finding)`
fn _local_mcp_security_message(finding: &Map<String, Value>) -> String {
    if let Some(description) = finding_str(finding, "description") {
        let trimmed = description.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(title) = finding_str(finding, "title") {
        let trimmed = title.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "MCP security finding".to_string()
}

/// `_local_mcp_targets_total(run)`
fn _local_mcp_targets_total(run: &Map<String, Value>) -> i64 {
    if let Some(metadata) = run_meta(run) {
        if let Some(value) = metadata.get("targetsScanned").and_then(Value::as_i64) {
            return value.max(0);
        }
    }
    0
}

/// `_local_skill_security_findings(run, *, skill_root)`
fn _local_skill_security_findings(
    run: &Map<String, Value>,
    skill_root: &Path,
) -> Vec<Map<String, Value>> {
    let resolved_root = skill_root
        .canonicalize()
        .unwrap_or_else(|_| skill_root.to_path_buf());
    let mut results = Vec::new();
    for finding in run_findings(run) {
        let finding = match finding.as_object() {
            Some(f) => f,
            None => continue,
        };
        let file_path = finding_str(finding, "file_path");
        let relative_file = if let Some(file_path) = file_path {
            if file_path.trim().is_empty() {
                "SKILL.md".to_string()
            } else {
                let path = PathBuf::from(file_path);
                if !_paths_related(skill_root, &path) {
                    continue;
                }
                let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
                resolved
                    .strip_prefix(&resolved_root)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| {
                        path.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.to_string_lossy().into_owned())
                    })
            }
        } else {
            "SKILL.md".to_string()
        };
        let mut row = Map::new();
        row.insert(
            "ruleId".into(),
            json!(finding_str(finding, "rule_id").map_or("unknown", |s| s)),
        );
        row.insert(
            "severity".into(),
            json!(_local_skill_security_severity(
                finding.get("severity").and_then(Value::as_str)
            )),
        );
        row.insert("file".into(), json!(relative_file));
        row.insert(
            "message".into(),
            json!(_local_skill_security_message(finding)),
        );
        results.push(row);
    }
    results
}

/// `_local_skill_security_severity(severity)`
///
/// Python accepts `Severity` enum members or arbitrary strings; anything not a
/// known severity folds to `"low"`.
fn _local_skill_security_severity(severity: Option<&str>) -> String {
    match severity {
        Some("critical") => "critical".into(),
        Some("high") => "high".into(),
        Some("medium") => "medium".into(),
        Some("low") => "low".into(),
        _ => "low".into(),
    }
}

/// `_local_skill_security_message(finding)`
fn _local_skill_security_message(finding: &Map<String, Value>) -> String {
    if let Some(description) = finding_str(finding, "description") {
        let trimmed = description.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(title) = finding_str(finding, "title") {
        let trimmed = title.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "Skill security finding".to_string()
}

/// `_local_skill_security_label(score)`
fn _local_skill_security_label(score: i64) -> &'static str {
    if score >= 90 {
        "safe"
    } else if score >= 70 {
        "review"
    } else if score >= 45 {
        "caution"
    } else {
        "unsafe"
    }
}

/// `_local_skill_scripts_total(run)`
fn _local_skill_scripts_total(run: &Map<String, Value>) -> i64 {
    if let Some(metadata) = run_meta(run) {
        if let Some(value) = metadata.get("skillsScanned").and_then(Value::as_i64) {
            return value.max(0);
        }
    }
    0
}

/// `_metadata_string(metadata, key)`
pub fn _metadata_string<'a>(metadata: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    meta_str(metadata, key)
}

/// `_local_trust_domain_for_artifact(artifact, *, item_kind, metadata, workspace_dir)`
fn _local_trust_domain_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    metadata: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> Option<TrustDomainScore> {
    let trust_root = _trust_root_for_artifact(artifact, item_kind, workspace_dir)?;
    match item_kind {
        "plugin" => deps.scoring.build_plugin_domain(&trust_root),
        "skill" => {
            let options = ScanOptions::inventory_trust_scan_options();
            let context = deps
                .scoring
                .resolve_skill_security_context(&trust_root, &options);
            if let Some(domain) = deps.scoring.build_skill_domain(&trust_root, &context) {
                return Some(domain);
            }
            if a_str(artifact, "artifact_type") == Some("skill_file") {
                if let Some(config_path) = a_str(artifact, "config_path") {
                    if !config_path.trim().is_empty() {
                        let file_path = PathBuf::from(config_path);
                        if file_path.is_file() {
                            return deps.scoring.build_instruction_domain(
                                &file_path,
                                "skill_file",
                                "skill",
                            );
                        }
                    }
                }
            }
            None
        }
        "mcp_server" => deps.scoring.build_mcp_domain(&trust_root).or_else(|| {
            deps.scoring.build_mcp_surface_domain(
                a_str(artifact, "name"),
                a_str(artifact, "command"),
                a_str(artifact, "url"),
                a_str(artifact, "transport"),
            )
        }),
        "mcp_tool" => deps.scoring.build_mcp_surface_domain(
            Some(
                meta_str(metadata, "toolName")
                    .or_else(|| meta_str(metadata, "title"))
                    .unwrap_or(""),
            ),
            meta_str(metadata, "serverCommand"),
            meta_str(metadata, "serverUrl"),
            meta_str(metadata, "serverTransport"),
        ),
        _ if INSTRUCTION_BASELINE_ITEM_KINDS.contains(&item_kind) => {
            let role = metadata.get("instructionRole").and_then(Value::as_str);
            let normalized_role = role
                .filter(|r| !r.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("{item_kind}_config"));
            deps.scoring
                .build_instruction_domain(&trust_root, &normalized_role, item_kind)
        }
        _ => None,
    }
}

/// `_trust_root_for_artifact(artifact, *, item_kind, workspace_dir)`
fn _trust_root_for_artifact(
    artifact: &Map<String, Value>,
    item_kind: &str,
    workspace_dir: Option<&Path>,
) -> Option<PathBuf> {
    let config_path = a_str(artifact, "config_path")?;
    if config_path.trim().is_empty() {
        return None;
    }
    let path = PathBuf::from(config_path);
    if !path.exists() {
        return None;
    }

    if item_kind == "skill" {
        let skill_dir = if path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase() == "skill.md")
            .unwrap_or(false)
        {
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| path.clone())
        } else {
            path.clone()
        };
        for candidate in std::iter::once(skill_dir.clone())
            .chain(skill_dir.ancestors().skip(1).map(Path::to_path_buf))
        {
            if candidate
                .join(".codex-plugin")
                .join("plugin.json")
                .is_file()
            {
                return Some(candidate);
            }
            let name_is_skill_md = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase() == "skill.md")
                .unwrap_or(false);
            if !name_is_skill_md && candidate.join("SKILL.md").is_file() {
                return Some(candidate);
            }
            if a_str(artifact, "artifact_type") == Some("skill_file")
                && candidate
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_lowercase() == "skills")
                    .unwrap_or(false)
                && (candidate.join("README.md").is_file()
                    || candidate.join("SECURITY.md").is_file())
                && _skill_file_name_matches_root(artifact, &candidate)
            {
                return Some(candidate);
            }
            if workspace_dir.is_some()
                && candidate
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase() == "skills")
                    .unwrap_or(false)
                && candidate.join("SKILL.md").is_file()
            {
                return Some(candidate);
            }
        }
        return None;
    }

    if item_kind == "mcp_server" || item_kind == "mcp_tool" {
        let dir = if path.is_dir() {
            path.clone()
        } else {
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| path.clone())
        };
        return Some(dir);
    }

    Some(path)
}

/// `_skill_file_name_matches_root(artifact, root)`
fn _skill_file_name_matches_root(artifact: &Map<String, Value>, root: &Path) -> bool {
    let root_name = match root.file_name().map(|n| n.to_string_lossy().into_owned()) {
        Some(n) if !n.is_empty() => n,
        _ => return false,
    };
    let name = a_str(artifact, "name").unwrap_or("");
    if !name.is_empty() && (name == root_name || name.starts_with(&format!("{root_name}/"))) {
        return true;
    }
    let artifact_id = a_str(artifact, "artifact_id").unwrap_or("");
    !artifact_id.is_empty() && artifact_id.contains(&format!(":{root_name}:"))
}

/// `_trust_layer_from_domain(domain, *, captured_at)`
fn _trust_layer_from_domain(
    domain: &TrustDomainScore,
    deps: &TrustDeps<'_>,
    captured_at: &str,
) -> Map<String, Value> {
    let trust_components = _trust_components_from_domain(domain);
    let normalized_captured_at =
        normalize_inventory_datetime(&Value::String(captured_at.to_string()));
    let evidence =
        _local_baseline_evidence_payload(domain, &normalized_captured_at, &trust_components);
    let mut out = Map::new();
    out.insert("layerId".into(), json!("local_baseline"));
    out.insert("layerType".into(), json!("local_baseline"));
    out.insert("status".into(), json!("local"));
    out.insert("evidenceAuthority".into(), json!("device_claim"));
    out.insert("affectsV4Score".into(), json!(false));
    out.insert("trustScore".into(), json!(py_round(domain.score)));
    out.insert(
        "trustComponents".into(),
        Value::Array(trust_components.into_iter().map(Value::Object).collect()),
    );
    out.insert("capturedAt".into(), normalized_captured_at);
    out.insert(
        "provenance".into(),
        Value::Object(_local_claim_provenance("hol-guard-local-baseline")),
    );
    let metadata = json!({
        "scorer": "hol-guard-local",
        "specId": domain.spec_id,
        "specVersion": domain.spec_version,
        "trustDomain": domain.domain,
        "attestationStatus": "unsigned",
        "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "evidence": evidence,
        "evidenceHash": _trust_evidence_hash(&evidence, deps),
    });
    out.insert("metadata".into(), metadata);
    out
}

/// `_local_baseline_evidence_payload(domain, *, captured_at, trust_components)`
fn _local_baseline_evidence_payload(
    domain: &TrustDomainScore,
    captured_at: &Value,
    trust_components: &[Map<String, Value>],
) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert("source".into(), json!("hol-guard-local-baseline"));
    payload.insert("layerId".into(), json!("local_baseline"));
    payload.insert("label".into(), json!("Local baseline"));
    payload.insert("status".into(), json!("local"));
    payload.insert("capturedAt".into(), captured_at.clone());
    payload.insert("trustScore".into(), json!(py_round(domain.score)));
    payload.insert(
        "componentCount".into(),
        json!(trust_components.len() as i64),
    );
    payload.insert("specId".into(), json!(domain.spec_id));
    payload.insert("specVersion".into(), json!(domain.spec_version));
    payload.insert("profileId".into(), json!(domain.profile_id));
    payload.insert("profileVersion".into(), json!(domain.profile_version));
    payload.insert("trustDomain".into(), json!(domain.domain));
    payload
}

/// `_merge_trust_layers(existing, additions)`
fn _merge_trust_layers(
    existing: Option<&Vec<Value>>,
    additions: Vec<Map<String, Value>>,
) -> Vec<Value> {
    let mut merged: Vec<(String, Map<String, Value>)> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    if let Some(existing) = existing {
        for raw_layer in existing {
            if let Some(layer) = raw_layer.as_object() {
                if let Some(layer_type) = layer.get("layerType").and_then(Value::as_str) {
                    if !layer_type.is_empty() {
                        let key = layer_type.to_string();
                        if let Some(&i) = index.get(&key) {
                            merged[i] = (key, layer.clone());
                        } else {
                            index.insert(key.clone(), merged.len());
                            merged.push((key, layer.clone()));
                        }
                    }
                }
            }
        }
    }
    for layer in additions {
        if let Some(layer_type) = layer.get("layerType").and_then(Value::as_str) {
            if !layer_type.is_empty() {
                let key = layer_type.to_string();
                if let Some(&i) = index.get(&key) {
                    merged[i] = (key, layer);
                } else {
                    index.insert(key.clone(), merged.len());
                    merged.push((key, layer));
                }
            }
        }
    }
    merged.into_iter().map(|(_, l)| Value::Object(l)).collect()
}

/// `_local_claim_provenance(derivation)`
fn _local_claim_provenance(derivation: &str) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("origin".into(), json!("hol-guard-local"));
    out.insert("verificationStatus".into(), json!("locally_derived"));
    out.insert("derivation".into(), json!(derivation));
    out
}

/// `_cisco_trust_layers_for_artifact(artifact, *, item_kind, captured_at, cisco_runs, workspace_dir)`
fn _cisco_trust_layers_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    captured_at: &str,
    cisco_runs: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
) -> Vec<Map<String, Value>> {
    let mut layers = Vec::new();
    for run in cisco_runs {
        let source = a_str(run, "source");
        if source == Some("cisco-skill-scanner")
            && (item_kind == "skill" || item_kind == "plugin")
            && _matches_skill_cisco_run(artifact, item_kind, run, workspace_dir)
        {
            layers.push(_cisco_trust_layer(
                run,
                deps,
                captured_at,
                "cisco_skill_scanner",
                "cisco.skill.score",
                "Cisco Skill Scanner",
            ));
        }
        if source == Some("cisco-mcp-scanner")
            && (item_kind == "mcp_server" || item_kind == "mcp_tool")
            && _matches_mcp_cisco_run(artifact, run)
        {
            layers.push(_cisco_trust_layer(
                run,
                deps,
                captured_at,
                "cisco_mcp_scanner",
                "cisco.mcp.score",
                "Cisco MCP Scanner",
            ));
        }
    }
    layers
}

/// `_matches_skill_cisco_run(artifact, *, item_kind, run, workspace_dir)`
fn _matches_skill_cisco_run(
    artifact: &Map<String, Value>,
    item_kind: &str,
    run: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> bool {
    let trust_root = _trust_root_for_artifact(artifact, item_kind, workspace_dir);
    let run_target = match _cisco_run_target_path(run) {
        Some(t) => t,
        None => return false,
    };
    match trust_root {
        None => false,
        Some(trust_root) => _paths_related(&trust_root, &run_target),
    }
}

/// `_matches_mcp_cisco_run(artifact, *, run)`
fn _matches_mcp_cisco_run(artifact: &Map<String, Value>, run: &Map<String, Value>) -> bool {
    let run_config_path = _cisco_run_config_path(run);
    let config_path = match a_str(artifact, "config_path") {
        Some(c) if !c.trim().is_empty() => c,
        _ => return false,
    };
    let path = PathBuf::from(config_path);
    if let Some(run_config_path) = run_config_path {
        return _paths_related(&path, &run_config_path);
    }
    let run_target = match _cisco_run_target_path(run) {
        Some(t) => t,
        None => return false,
    };
    if path.is_file()
        && (_paths_related(&path, &run_target)
            || _paths_related(
                &path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path.clone()),
                &run_target,
            ))
    {
        return true;
    }
    _paths_related(&path, &run_target)
}

/// `_paths_related(left, right)`
fn _paths_related(left: &Path, right: &Path) -> bool {
    let left_resolved = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right_resolved = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    if left_resolved == right_resolved {
        return true;
    }
    left_resolved.starts_with(&right_resolved) || right_resolved.starts_with(&left_resolved)
}

/// `_cisco_run_config_path(run)`
fn _cisco_run_config_path(run: &Map<String, Value>) -> Option<PathBuf> {
    let metadata = run_meta(run)?;
    let config_path = metadata.get("configPath").and_then(Value::as_str)?;
    if config_path.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(config_path))
}

/// `_cisco_run_target_path(run)`
fn _cisco_run_target_path(run: &Map<String, Value>) -> Option<PathBuf> {
    if let Some(target) = a_str(run, "target_path") {
        if !target.trim().is_empty() {
            return Some(PathBuf::from(target));
        }
    }
    let metadata = run_meta(run)?;
    let target = metadata.get("targetPath").and_then(Value::as_str)?;
    if target.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(target))
}

/// `_cisco_trust_layer(run, *, captured_at, layer_id, component_id, label)`
fn _cisco_trust_layer(
    run: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    captured_at: &str,
    layer_id: &str,
    component_id: &str,
    label: &str,
) -> Map<String, Value> {
    let status = a_str(run, "status").map_or("unknown".to_string(), str::to_string);
    let message = a_str(run, "message").map_or("".to_string(), str::to_string);
    let severity_counts = _cisco_severity_counts(run);
    let analyzers_used = _cisco_analyzers_used(run);
    let trust_score: Option<i64> = if status == "enabled" {
        Some(_cisco_layer_score(&severity_counts, &analyzers_used))
    } else {
        None
    };
    let mut trust_components: Vec<Map<String, Value>> = Vec::new();
    if let Some(score) = trust_score {
        let component_status = if score < 40 {
            "critical"
        } else if score < 70 {
            "warning"
        } else {
            "positive"
        };
        let analyzer_confidence = (90 + (analyzers_used.len() as i64 - 1) * 5).min(99);
        let total_findings: i64 = severity_counts
            .values()
            .map(|v| v.as_i64().unwrap_or(0))
            .sum();
        let mut row = Map::new();
        row.insert("componentId".into(), json!(component_id));
        row.insert("confidence".into(), json!(analyzer_confidence));
        row.insert("label".into(), json!(label));
        row.insert("score".into(), json!(score));
        row.insert("status".into(), json!(component_status));
        row.insert(
            "summary".into(),
            json!(if !message.is_empty() {
                message.clone()
            } else {
                format!(
                    "{} completed with {} findings using {} analyzer(s).",
                    label,
                    total_findings,
                    analyzers_used.len()
                )
            }),
        );
        row.insert("weight".into(), json!(1.0));
        trust_components.push(row);
    }

    let run_metadata = run_meta(run);
    let mut safe_metadata = Map::new();
    safe_metadata.insert(
        "scannerSource".into(),
        json!(a_str(run, "source").map_or("unknown", |s| s)),
    );
    safe_metadata.insert("message".into(), json!(message));
    let total_findings: i64 = severity_counts
        .values()
        .map(|v| v.as_i64().unwrap_or(0))
        .sum();
    safe_metadata.insert("totalFindings".into(), json!(total_findings));
    safe_metadata.insert(
        "findingsBySeverity".into(),
        Value::Object(severity_counts.clone()),
    );
    if let Some(d) = run.get("duration_ms").and_then(Value::as_i64) {
        safe_metadata.insert("durationMs".into(), json!(d));
    }
    if let Some(run_metadata) = run_metadata {
        for key in [
            "analyzersUsed",
            "policyName",
            "scanMode",
            "mode",
            "targetsScanned",
            "skillsScanned",
            "skillsSkipped",
        ] {
            if let Some(value) = run_metadata.get(key) {
                safe_metadata.insert(key.into(), value.clone());
            }
        }
    }
    safe_metadata.insert("attestationStatus".into(), json!("unsigned"));
    safe_metadata.insert("evidenceAuthority".into(), json!("device_claim"));
    safe_metadata.insert("affectsV4Score".into(), json!(false));
    safe_metadata.insert(
        "evidenceSchemaVersion".into(),
        json!("guard-aibom-cisco-scanner-evidence.v1"),
    );
    let normalized_captured_at =
        normalize_inventory_datetime(&Value::String(captured_at.to_string()));
    let evidence_payload = _cisco_evidence_payload(
        layer_id,
        label,
        &status,
        &message,
        &normalized_captured_at,
        trust_score,
        &trust_components,
        &safe_metadata,
    );
    safe_metadata.insert("evidence".into(), Value::Object(evidence_payload.clone()));
    safe_metadata.insert(
        "evidenceHash".into(),
        json!(_trust_evidence_hash(&evidence_payload, deps)),
    );

    let mut out = Map::new();
    out.insert("layerId".into(), json!(layer_id));
    out.insert("layerType".into(), json!(layer_id));
    out.insert("status".into(), json!(status));
    out.insert("evidenceAuthority".into(), json!("device_claim"));
    out.insert("affectsV4Score".into(), json!(false));
    match trust_score {
        Some(s) => {
            out.insert("trustScore".into(), json!(s));
        }
        None => {
            out.insert("trustScore".into(), Value::Null);
        }
    }
    out.insert(
        "trustComponents".into(),
        Value::Array(trust_components.into_iter().map(Value::Object).collect()),
    );
    out.insert("capturedAt".into(), normalized_captured_at);
    let scanner_source = safe_metadata
        .get("scannerSource")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(layer_id);
    out.insert(
        "provenance".into(),
        Value::Object(_local_claim_provenance(scanner_source)),
    );
    out.insert("metadata".into(), Value::Object(safe_metadata));
    out
}

/// `_cisco_evidence_payload(*, layer_id, label, status, message, captured_at, trust_score, trust_components, metadata)`
#[allow(clippy::too_many_arguments)]
fn _cisco_evidence_payload(
    layer_id: &str,
    label: &str,
    status: &str,
    message: &str,
    captured_at: &Value,
    trust_score: Option<i64>,
    trust_components: &[Map<String, Value>],
    metadata: &Map<String, Value>,
) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert(
        "source".into(),
        metadata
            .get("scannerSource")
            .cloned()
            .unwrap_or_else(|| json!("unknown")),
    );
    payload.insert("layerId".into(), json!(layer_id));
    payload.insert("label".into(), json!(label));
    payload.insert("status".into(), json!(status));
    payload.insert("message".into(), json!(message));
    payload.insert("capturedAt".into(), captured_at.clone());
    match trust_score {
        Some(s) => {
            payload.insert("trustScore".into(), json!(s));
        }
        None => {
            payload.insert("trustScore".into(), Value::Null);
        }
    }
    payload.insert(
        "componentCount".into(),
        json!(trust_components.len() as i64),
    );
    payload.insert(
        "totalFindings".into(),
        metadata.get("totalFindings").cloned().unwrap_or(json!(0)),
    );
    payload.insert(
        "findingsBySeverity".into(),
        metadata
            .get("findingsBySeverity")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new())),
    );
    for key in [
        "analyzersUsed",
        "policyName",
        "scanMode",
        "mode",
        "targetsScanned",
        "skillsScanned",
        "skillsSkipped",
        "durationMs",
    ] {
        if let Some(value) = metadata.get(key) {
            payload.insert(key.into(), value.clone());
        }
    }
    payload
}

/// `_cisco_severity_counts(run)`
fn _cisco_severity_counts(run: &Map<String, Value>) -> Map<String, Value> {
    let mut counts = Map::new();
    for key in ["critical", "high", "medium", "low"] {
        counts.insert(key.into(), json!(0));
    }
    if let Some(metadata) = run_meta(run) {
        if let Some(raw_counts) = metadata
            .get("findingsBySeverity")
            .and_then(Value::as_object)
        {
            let mut resolved = Map::new();
            for key in ["critical", "high", "medium", "low"] {
                let value = raw_counts
                    .get(key)
                    .and_then(Value::as_i64)
                    .filter(|v| *v >= 0)
                    .unwrap_or(0);
                resolved.insert(key.into(), json!(value));
            }
            return resolved;
        }
    }
    for finding in run_findings(run) {
        let severity = finding
            .as_object()
            .and_then(|f| f.get("severity"))
            .and_then(|s| {
                s.as_str().map(str::to_string).or_else(|| {
                    // `Severity` enum mirrors carry `.value` → lowercase token.
                    s.get("value").and_then(Value::as_str).map(str::to_string)
                })
            });
        if let Some(severity) = severity {
            if let Some(entry) = counts.get_mut(&severity) {
                *entry = json!(entry.as_i64().unwrap_or(0) + 1);
            }
        }
    }
    counts
}

/// `_cisco_analyzers_used(run)`
fn _cisco_analyzers_used(run: &Map<String, Value>) -> Vec<String> {
    if let Some(metadata) = run_meta(run) {
        if let Some(raw) = metadata.get("analyzersUsed").and_then(Value::as_array) {
            return raw
                .iter()
                .filter_map(|a| {
                    // `str(a)` keeps only genuine JSON strings verbatim;
                    // non-strings serialize, but Python `str(a)` on non-str
                    // scalars is a display string — mirror strings only.
                    a.as_str().map(str::to_string)
                })
                .filter(|a| !a.is_empty())
                .collect();
        }
    }
    vec!["yara".to_string()]
}

/// `_cisco_layer_score(severity_counts, *, analyzers_used=("yara",))`
fn _cisco_layer_score(severity_counts: &Map<String, Value>, analyzers_used: &[String]) -> i64 {
    let get = |k: &str| severity_counts.get(k).and_then(Value::as_i64).unwrap_or(0);
    let raw_score =
        100 - (30 * get("critical") + 12 * get("high") + 4 * get("medium") + get("low"));
    let analyzer_count = analyzers_used.len();
    let ceiling = if analyzer_count >= 3 {
        100
    } else if analyzer_count == 2 {
        95
    } else {
        90
    };
    raw_score.max(0).min(ceiling)
}

/// `_trust_components_from_domain(domain)`
fn _trust_components_from_domain(domain: &TrustDomainScore) -> Vec<Map<String, Value>> {
    let mut components: Vec<Map<String, Value>> = Vec::new();
    for adapter in &domain.adapters {
        if !adapter.emitted {
            continue;
        }
        components.extend(_trust_components_from_adapter(adapter));
        if components.len() >= 32 {
            break;
        }
    }
    components.truncate(32);
    components
}

/// `_trust_components_from_adapter(adapter)`
fn _trust_components_from_adapter(adapter: &TrustAdapterScore) -> Vec<Map<String, Value>> {
    adapter
        .components
        .iter()
        .map(|component| _trust_component_row(adapter, component))
        .collect()
}

/// `_trust_component_row(adapter, component)`
fn _trust_component_row(
    adapter: &TrustAdapterScore,
    component: &TrustComponentScore,
) -> Map<String, Value> {
    let score = py_round(component.score);
    let status = if score < 40 {
        "critical"
    } else if score < 70 {
        "warning"
    } else {
        "positive"
    };
    let mut payload = Map::new();
    payload.insert(
        "componentId".into(),
        json!(format!("{}:{}", adapter.adapter_id, component.key)),
    );
    payload.insert("confidence".into(), json!(85));
    payload.insert("label".into(), json!(adapter.label));
    payload.insert("score".into(), json!(score));
    payload.insert("status".into(), json!(status));
    payload.insert("summary".into(), json!(component.rationale));
    payload.insert("weight".into(), json!(adapter.weight));
    if !component.evidence.is_empty() {
        payload.insert("evidence".into(), json!({ "lines": component.evidence }));
    }
    payload
}

/// `_trust_evidence_hash(payload)`
fn _trust_evidence_hash(payload: &Map<String, Value>, deps: &TrustDeps<'_>) -> String {
    deps.evidence_hash.guard_evidence_hash(payload)
}
