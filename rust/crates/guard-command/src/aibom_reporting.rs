//! Port of `src/codex_plugin_scanner/guard/aibom_reporting.py` (RTM-027).
//!
//! AIBOM reporting helpers preserving the public CLI dependency seams.
//!
//! TODO(deps): the Python module lazily resolves `.aibom_cli` (`api`) for
//! `extract_aibom_metadata_extensions`, `_metadata_lookup_from_snapshots`,
//! `_redact_inventory_store_item`, `_store_row_config_path`,
//! `_store_only_artifact_metadata_extensions`, `_sync_summary`, and
//! `apply_local_trust_metadata`, and `.inventory_contract` for
//! `_redact_command_value`. Until those land they sit behind the
//! `ReportingApi` + `StoreApi` + `RedactionApi` seams. `HarnessContext` is
//! mirrored locally.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

/// `adapters.base.HarnessContext` mirror.
#[derive(Debug, Clone, Default)]
pub struct HarnessContext {
    pub home_dir: PathBuf,
    pub workspace_dir: Option<PathBuf>,
    pub guard_home: PathBuf,
    pub executable_overrides: Map<String, Value>,
    pub home_override_explicit: bool,
    pub workspace_override_explicit: bool,
}

/// Duck-typed inventory-item mirror used across reporting summaries.
/// Carries `item_kind`, `metadata`, `risk_level`, `drift_state`, and `item_id`.
#[derive(Debug, Clone, Default)]
pub struct InventoryItem {
    pub item_id: String,
    pub item_kind: String,
    pub metadata: Map<String, Value>,
    pub risk_level: String,
    pub drift_state: String,
}

/// `GuardAgentInventoryDrift` mirror (only `state` is read here).
#[derive(Debug, Clone, Default)]
pub struct InventoryDrift {
    pub state: String,
}

/// `GuardAgentInventorySnapshot` mirror — only the fields reporting consumes.
#[derive(Debug, Clone, Default)]
pub struct GuardAgentInventorySnapshot {
    pub agent_id: String,
    pub agent_type: String,
    pub items: Vec<InventoryItem>,
    pub findings: Vec<Value>,
    pub drift: Vec<InventoryDrift>,
    pub sources: Vec<Value>,
    pub redaction_report: Map<String, Value>,
}

// ---------------------------------------------------------------------------
// Seams.
// ---------------------------------------------------------------------------

/// `.inventory_contract` redaction seam.
pub trait RedactionApi {
    /// `redact_local_path(path, home_dir=)`
    fn redact_local_path(&self, path: &std::path::Path, home_dir: &std::path::Path) -> String;
    /// `_redact_command_value(value, home_dir, workspace_dir)`
    fn _redact_command_value(
        &self,
        value: &str,
        home_dir: &std::path::Path,
        workspace_dir: Option<&std::path::Path>,
    ) -> String;
}

/// `aibom_cli` + inventory-contract api seam.
pub trait ReportingApi {
    /// `extract_aibom_metadata_extensions(metadata)`
    fn extract_aibom_metadata_extensions(
        &self,
        metadata: &Map<String, Value>,
    ) -> Map<String, Value>;
    /// `apply_local_trust_metadata(artifact, *, captured_at, item_kind, metadata, workspace_dir)`
    fn apply_local_trust_metadata(
        &self,
        artifact: &Map<String, Value>,
        captured_at: &str,
        item_kind: &str,
        metadata: Map<String, Value>,
        workspace_dir: Option<&std::path::Path>,
    ) -> Map<String, Value>;
    /// `_sync_summary(store)` → `{synced: bool, synced_at: Option<str>, ..}`
    fn _sync_summary(&self, store: &dyn StoreApi) -> Map<String, Value>;
}

/// `store.list_inventory()` / cloud-profile seam.
pub trait StoreApi {
    /// `store.list_inventory()` → iterable of stored artifact rows.
    fn list_inventory(&self) -> Vec<Map<String, Value>>;
    /// `store.get_cloud_sync_profile()`
    fn get_cloud_sync_profile(&self) -> Option<Value>;
    /// `store.get_cloud_workspace_id()`
    fn get_cloud_workspace_id(&self) -> Option<Value>;
}

/// Bundle of reporting seams.
pub struct ReportingDeps<'a> {
    pub api: &'a dyn ReportingApi,
    pub redaction: &'a dyn RedactionApi,
    pub store: &'a dyn StoreApi,
}

// ---------------------------------------------------------------------------
// defmap order
// ---------------------------------------------------------------------------

/// `summarize_aibom_layers(snapshots, *, generated_at)`
///
/// Returns `(layer_summary, trust, drift)`.
pub fn summarize_aibom_layers(
    snapshots: &[GuardAgentInventorySnapshot],
    _deps: &ReportingDeps<'_>,
    generated_at: &str,
) -> (Map<String, Value>, Map<String, Value>, Map<String, Value>) {
    let mut counts: std::collections::BTreeMap<String, i64> = [
        ("instructions", 0),
        ("skills", 0),
        ("mcp", 0),
        ("plugins", 0),
        ("policies", 0),
        ("findings", 0),
        ("trust", 0),
        ("sources", 0),
        ("configSources", 0),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for snapshot in snapshots {
        *counts.get_mut("findings").unwrap() += snapshot.findings.len() as i64;
        *counts.get_mut("configSources").unwrap() += snapshot.sources.len() as i64;
        for item in &snapshot.items {
            match item.item_kind.as_str() {
                "overlay" | "prompt_pack" => *counts.get_mut("instructions").unwrap() += 1,
                "skill" => *counts.get_mut("skills").unwrap() += 1,
                "mcp_server" | "mcp_tool" => *counts.get_mut("mcp").unwrap() += 1,
                "plugin" | "daemon_plugin" => *counts.get_mut("plugins").unwrap() += 1,
                "policy" => *counts.get_mut("policies").unwrap() += 1,
                _ => {}
            }
            if item
                .metadata
                .get("trustResolution")
                .is_some_and(Value::is_object)
            {
                *counts.get_mut("trust").unwrap() += 1;
            }
            let source_links = item.metadata.get("sourceLinks");
            let source_of_truth = item.metadata.get("sourceOfTruth");
            if let Some(links) = source_links.and_then(Value::as_array) {
                if !links.is_empty() {
                    *counts.get_mut("sources").unwrap() += links.len() as i64;
                    continue;
                }
            }
            if source_of_truth.is_some_and(Value::is_object) {
                *counts.get_mut("sources").unwrap() += 1;
            }
        }
    }
    let drift = summarize_aibom_drift(snapshots);
    let trust = summarize_aibom_trust(snapshots);
    let mut layer_summary = Map::new();
    for (k, v) in &counts {
        layer_summary.insert(k.clone(), json!(v));
    }
    layer_summary.insert(
        "driftCount".into(),
        drift.get("total").cloned().unwrap_or(json!(0)),
    );
    layer_summary.insert(
        "highRiskCount".into(),
        drift.get("high_risk").cloned().unwrap_or(json!(0)),
    );
    layer_summary.insert(
        "lowTrustCount".into(),
        trust.get("low_trust").cloned().unwrap_or(json!(0)),
    );
    layer_summary.insert("generatedAt".into(), json!(generated_at));
    layer_summary.insert("staleSnapshot".into(), json!(false));
    (layer_summary, trust, drift)
}

/// `summarize_aibom_trust(snapshots)`
pub fn summarize_aibom_trust(snapshots: &[GuardAgentInventorySnapshot]) -> Map<String, Value> {
    let mut covered = 0i64;
    let mut eligible = 0i64;
    let mut low_trust = 0i64;
    let mut scores: Vec<i64> = Vec::new();
    for snapshot in snapshots {
        for item in &snapshot.items {
            if !matches!(item.item_kind.as_str(), "skill" | "plugin" | "mcp_server") {
                continue;
            }
            eligible += 1;
            let trust = item.metadata.get("trustResolution");
            let trust = match trust.and_then(Value::as_object) {
                Some(t) => t,
                None => continue,
            };
            covered += 1;
            if let Some(score) = trust.get("trustScore").and_then(Value::as_i64) {
                scores.push(score);
                if score < 70 {
                    low_trust += 1;
                }
            }
        }
    }
    let coverage_percent = if eligible != 0 {
        py_round_f64((covered as f64 / eligible as f64) * 100.0)
    } else {
        100
    };
    let average_score = if scores.is_empty() {
        Value::Null
    } else {
        json!(py_round_f64(
            scores.iter().sum::<i64>() as f64 / scores.len() as f64
        ))
    };
    let mut out = Map::new();
    out.insert("eligible".into(), json!(eligible));
    out.insert("covered".into(), json!(covered));
    out.insert("coverage_percent".into(), json!(coverage_percent));
    out.insert("low_trust".into(), json!(low_trust));
    out.insert("average_score".into(), average_score);
    out
}

/// `summarize_aibom_drift(snapshots)`
pub fn summarize_aibom_drift(snapshots: &[GuardAgentInventorySnapshot]) -> Map<String, Value> {
    let mut counts: std::collections::BTreeMap<String, i64> = [
        ("new", 0),
        ("changed", 0),
        ("removed", 0),
        ("unchanged", 0),
        ("high_risk", 0),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for snapshot in snapshots {
        for item in &snapshot.items {
            let state = item.drift_state.as_str();
            if let Some(entry) = counts.get_mut(state) {
                *entry += 1;
            }
            if matches!(item.risk_level.as_str(), "critical" | "high") {
                *counts.get_mut("high_risk").unwrap() += 1;
            }
        }
        for drift in &snapshot.drift {
            if let Some(entry) = counts.get_mut(drift.state.as_str()) {
                *entry += 1;
            }
        }
    }
    let total = counts["new"] + counts["changed"] + counts["removed"];
    let mut out = Map::new();
    for key in ["new", "changed", "removed", "unchanged", "high_risk"] {
        out.insert(key.into(), json!(counts[key]));
    }
    out.insert("total".into(), json!(total));
    out
}

/// `_metadata_lookup_from_snapshots(snapshots)`
pub fn _metadata_lookup_from_snapshots(
    snapshots: &[GuardAgentInventorySnapshot],
    deps: &ReportingDeps<'_>,
) -> Map<String, Value> {
    let mut lookup = Map::new();
    for snapshot in snapshots {
        let harness = snapshot.agent_type.clone();
        for item in &snapshot.items {
            let extensions = deps.api.extract_aibom_metadata_extensions(&item.metadata);
            if extensions.is_empty() {
                continue;
            }
            let key = format!("{}\u{1f}{}", harness, item.item_id);
            lookup.insert(key, Value::Object(extensions));
        }
    }
    lookup
}

/// `_artifact_rows_from_store(store, snapshots, *, context, generated_at)`
pub fn _artifact_rows_from_store(
    snapshots: &[GuardAgentInventorySnapshot],
    deps: &ReportingDeps<'_>,
    context: &HarnessContext,
    generated_at: &str,
) -> Vec<Map<String, Value>> {
    let metadata_by_artifact = _metadata_lookup_from_snapshots(snapshots, deps);
    let mut artifacts = Vec::new();
    for item in deps.store.list_inventory() {
        let trust_verdict = item
            .get("last_policy_action")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        let harness = item
            .get("harness")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        let artifact_id = item
            .get("artifact_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        let mut row = _redact_inventory_store_item(&item, deps, &context.home_dir);
        row.insert("trust_verdict".into(), json!(trust_verdict));
        let key = format!("{harness}\u{1f}{artifact_id}");
        let mut extensions = metadata_by_artifact
            .get(&key)
            .and_then(Value::as_object)
            .cloned();
        let config_path = if item.get("artifact_type").and_then(Value::as_str) == Some("skill_file")
        {
            _store_row_config_path(&item)
        } else {
            None
        };
        let config_path_exists = config_path.as_ref().map(|p| p.exists());
        if extensions.as_ref().is_none_or(Map::is_empty) {
            extensions = {
                let ext = _store_only_artifact_metadata_extensions(
                    &row,
                    deps,
                    context,
                    generated_at,
                    config_path.as_deref(),
                    config_path_exists,
                );
                if ext.is_empty() {
                    None
                } else {
                    Some(ext)
                }
            };
            if config_path_exists == Some(false) {
                row.insert("present".into(), json!(false));
            }
        }
        if let Some(ext) = extensions {
            for (k, v) in ext {
                row.insert(k, v);
            }
        }
        artifacts.push(row);
    }
    artifacts
}

/// `_store_row_config_path(row)`
fn _store_row_config_path(row: &Map<String, Value>) -> Option<PathBuf> {
    let raw = row.get("config_path").and_then(Value::as_str)?;
    if raw.trim().is_empty() {
        return None;
    }
    // `Path(...).expanduser()` — expand a leading `~` against `$HOME`.
    let expanded = if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(rest)
        } else {
            PathBuf::from(raw)
        }
    } else if raw == "~" {
        std::env::var("HOME").map_or_else(|_| PathBuf::from(raw), PathBuf::from)
    } else {
        PathBuf::from(raw)
    };
    Some(expanded)
}

/// `_store_only_artifact_metadata_extensions(row, *, context, generated_at, config_path, config_path_exists)`
fn _store_only_artifact_metadata_extensions(
    row: &Map<String, Value>,
    deps: &ReportingDeps<'_>,
    context: &HarnessContext,
    generated_at: &str,
    config_path: Option<&std::path::Path>,
    config_path_exists: Option<bool>,
) -> Map<String, Value> {
    let artifact_type = row
        .get("artifact_type")
        .and_then(Value::as_str)
        .unwrap_or("");
    if artifact_type != "skill_file" {
        return Map::new();
    }
    if config_path.is_none() || config_path_exists != Some(true) {
        return Map::new();
    }
    let config_path = config_path.unwrap();
    let mut artifact = Map::new();
    artifact.insert(
        "artifact_id".into(),
        json!(row.get("artifact_id").and_then(Value::as_str).unwrap_or("")),
    );
    artifact.insert("artifact_type".into(), json!(artifact_type));
    artifact.insert(
        "config_path".into(),
        json!(config_path.to_string_lossy().into_owned()),
    );
    artifact.insert(
        "name".into(),
        json!(row
            .get("artifact_name")
            .and_then(Value::as_str)
            .or_else(|| row.get("artifact_id").and_then(Value::as_str))
            .unwrap_or("skill_file")),
    );
    let mut metadata = Map::new();
    metadata.insert("artifactType".into(), json!(artifact_type));
    let enriched = deps.api.apply_local_trust_metadata(
        &artifact,
        generated_at,
        "skill",
        metadata,
        context.workspace_dir.as_deref(),
    );
    deps.api.extract_aibom_metadata_extensions(&enriched)
}

/// `_aggregate_redaction_report(snapshots)`
pub fn _aggregate_redaction_report(
    snapshots: &[GuardAgentInventorySnapshot],
) -> Map<String, Value> {
    let mut redacted_fields: BTreeSet<String> = BTreeSet::new();
    let mut raw_secrets = false;
    let mut symlink_items = 0i64;
    for snapshot in snapshots {
        let report = &snapshot.redaction_report;
        if report.get("rawSecretsIncluded").and_then(Value::as_bool) == Some(true) {
            raw_secrets = true;
        }
        if let Some(fields) = report.get("redactedFields").and_then(Value::as_array) {
            for field in fields {
                redacted_fields.insert(value_display(field));
            }
        }
        for item in &snapshot.items {
            let source_of_truth = item.metadata.get("sourceOfTruth");
            let source_links = item.metadata.get("sourceLinks");
            if source_of_truth.is_some_and(Value::is_object)
                || source_links
                    .and_then(Value::as_array)
                    .is_some_and(|l| !l.is_empty())
            {
                symlink_items += 1;
            }
        }
    }
    let mut out = Map::new();
    out.insert("rawValuesIncluded".into(), json!(raw_secrets));
    out.insert(
        "redactedFields".into(),
        json!(redacted_fields.into_iter().collect::<Vec<_>>()),
    );
    out.insert("symlinkItems".into(), json!(symlink_items));
    out.insert("snapshots".into(), json!(snapshots.len() as i64));
    out
}

/// `str(field)` — for non-string scalars Python renders `str(value)`.
fn value_display(value: &Value) -> String {
    match value.as_str() {
        Some(s) => s.to_string(),
        None => value.to_string(),
    }
}

/// `_redact_inventory_store_item(item, *, home_dir)`
fn _redact_inventory_store_item(
    item: &Map<String, Value>,
    deps: &ReportingDeps<'_>,
    home_dir: &std::path::Path,
) -> Map<String, Value> {
    let mut redacted = item.clone();
    if let Some(config_path) = item.get("config_path").and_then(Value::as_str) {
        if !config_path.is_empty() {
            let p = PathBuf::from(config_path);
            let redacted_path = deps.redaction.redact_local_path(&p, home_dir);
            redacted.insert("config_path".into(), json!(redacted_path));
        }
    }
    if let Some(launch_command) = item.get("launch_command").and_then(Value::as_str) {
        let redacted_cmd = deps
            .redaction
            ._redact_command_value(launch_command, home_dir, None);
        redacted.insert("launch_command".into(), json!(redacted_cmd));
    }
    redacted
}

/// `_aibom_connection_status(store)`
pub fn _aibom_connection_status(deps: &ReportingDeps<'_>) -> String {
    if deps.store.get_cloud_sync_profile().is_none() {
        return "not_connected".to_string();
    }
    if deps.store.get_cloud_workspace_id().is_none() {
        return "workspace_required".to_string();
    }
    let sync_summary = deps.api._sync_summary(deps.store);
    if sync_summary.get("synced").and_then(Value::as_bool) == Some(true)
        && sync_summary
            .get("synced_at")
            .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.is_empty()))
    {
        return "synced".to_string();
    }
    "sync_required".to_string()
}

/// `_markdown_table_cell(value)`
fn _markdown_table_cell(value: &Value) -> String {
    // `html.escape(" ".join(str(value).splitlines()), quote=False)` — collapse
    // newlines to spaces, then `&` `<` `>` escaping, then markdown punct escape.
    let raw = value_display(value);
    let joined = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let escaped = joined
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    static MD_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"([\\|`*_\[\]()!~])").expect("md cell re"));
    MD_RE.replace_all(&escaped, "\\$1").to_string()
}

/// `_render_aibom_markdown(payload)`
pub fn _render_aibom_markdown(payload: &Map<String, Value>) -> String {
    let layer_summary = payload.get("layer_summary");
    let trust_summary = payload.get("trust_summary");
    let mut lines: Vec<String> = vec![
        "# HOL Guard AIBOM".to_string(),
        String::new(),
        "## Layer summary".to_string(),
        String::new(),
    ];
    if let Some(layer_summary) = layer_summary.and_then(Value::as_object) {
        let get = |k: &str| layer_summary.get(k).cloned().unwrap_or(json!(0));
        for line in [
            format!("- Instructions: {}", value_display(&get("instructions"))),
            format!("- Skills: {}", value_display(&get("skills"))),
            format!("- MCP: {}", value_display(&get("mcp"))),
            format!("- Plugins: {}", value_display(&get("plugins"))),
            format!("- Policies: {}", value_display(&get("policies"))),
            format!("- Findings: {}", value_display(&get("findings"))),
            format!("- Trust: {}", value_display(&get("trust"))),
            format!("- Sources: {}", value_display(&get("sources"))),
            format!("- Drift: {}", value_display(&get("driftCount"))),
            String::new(),
        ] {
            lines.push(line);
        }
    }
    lines.push("## Artifacts".to_string());
    lines.push(String::new());
    lines.push("| Artifact | Harness | Type | Scope | Verdict | Present |".to_string());
    lines.push("| --- | --- | --- | --- | --- | --- |".to_string());
    if let Some(artifacts) = payload.get("artifacts").and_then(Value::as_array) {
        for item in artifacts {
            let item = match item.as_object() {
                Some(i) => i,
                None => continue,
            };
            let mut cells: Vec<String> = [
                "artifact_name",
                "harness",
                "artifact_type",
                "source_scope",
                "trust_verdict",
            ]
            .iter()
            .map(|field| {
                _markdown_table_cell(item.get(*field).unwrap_or(&Value::String(String::new())))
            })
            .collect();
            cells.push(
                if item
                    .get("present")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "yes"
                } else {
                    "no"
                }
                .to_string(),
            );
            lines.push(format!("| {} |", cells.join(" | ")));
        }
    }
    if let Some(trust_summary) = trust_summary.and_then(Value::as_object) {
        let get = |k: &str| trust_summary.get(k).cloned().unwrap_or(json!(0));
        lines.push(String::new());
        lines.push("## Trust coverage".to_string());
        lines.push(String::new());
        lines.push(format!(
            "- Covered: {} / {}",
            value_display(&get("covered")),
            value_display(&get("eligible"))
        ));
        lines.push(format!(
            "- Coverage: {}%",
            value_display(&get("coverage_percent"))
        ));
        lines.push(String::new());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// `round()` — Python banker's rounding for floats.
fn py_round_f64(value: f64) -> i64 {
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
