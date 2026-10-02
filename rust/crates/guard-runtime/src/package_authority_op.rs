//! `PackageAuthority` resident ops — `PackageIntentParse`, `SupplyChainEval`,
//! and `PackageAuthorityDecide` dispatch evaluators plus the resident-side
//! seams they need.
//!
//! `ResidentSupplyChainStore` is the rusqlite-backed impl of
//! `guard_command::local_supply_chain::SupplyChainStore`, opening
//! `guard.db` under `guard_home` on demand and mirroring the Python
//! `GuardStore` SQL (`store_*.py`). `ResidentEvalDeps` satisfies the
//! `SupplyChainEvalDeps` seam traits, delegating to the ported
//! `guard_command` fns where they exist and returning the same fail-closed
//! `EvalError` the Python callers degrade on for the unported seams (HTTP
//! guard-sync, native archive inspection).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use guard_command::local_supply_chain::{
    GuardConfig, PolicyDecisionLookup, SupplyChainStore,
};
use guard_command::package_intent_common::{
    build_package_request_artifact, resolve_path_within_workspace, GuardArtifact,
};
use guard_command::package_intent_parser::parse_package_intent;
use guard_command::supply_chain_bundle;
use guard_command::supply_chain_package_eval::{
    evaluate_package_request_artifact, EvalError, EvalResult, GuardSyncRequest,
    GuardSyncRunnerApi, JsSemverApi, LockfileParseApi, LockfileParseResult,
    ManifestDepsApi, NativeArchiveApi, PackageIdentityApi, RestrictedArchiveApi,
    RestrictedArchiveDownloadResult, RestrictedArchiveFailure, RiskDetectApi, SpecifierSet,
    StoreExtrasApi, SupplyChainBundleApi, SupplyChainEvalDeps, Version, WorkspaceIoApi,
    EntitlementRefreshApi, ConfigLoaderApi,
    SupplyChainBundleResponse as EvalBundleResponse,
    CanonicalPackageIdentity as EvalCanonicalPackageIdentity,
};
use guard_command::supply_chain_package_identity;
use guard_contracts::{
    PackageAuthorityDecideRequestV1, PackageAuthorityDecideResultV1,
    PackageIntentParseRequestV1, PackageIntentParseResultV1, SupplyChainEvalRequestV1,
    SupplyChainEvalResultV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
// ---------------------------------------------------------------------------
// Shared result helpers
// ---------------------------------------------------------------------------

fn err_result(request_id: &str, request_sha256: &str, code: &str) -> Value {
    json!({
        "schema": PACKAGE_AUTHORITY_RESULT_SCHEMA,
        "request_id": request_id,
        "request_sha256": request_sha256,
        "status": "error",
        "code": code,
        "payload": Value::Null,
    })
}

fn eval_error_code(e: &EvalError) -> &'static str {
    match e {
        EvalError::Validation(_) => "validation",
        EvalError::NotFound(_) => "not_found",
        EvalError::Internal(_) => "internal",
        EvalError::HttpStatus(_, _) => "http_status",
    }
}

// ---------------------------------------------------------------------------
// ResidentSupplyChainStore — rusqlite impl of `SupplyChainStore`.
// ---------------------------------------------------------------------------

/// rusqlite-backed `SupplyChainStore`. Opens `store_path` per call so a
/// dropped connection never wedges the resident; SQL mirrors the Python
/// `store_*.py` bodies.
pub struct ResidentSupplyChainStore {
    store_path: PathBuf,
    guard_home: PathBuf,
}

impl ResidentSupplyChainStore {
    pub fn new(store_path: &Path, guard_home: &Path) -> Self {
        Self {
            store_path: store_path.to_path_buf(),
            guard_home: guard_home.to_path_buf(),
        }
    }

    fn conn(&self) -> Result<Connection, rusqlite::Error> {
        Connection::open(&self.store_path)
    }
}

impl SupplyChainStore for ResidentSupplyChainStore {
    fn guard_home(&self) -> &Path {
        &self.guard_home
    }

    fn get_cloud_sync_profile(&self) -> Option<Value> {
        // store_oauth.py: get_cloud_sync_profile — last `profile` row from
        // the sync-state table.
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT payload_json FROM guard_sync_state \
                 WHERE kind = 'profile' ORDER BY rowid DESC LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt.query([]).ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn get_cloud_workspace_id(&self) -> Option<String> {
        let profile = self.get_cloud_sync_profile()?;
        profile
            .get("workspace_id")
            .or_else(|| profile.get("workspaceId"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    fn get_cached_supply_chain_bundle(&self, workspace_id: &str) -> Option<Value> {
        // store_supply_chain.py: get_cached_supply_chain_bundle
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT bundle_json FROM guard_supply_chain_bundles \
                 WHERE workspace_id = ?1 ORDER BY fetched_at DESC LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt.query([workspace_id]).ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn get_sync_payload(&self, key: &str) -> Option<Value> {
        // store_cloud_events.py: get_sync_payload — KV sync payloads table.
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare("SELECT payload_json FROM guard_sync_payloads WHERE key = ?1 LIMIT 1")
            .ok()?;
        let mut rows = stmt.query([key]).ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn set_sync_payload(&self, key: &str, payload: &Value) {
        if let Ok(conn) = self.conn() {
            let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
            let _ = conn.execute(
                "INSERT INTO guard_sync_payloads (key, payload_json) \
                 VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET payload_json = excluded.payload_json",
                rusqlite::params![key, body],
            );
        }
    }

    fn list_cached_advisories(&self) -> Vec<Value> {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match conn
            .prepare("SELECT advisory_json FROM guard_advisories ORDER BY advisory_id")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.flatten()
            .filter_map(|raw| serde_json::from_str(&raw).ok())
            .collect()
    }

    fn list_managed_installs(&self) -> Vec<Value> {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match conn.prepare(
            "SELECT install_json FROM guard_managed_installs ORDER BY install_id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.flatten()
            .filter_map(|raw| serde_json::from_str(&raw).ok())
            .collect()
    }

    fn record_latest_guard_connect_sync_result(
        &self,
        status: &str,
        milestone: &str,
        now: &str,
        reason: Option<&str>,
    ) {
        // store_oauth.py: record_latest_guard_connect_sync_result
        if let Ok(conn) = self.conn() {
            let payload = json!({
                "status": status,
                "milestone": milestone,
                "recorded_at": now,
                "reason": reason,
            });
            let _ = conn.execute(
                "INSERT INTO guard_oauth_metadata (key, value_json) \
                 VALUES ('latest_guard_connect_sync_result', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
                rusqlite::params![payload.to_string()],
            );
        }
    }

    fn get_approval_request(&self, request_id: &str) -> Option<Value> {
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT request_json FROM guard_approval_requests \
                 WHERE request_id = ?1 LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt.query([request_id]).ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn resolve_policy_decision_lookup(
        &self,
        _harness: &str,
        artifact_id: &str,
        _artifact_hash: Option<&str>,
        _workspace: &str,
        _publisher: Option<&str>,
        _now: &str,
        _consume_one_shot: bool,
    ) -> PolicyDecisionLookup {
        // store_policy.py: resolve_policy_decision_lookup — look up the
        // materialized decision row for the artifact.
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return PolicyDecisionLookup::default(),
        };
        let decision = conn
            .query_row(
                "SELECT decision_json FROM guard_policy_decisions \
                 WHERE artifact_id = ?1 ORDER BY id DESC LIMIT 1",
                [artifact_id],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok());
        PolicyDecisionLookup {
            decision,
            ignored_local_integrity: None,
        }
    }

    fn approval_reuse_diagnostic(
        &self,
        _harness: &str,
        _artifact_id: &str,
        _artifact_hash: &str,
        _workspace: &str,
        _publisher: Option<&str>,
        _now: &str,
    ) -> (Option<String>, Option<String>) {
        (None, None)
    }

    fn approval_reuse_claim_disposition(&self, decision: &Value) -> Option<String> {
        crate::claim_reuse::approval_reuse_claim_disposition(decision).map(str::to_owned)
    }

    fn claim_approval_reuse_decision(&self, decision: &Value, now: &str) -> bool {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return false,
        };
        crate::claim_reuse::claim_approval_reuse_decisions(
            &conn,
            std::slice::from_ref(decision),
            Some(now),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_or(false)
    }

    fn claim_local_once_approval(
        &self,
        approval_id: &str,
        claimed_at: &str,
        _expected_decision: &Value,
    ) -> bool {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return false,
        };
        crate::local_once_store::claim_local_once_approval_locked(
            &conn,
            "",
            Some(approval_id),
            None,
            None,
            None,
            claimed_at,
            None,
            None,
        )
        .map(|v| v.is_some())
        .unwrap_or(false)
    }

    fn add_receipt(&self, receipt: &Value) {
        if let Ok(conn) = self.conn() {
            let body = serde_json::to_string(receipt).unwrap_or_else(|_| "{}".into());
            let receipt_id = receipt
                .get("receipt_id")
                .or_else(|| receipt.get("receiptId"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let _ = conn.execute(
                "INSERT INTO guard_receipts (receipt_id, receipt_json) VALUES (?1, ?2)",
                rusqlite::params![receipt_id, body],
            );
        }
    }

    fn set_receipt_action_envelope(&self, receipt_id: &str, metadata: &Value) {
        if let Ok(conn) = self.conn() {
            let body = serde_json::to_string(metadata).unwrap_or_else(|_| "{}".into());
            let _ = conn.execute(
                "UPDATE guard_receipts SET action_envelope_json = ?2 WHERE receipt_id = ?1",
                rusqlite::params![receipt_id, body],
            );
        }
    }

    fn add_event(&self, kind: &str, payload: &Value, now: &str) {
        if let Ok(conn) = self.conn() {
            let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
            let _ = conn.execute(
                "INSERT INTO guard_events (kind, payload_json, created_at) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![kind, body, now],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ResidentEvalDeps — concrete `SupplyChainEvalDeps` impls.
// ---------------------------------------------------------------------------

/// Fails closed — resident has no HTTP transport for guard-sync; eval falls
/// back to local-only exactly like Python `GuardSyncNotConfiguredError`.
struct ResidentGuardSyncRunner;

impl GuardSyncRunnerApi for ResidentGuardSyncRunner {
    fn resolve_guard_sync_auth_context(
        &self,
        _store: &dyn SupplyChainStore,
        _allow_primary_repair: bool,
        _force_refresh: bool,
    ) -> EvalResult<Map<String, Value>> {
        Err(EvalError::NotFound(
            "guard sync auth context unavailable in resident".into(),
        ))
    }
    fn validate_guard_sync_url(&self, sync_url: &str, _issuer: Option<&str>) -> EvalResult<String> {
        Ok(sync_url.trim_end_matches('/').to_owned())
    }
    fn guard_sync_request(
        &self,
        _auth_context: &Value,
        request_url: &str,
        method: &str,
        data: Option<&[u8]>,
        _extra_headers: Option<&Map<String, Value>>,
        dpop_nonce: Option<&str>,
    ) -> EvalResult<GuardSyncRequest> {
        Ok(GuardSyncRequest {
            url: request_url.to_owned(),
            method: method.to_owned(),
            headers: BTreeMap::new(),
            body: data.map(|d| d.to_vec()),
            dpop_nonce: dpop_nonce.map(str::to_owned),
        })
    }
    fn urlopen_json_with_timeout_retry(
        &self,
        _request: &GuardSyncRequest,
        _timeout_seconds: u64,
        _retry_timeout_seconds: u64,
    ) -> EvalResult<Map<String, Value>> {
        Err(EvalError::Internal(
            "resident guard-sync transport unavailable".into(),
        ))
    }
    fn is_timeout_error(&self, _error: &(dyn std::error::Error + 'static)) -> bool {
        false
    }
    fn normalized_receipts_sync_url(&self, sync_url: &str) -> String {
        sync_url.to_owned()
    }
}

/// Lockfile parse seam — delegates to the ported
/// `package_manifest_diff::parse_manifest_dependencies` for formats with a
/// native parser; everything else returns `incomplete` like Python's
/// `incomplete_lockfile_result` degrade path.
struct ResidentLockfileParse;

impl LockfileParseApi for ResidentLockfileParse {
    fn collect_lockfile_parse_results(
        &self,
        workspace_dir: Option<&Path>,
        lockfile_paths: Option<&Value>,
        budget_ms: f64,
        parse_text_result: &dyn Fn(&str, &[u8]) -> LockfileParseResult,
    ) -> Vec<LockfileParseResult> {
        let mut results = Vec::new();
        let Some(ws) = workspace_dir else {
            return results;
        };
        let Some(Value::Array(paths)) = lockfile_paths else {
            return results;
        };
        for rel in paths.iter().filter_map(Value::as_str) {
            let Some(resolved) = resolve_path_within_workspace(ws, rel) else {
                results.push(self.incomplete_lockfile_result(
                    rel,
                    b"",
                    "path outside workspace",
                    budget_ms,
                    0.0,
                ));
                continue;
            };
            match std::fs::read(&resolved) {
                Ok(bytes) => results.push(parse_text_result(rel, &bytes)),
                Err(e) => results.push(self.incomplete_lockfile_result(
                    rel,
                    b"",
                    &format!("read failed: {e}"),
                    budget_ms,
                    0.0,
                )),
            }
        }
        results
    }

    fn parse_lockfile_with_budget(
        &self,
        path: &str,
        source_text: &[u8],
        budget_seconds: f64,
    ) -> LockfileParseResult {
        let text = String::from_utf8_lossy(source_text);
        let budget_ms = (budget_seconds * 1000.0).max(1.0);
        let map = guard_command::package_manifest_diff::parse_manifest_dependencies(
            path,
            &text,
            text.len(),
            budget_ms as u64,
        );
        if map.is_empty() {
            return self.incomplete_lockfile_result(
                path,
                source_text,
                "no parser produced entries",
                budget_ms,
                0.0,
            );
        }
        let entries = map
            .into_iter()
            .map(
                |(dependency_path, version)| {
                    guard_command::supply_chain_package_eval::LockfileDependencyEntry {
                        dependency_path,
                        package_name: String::new(),
                        version,
                        direct: false,
                    }
                },
            )
            .collect();
        LockfileParseResult {
            entries,
            complete: true,
            format: Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned(),
            source_hash: guard_policy_snapshot::digest_bytes(source_text),
            elapsed_ms: 0.0,
            budget_ms,
            warnings: Vec::new(),
            error_reason: None,
            parser_version: "resident-lockfile-parse-v1".into(),
        }
    }

    fn incomplete_lockfile_result(
        &self,
        path: &str,
        source: &[u8],
        error_reason: &str,
        budget_ms: f64,
        elapsed_ms: f64,
    ) -> LockfileParseResult {
        LockfileParseResult {
            entries: Vec::new(),
            complete: false,
            format: Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned(),
            source_hash: if source.is_empty() {
                String::new()
            } else {
                guard_policy_snapshot::digest_bytes(source)
            },
            elapsed_ms,
            budget_ms,
            warnings: Vec::new(),
            error_reason: Some(error_reason.to_owned()),
            parser_version: "resident-lockfile-parse-v1".into(),
        }
    }
}

/// Bundle seam — delegates to `guard_command::supply_chain_bundle` loaders.
struct ResidentBundle;

impl SupplyChainBundleApi for ResidentBundle {
    fn load_supply_chain_bundle_response(
        &self,
        raw_json: &Value,
    ) -> EvalResult<EvalBundleResponse> {
        let resp = supply_chain_bundle::load_supply_chain_bundle_response(raw_json)
            .map_err(|e| EvalError::Validation(e.to_string()))?;
        Ok(EvalBundleResponse {
            bundle: resp.bundle.to_dict().as_object().cloned().unwrap_or_default(),
            signed_bundle: resp.signed_bundle,
            payload_hash: resp.payload_hash,
            signature: resp.signature,
            signature_algorithm: resp.signature_algorithm,
            verification_keys: resp
                .verification_keys
                .iter()
                .filter_map(|k| k.to_dict().as_object().cloned())
                .collect(),
        })
    }

    fn check_supply_chain_bundle_freshness(
        &self,
        bundle: &Map<String, Value>,
        now: Option<f64>,
    ) -> EvalResult<()> {
        let parsed = supply_chain_bundle::SupplyChainBundle::from_dict(bundle)
            .map_err(|e| EvalError::Validation(e.to_string()))?;
        supply_chain_bundle::check_supply_chain_bundle_freshness(&parsed, now)
            .map_err(|e| EvalError::Validation(e.to_string()))
    }

    fn evaluate_cached_supply_chain_bundle(
        &self,
        response: &EvalBundleResponse,
        package_name: &str,
        package_version: Option<&str>,
        ecosystem: Option<&str>,
        now: Option<f64>,
    ) -> EvalResult<Map<String, Value>> {
        let raw = response_to_bundle_json(response);
        let typed = supply_chain_bundle::load_supply_chain_bundle_response(&raw)
            .map_err(|e| EvalError::Validation(e.to_string()))?;
        let decision = supply_chain_bundle::evaluate_cached_supply_chain_bundle(
            &typed,
            package_name,
            package_version,
            ecosystem,
            now,
        );
        Ok(json!({
            "action": decision.action,
            "bundle_version": decision.bundle_version,
            "matched_advisory_ids": decision.matched_advisory_ids,
            "reason": decision.reason,
            "stale": decision.stale,
            "recommended_fix_version": decision.recommended_fix_version,
            "emergency_deny": decision.emergency_deny,
        })
        .as_object()
        .cloned()
        .unwrap_or_default())
    }

    fn supply_chain_bundle_meta(
        &self,
        bundle_payload: &Map<String, Value>,
    ) -> EvalResult<BTreeMap<String, String>> {
        let parsed = supply_chain_bundle::SupplyChainBundle::from_dict(bundle_payload)
            .map_err(|e| EvalError::Validation(e.to_string()))?;
        let mut out = BTreeMap::new();
        out.insert("bundle_version".into(), parsed.bundle_version);
        out.insert("feed_snapshot_hash".into(), parsed.feed_snapshot_hash);
        out.insert("policy_hash".into(), parsed.policy_hash);
        out.insert("scoring_version".into(), parsed.scoring_version);
        Ok(out)
    }
}

fn response_to_bundle_json(response: &EvalBundleResponse) -> Value {
    json!({
        "bundle": Value::Object(response.signed_bundle.clone()),
        "payloadHash": response.payload_hash,
        "signature": response.signature,
        "signatureAlgorithm": response.signature_algorithm,
        "verificationKeys": response
            .verification_keys
            .iter()
            .cloned()
            .map(Value::Object)
            .collect::<Vec<Value>>(),
    })
}

/// `packaging`-style PEP-440 + npm-selector semver seam — faithful subset
/// matching the shape Python's `packaging`/`js_semver` expose.
struct ResidentSemver;

impl ResidentSemver {
    fn parse_version(value: &str) -> EvalResult<Version> {
        let normalized = value.trim().to_owned();
        if normalized.is_empty() {
            return Err(EvalError::Validation("empty version".into()));
        }
        let release_part = normalized.split(['-', '+']).next().unwrap_or(normalized.as_str());
        let mut release: Vec<u64> = Vec::new();
        for seg in release_part.split('.') {
            if seg.is_empty() {
                continue;
            }
            release.push(seg.parse::<u64>().unwrap_or(0));
        }
        if release.is_empty() {
            release.push(0);
        }
        Ok(Version { normalized, release })
    }

    fn compare_release(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
        let len = a.len().max(b.len());
        for i in 0..len {
            match a.get(i).copied().unwrap_or(0).cmp(&b.get(i).copied().unwrap_or(0)) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }

    fn satisfies_specifier(version: &Version, spec: &str) -> bool {
        let spec = spec.trim();
        if spec.is_empty() || spec == "*" {
            return true;
        }
        for clause in spec.split(',') {
            let clause = clause.trim();
            if clause.is_empty() {
                continue;
            }
            let (op, rhs) = if let Some(rest) = clause.strip_prefix(">=") {
                (">=", rest)
            } else if let Some(rest) = clause.strip_prefix("<=") {
                ("<=", rest)
            } else if let Some(rest) = clause.strip_prefix("==") {
                ("==", rest)
            } else if let Some(rest) = clause.strip_prefix("!=") {
                ("!=", rest)
            } else if let Some(rest) = clause.strip_prefix('>') {
                (">", rest)
            } else if let Some(rest) = clause.strip_prefix('<') {
                ("<", rest)
            } else if let Some(rest) = clause.strip_prefix('~') {
                ("~=", rest)
            } else if let Some(rest) = clause.strip_prefix('^') {
                ("^", rest)
            } else {
                ("==", clause)
            };
            let rhs_v = match Self::parse_version(rhs.trim()) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let ord = Self::compare_release(&version.release, &rhs_v.release);
            let ok = match op {
                "==" => ord == std::cmp::Ordering::Equal,
                "!=" => ord != std::cmp::Ordering::Equal,
                ">=" => ord != std::cmp::Ordering::Less,
                "<=" => ord != std::cmp::Ordering::Greater,
                ">" => ord == std::cmp::Ordering::Greater,
                "<" => ord == std::cmp::Ordering::Less,
                "~=" | "^" => {
                    if ord == std::cmp::Ordering::Less {
                        false
                    } else {
                        let mut upper = rhs_v.release.clone();
                        if op == "^"
                            && upper.first().copied().unwrap_or(0) == 0
                            && upper.len() > 1
                        {
                            upper[1] += 1;
                            upper.truncate(2);
                        } else {
                            upper[0] = upper.first().copied().unwrap_or(0) + 1;
                            upper.truncate(1);
                        }
                        Self::compare_release(&version.release, &upper)
                            == std::cmp::Ordering::Less
                    }
                }
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

impl JsSemverApi for ResidentSemver {
    fn specifier_set(&self, range: &str) -> EvalResult<SpecifierSet> {
        if range.trim().is_empty() {
            return Err(EvalError::Validation("empty specifier".into()));
        }
        Ok(SpecifierSet {
            normalized: range.trim().to_owned(),
        })
    }
    fn version(&self, value: &str) -> EvalResult<Version> {
        Self::parse_version(value)
    }
    fn version_in_specifier_set(&self, version: &Version, set: &SpecifierSet) -> bool {
        Self::satisfies_specifier(version, &set.normalized)
    }
    fn highest_js_version_for_selector(
        &self,
        versions: &[String],
        selector: &str,
    ) -> Option<String> {
        let mut best: Option<Version> = None;
        let mut best_raw: Option<String> = None;
        for candidate in versions {
            let Ok(v) = Self::parse_version(candidate) else {
                continue;
            };
            if !Self::satisfies_specifier(&v, selector) {
                continue;
            }
            let better = match &best {
                None => true,
                Some(b) => {
                    Self::compare_release(&v.release, &b.release)
                        == std::cmp::Ordering::Greater
                }
            };
            if better {
                best = Some(v);
                best_raw = Some(candidate.clone());
            }
        }
        best_raw
    }
    fn version_matches_js_selector(&self, version: &str, selector: &str) -> bool {
        match Self::parse_version(version) {
            Ok(v) => Self::satisfies_specifier(&v, selector),
            Err(_) => false,
        }
    }
}

/// Risk-detection seam — `detect_supply_chain_risk` is not yet ported; return
/// an empty signal list so eval continues with zero risk contribution.
struct ResidentRisk;

impl RiskDetectApi for ResidentRisk {
    fn detect_supply_chain_risk(
        &self,
        _content: &str,
        _file_path: Option<&str>,
    ) -> EvalResult<Vec<Map<String, Value>>> {
        Ok(Vec::new())
    }
    fn evaluate_supply_chain_risk_sync(
        &self,
        _content: &str,
        _file_path: Option<&str>,
    ) -> EvalResult<Vec<Map<String, Value>>> {
        Ok(Vec::new())
    }
}

/// Manifest seam — delegates to `package_manifest_diff::parse_manifest_dependencies`.
struct ResidentManifestDeps;

impl ManifestDepsApi for ResidentManifestDeps {
    fn evaluation_targets(
        &self,
        artifact: &GuardArtifact,
        workspace_dir: Option<&Path>,
        explicit_targets: &[Map<String, Value>],
        include_locked: bool,
    ) -> Vec<Map<String, Value>> {
        let mut out: Vec<Map<String, Value>> = explicit_targets.to_vec();
        if !include_locked {
            return out;
        }
        let Some(ws) = workspace_dir else {
            return out;
        };
        for key in ["manifest_paths", "lockfile_paths"] {
            let Some(Value::Array(paths)) = artifact.metadata.get(key).cloned() else {
                continue;
            };
            for rel in paths.iter().filter_map(Value::as_str) {
                let Some(resolved) = resolve_path_within_workspace(ws, rel) else {
                    continue;
                };
                let Ok(text) = std::fs::read_to_string(&resolved) else {
                    continue;
                };
                let deps = guard_command::package_manifest_diff::parse_manifest_dependencies(
                    rel,
                    &text,
                    text.len(),
                    4000,
                );
                for (name, version) in deps {
                    out.push(
                        json!({
                            "ecosystem": ecosystem_for_path(rel),
                            "name": name,
                            "package_name": name,
                            "version": version,
                            "source": rel,
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    );
                }
            }
        }
        out
    }

    fn dependency_map_for_path(
        &self,
        path: &str,
        text: &str,
        _deadline: f64,
    ) -> EvalResult<BTreeMap<String, String>> {
        Ok(guard_command::package_manifest_diff::parse_manifest_dependencies(
            path,
            text,
            text.len(),
            4000,
        ))
    }

    fn parse_manifest_dependencies(
        &self,
        path: &str,
        text: &str,
        byte_limit: usize,
        deadline_ms: u64,
    ) -> BTreeMap<String, String> {
        guard_command::package_manifest_diff::parse_manifest_dependencies(
            path,
            text,
            byte_limit,
            deadline_ms,
        )
    }
}

fn ecosystem_for_path(path: &str) -> &'static str {
    let name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    match name {
        "package.json" | "package-lock.json" | "npm-shrinkwrap.json" | "yarn.lock"
        | "pnpm-lock.yaml" | "bun.lock" | "bun.lockb" => "npm",
        "requirements.txt" | "Pipfile" | "Pipfile.lock" | "poetry.lock"
        | "pyproject.toml" | "uv.lock" | "setup.py" => "pypi",
        "Cargo.toml" | "Cargo.lock" => "cargo",
        "Gemfile" | "Gemfile.lock" => "rubygems",
        "composer.json" | "composer.lock" => "packagist",
        "go.mod" | "go.sum" => "go",
        _ => "",
    }
}

/// Package-identity seam — delegates to `supply_chain_package_identity` fns.
struct ResidentPackageIdentity;

fn to_eval_identity(
    ident: supply_chain_package_identity::CanonicalPackageIdentity,
) -> EvalCanonicalPackageIdentity {
    EvalCanonicalPackageIdentity {
        ecosystem: ident.ecosystem,
        namespace: ident.namespace,
        name: ident.name,
        version: ident.version,
    }
}

impl PackageIdentityApi for ResidentPackageIdentity {
    fn canonical_package_identity(
        &self,
        ecosystem: &str,
        namespace: Option<&str>,
        name: &str,
        version: &str,
    ) -> EvalResult<EvalCanonicalPackageIdentity> {
        supply_chain_package_identity::canonical_package_identity(
            ecosystem, namespace, name, version,
        )
        .map(to_eval_identity)
        .map_err(|e| EvalError::Validation(e.to_string()))
    }
    fn parse_package_identity(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> EvalResult<EvalCanonicalPackageIdentity> {
        supply_chain_package_identity::parse_package_identity(ecosystem, package_name, version)
            .map(to_eval_identity)
            .map_err(|e| EvalError::Validation(e.to_string()))
    }
    fn normalize_ecosystem(&self, ecosystem: &str) -> EvalResult<String> {
        supply_chain_package_identity::normalize_ecosystem(ecosystem)
            .map_err(|e| EvalError::Validation(e.to_string()))
    }
    fn normalize_qualified_package_name(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> EvalResult<String> {
        supply_chain_package_identity::normalize_qualified_package_name(ecosystem, package_name)
            .map_err(|e| EvalError::Validation(e.to_string()))
    }
}

/// Restricted-archive seam — no HTTP transport in the resident; return the
/// policy Failure the Python download produces when the fetch is denied.
struct ResidentRestrictedArchive;

impl RestrictedArchiveApi for ResidentRestrictedArchive {
    fn download_restricted_archive(
        &self,
        source_url: &str,
        _max_bytes: u64,
        _max_redirects: u32,
        _timeout_seconds: f64,
        _temp_dir: Option<&Path>,
    ) -> EvalResult<RestrictedArchiveDownloadResult> {
        Ok(RestrictedArchiveDownloadResult::Failure(
            RestrictedArchiveFailure {
                code: "external_archive_transport_unavailable".into(),
                message: format!(
                    "Restricted archive download is unavailable in the resident: {source_url}"
                ),
            },
        ))
    }
}

/// Native-archive inspection seam — delegated scanner not yet resident;
/// report unavailable so eval marks the archive uninspected.
struct ResidentNativeArchive;

impl NativeArchiveApi for ResidentNativeArchive {
    #[allow(clippy::too_many_arguments)]
    fn inspect_archive_native(
        &self,
        _path: &Path,
        _expected_sha256: &str,
        _state_dir: &Path,
        _timeout_seconds: f64,
        _max_archive_bytes: u64,
        _max_files: u64,
        _max_expanded_bytes: u64,
        _max_member_bytes: u64,
        _max_package_json_bytes: u64,
        _max_memory_bytes: u64,
        _max_decompression_ratio: f64,
        _max_nested_archives: u64,
        _max_path_depth: u64,
    ) -> EvalResult<Map<String, Value>> {
        Err(EvalError::Internal(
            "native archive inspection unavailable in resident".into(),
        ))
    }
}

/// Workspace IO — thin wrappers over `resolve_path_within_workspace` + `fs`.
struct ResidentWorkspaceIo;

impl WorkspaceIoApi for ResidentWorkspaceIo {
    fn read_text(&self, workspace_dir: &Path, relative_path: &str) -> Option<String> {
        std::fs::read_to_string(resolve_path_within_workspace(workspace_dir, relative_path)?).ok()
    }
    fn read_bytes_within_workspace(
        &self,
        workspace_dir: &Path,
        relative_path: &str,
    ) -> Option<Vec<u8>> {
        std::fs::read(resolve_path_within_workspace(workspace_dir, relative_path)?).ok()
    }
}

/// Eval-cache / evidence / OAuth-health extras on the same `guard.db` conn.
struct ResidentStoreExtras {
    store_path: PathBuf,
}

impl ResidentStoreExtras {
    fn conn(&self) -> Result<Connection, rusqlite::Error> {
        Connection::open(&self.store_path)
    }
}

impl StoreExtrasApi for ResidentStoreExtras {
    fn get_cached_supply_chain_evaluation(
        &self,
        workspace_id: &str,
        package_intent_hash: &str,
        feed_snapshot_hash: &str,
        policy_hash: &str,
        scoring_version: &str,
        bundle_version: &str,
    ) -> Option<Map<String, Value>> {
        // store_supply_chain.py: get_cached_supply_chain_evaluation
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT evaluation_json FROM guard_supply_chain_eval_cache \
                 WHERE workspace_id = ?1 AND package_intent_hash = ?2 \
                 AND feed_snapshot_hash = ?3 AND policy_hash = ?4 \
                 AND scoring_version = ?5 AND bundle_version = ?6 LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt
            .query(rusqlite::params![
                workspace_id,
                package_intent_hash,
                feed_snapshot_hash,
                policy_hash,
                scoring_version,
                bundle_version
            ])
            .ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        match serde_json::from_str::<Value>(&raw).ok()? {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

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
    ) {
        if let Ok(conn) = self.conn() {
            let body = serde_json::to_string(&Value::Object(decision.clone()))
                .unwrap_or_else(|_| "{}".into());
            let _ = conn.execute(
                "INSERT INTO guard_supply_chain_eval_cache \
                 (workspace_id, package_intent_hash, feed_snapshot_hash, \
                  policy_hash, scoring_version, bundle_version, evaluation_json, cached_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                 ON CONFLICT(workspace_id, package_intent_hash, feed_snapshot_hash, \
                             policy_hash, scoring_version, bundle_version) \
                 DO UPDATE SET evaluation_json = excluded.evaluation_json, \
                               cached_at = excluded.cached_at",
                rusqlite::params![
                    workspace_id,
                    package_intent_hash,
                    feed_snapshot_hash,
                    policy_hash,
                    scoring_version,
                    bundle_version,
                    body,
                    now
                ],
            );
        }
    }

    fn add_evidence(&self, record: &Map<String, Value>) {
        // store_evidence.py: add_evidence — append-only insert.
        if let Ok(conn) = self.conn() {
            let kind = record
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("package_eval");
            let key = record.get("key").and_then(Value::as_str).unwrap_or("");
            let now = record
                .get("created_at")
                .or_else(|| record.get("now"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let body = serde_json::to_string(&Value::Object(record.clone()))
                .unwrap_or_else(|_| "{}".into());
            let _ = conn.execute(
                "INSERT INTO guard_evidence (kind, key, payload_json, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![kind, key, body, now],
            );
        }
    }

    fn get_oauth_local_credential_health(&self) -> Map<String, Value> {
        // store_oauth.py: get_oauth_local_credential_health
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return Map::new(),
        };
        let raw: Option<String> = conn
            .query_row(
                "SELECT value_json FROM guard_oauth_metadata \
                 WHERE key = 'local_credential_health' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();
        match raw.and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        }
    }
}

/// Entitlement-refresh seam — `resolve_package_firewall_entitlement_with_refresh`
/// takes the full deps aggregate not yet assembled here; fail closed.
struct ResidentEntitlementRefresh;

impl EntitlementRefreshApi for ResidentEntitlementRefresh {
    fn resolve_package_firewall_entitlement_with_refresh(
        &self,
        _store: &dyn SupplyChainStore,
    ) -> EvalResult<Map<String, Value>> {
        Err(EvalError::Internal(
            "entitlement refresh unavailable in resident".into(),
        ))
    }
}

/// Config seam — `load_guard_config` is not ported; error → callers substitute
/// `GuardConfig::default()`, matching Python's missing-config path.
struct ResidentConfigLoader;

impl ConfigLoaderApi for ResidentConfigLoader {
    fn load_guard_config(
        &self,
        _guard_home: &Path,
        _workspace: Option<&Path>,
        _require_canonical_workspace: bool,
    ) -> EvalResult<GuardConfig> {
        Err(EvalError::Internal(
            "guard config loader unavailable in resident".into(),
        ))
    }
}

/// Aggregate `SupplyChainEvalDeps` wired to the resident impls.
pub struct ResidentEvalDeps {
    guard_sync: ResidentGuardSyncRunner,
    lockfile: ResidentLockfileParse,
    bundle: ResidentBundle,
    semver: ResidentSemver,
    risk: ResidentRisk,
    manifest: ResidentManifestDeps,
    identity: ResidentPackageIdentity,
    archive: ResidentRestrictedArchive,
    native_archive: ResidentNativeArchive,
    workspace_io: ResidentWorkspaceIo,
    store_extras: ResidentStoreExtras,
    entitlement: ResidentEntitlementRefresh,
    config: ResidentConfigLoader,
}

impl ResidentEvalDeps {
    pub fn new(store_path: &Path) -> Self {
        Self {
            guard_sync: ResidentGuardSyncRunner,
            lockfile: ResidentLockfileParse,
            bundle: ResidentBundle,
            semver: ResidentSemver,
            risk: ResidentRisk,
            manifest: ResidentManifestDeps,
            identity: ResidentPackageIdentity,
            archive: ResidentRestrictedArchive,
            native_archive: ResidentNativeArchive,
            workspace_io: ResidentWorkspaceIo,
            store_extras: ResidentStoreExtras {
                store_path: store_path.to_path_buf(),
            },
            entitlement: ResidentEntitlementRefresh,
            config: ResidentConfigLoader,
        }
    }

    pub fn as_deps(&self) -> SupplyChainEvalDeps<'_> {
        SupplyChainEvalDeps {
            guard_sync: &self.guard_sync,
            lockfile: &self.lockfile,
            bundle: &self.bundle,
            semver: &self.semver,
            risk: &self.risk,
            manifest: &self.manifest,
            identity: &self.identity,
            archive: &self.archive,
            native_archive: &self.native_archive,
            workspace_io: &self.workspace_io,
            store_extras: &self.store_extras,
            entitlement: &self.entitlement,
            config: &self.config,
        }
    }
}

// ---------------------------------------------------------------------------
// Op evaluators
// ---------------------------------------------------------------------------

fn request_digest<T: serde::Serialize>(request: &T) -> Result<String, String> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_package_authority_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_package_authority_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

/// `PackageIntentParse` — `parse_package_intent` port.
pub(crate) fn evaluate_package_intent_parse(
    request: &PackageIntentParseRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    let workspace = request.workspace.as_deref().map(Path::new);
    let home = request.home_dir.as_deref().map(Path::new);
    let intent = parse_package_intent(&request.command_text, workspace, home, None, None);
    let payload = intent.map(|i| i.to_dict()).unwrap_or(Value::Null);
    let result = PackageIntentParseResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(payload),
    };
    crate::encode_response(&result)
}

/// `SupplyChainEval` — `evaluate_package_request_artifact` port.
pub(crate) fn evaluate_supply_chain_eval(
    request: &SupplyChainEvalRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    let store_path = PathBuf::from(&request.store_path);
    let guard_home = PathBuf::from(&request.guard_home);
    let store = ResidentSupplyChainStore::new(&store_path, &guard_home);
    let deps_holder = ResidentEvalDeps::new(&store_path);
    let deps = deps_holder.as_deps();
    let artifact = artifact_from_value(&request.artifact);
    let workspace = request.workspace_dir.as_deref().map(Path::new);
    let result = match evaluate_package_request_artifact(
        &artifact,
        &store,
        &deps,
        workspace,
        request.now.as_deref(),
        request.external_archive_network_authorized,
        request.retain_external_archive_blob,
    ) {
        Ok(eval) => SupplyChainEvalResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "ok".to_owned(),
            code: "ok".to_owned(),
            payload: Some(eval.to_dict()),
        },
        Err(e) => SupplyChainEvalResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "error".to_owned(),
            code: format!("native_supply_chain_eval_failed:{}", eval_error_code(&e)),
            payload: None,
        },
    };
    crate::encode_response(&result)
}

/// `PackageAuthorityDecide` — parse → artifact → eval in one call.
pub(crate) fn evaluate_package_authority_decide(
    request: &PackageAuthorityDecideRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    let workspace = request.workspace_dir.as_deref().map(Path::new);
    let intent = match parse_package_intent(&request.command_text, workspace, None, None, None) {
        Some(i) => i,
        None => {
            let result = PackageAuthorityDecideResultV1 {
                schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256,
                status: "ok".to_owned(),
                code: "no_intent".to_owned(),
                payload: None,
            };
            return crate::encode_response(&result);
        }
    };
    let artifact =
        build_package_request_artifact(&request.artifact_kind, &intent, "", &request.artifact_type);
    let store_path = PathBuf::from(&request.store_path);
    let guard_home = PathBuf::from(&request.guard_home);
    let store = ResidentSupplyChainStore::new(&store_path, &guard_home);
    let deps_holder = ResidentEvalDeps::new(&store_path);
    let deps = deps_holder.as_deps();
    let result = match evaluate_package_request_artifact(
        &artifact,
        &store,
        &deps,
        workspace,
        request.now.as_deref(),
        request.external_archive_network_authorized,
        request.retain_external_archive_blob,
    ) {
        Ok(eval) => PackageAuthorityDecideResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "ok".to_owned(),
            code: "ok".to_owned(),
            payload: Some(json!({
                "intent": intent.to_dict(),
                "artifact": artifact.to_dict(),
                "evaluation": eval.to_dict(),
                "policy_action": eval.policy_action,
                "decision": eval.decision,
            })),
        },
        Err(e) => PackageAuthorityDecideResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "error".to_owned(),
            code: format!(
                "native_package_authority_decide_failed:{}",
                eval_error_code(&e)
            ),
            payload: None,
        },
    };
    crate::encode_response(&result)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Reconstruct a `GuardArtifact` from the wire dict (`{artifact_id, name,
/// harness, artifact_type, source_scope, config_path, command, args, url,
/// transport, publisher, metadata}`).
fn artifact_from_value(v: &Value) -> GuardArtifact {
    let get_str = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let get_opt = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|s| !s.is_empty())
    };
    GuardArtifact {
        artifact_id: get_str("artifact_id"),
        name: get_str("name"),
        harness: get_str("harness"),
        artifact_type: get_str("artifact_type"),
        source_scope: get_str("source_scope"),
        config_path: get_str("config_path"),
        command: get_opt("command"),
        args: v
            .get("args")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        url: get_opt("url"),
        transport: get_opt("transport"),
        publisher: get_opt("publisher"),
        metadata: v.get("metadata").cloned().unwrap_or(Value::Null),
        runtime_private_metadata: Value::Null,
    }
}
