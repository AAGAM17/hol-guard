//! Canonical request/response contracts for the contained-execution resident
//! ops (RTM-020). Mirrors the pattern established by `package_authority.rs`.
//!
//! Coverage:
//!   * `try_execute_contained_node_command`   — `contained_node_execute`
//!   * `try_execute_contained_typescript`     — `contained_typescript_execute`
//!   * `try_execute_contained_package_script` — `contained_package_script_execute`
//!   * `try_execute_contained_workspace_write`— `contained_workspace_write_execute`
//!   * `execute_contained`                    — `contained_execute`
//!   * `contained_test_hook`                  — `contained_test_hook`
//!   * shim admin (`probe_intercepts`/`status`/`activate`/`repair`/
//!     `supported_managers`)                   — `shim_admin`
//!   * `probe_stdio_mcp_server`               — `mcp_stdio_probe`
//!
//! Every struct uses `deny_unknown_fields` so a stale resident cannot smuggle
//! new keys past the schema check.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Feature tokens advertised by `resident_capabilities`.
// ---------------------------------------------------------------------------

/// All six contained-execution ops share one feature token; the resident
/// advertises it only when the whole surface is live.
pub const CONTAINED_EXECUTION_FEATURE: &str = "contained-execution-v1";
/// Shim-admin multiplex op.
pub const SHIM_ADMIN_FEATURE: &str = "shim-admin-v1";
/// Stdio MCP probe op.
pub const MCP_STDIO_PROBE_FEATURE: &str = "mcp-stdio-probe-v1";

// ---------------------------------------------------------------------------
// Schema strings — one stable pair per op.
// ---------------------------------------------------------------------------

pub const CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA: &str = "guard-contained-node-execute-request.v1";
pub const CONTAINED_NODE_EXECUTE_RESULT_SCHEMA: &str = "guard-contained-node-execute-result.v1";
pub const CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA: &str =
    "guard-contained-typescript-execute-request.v1";
pub const CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA: &str =
    "guard-contained-typescript-execute-result.v1";
pub const CONTAINED_PACKAGE_SCRIPT_EXECUTE_REQUEST_SCHEMA: &str =
    "guard-contained-package-script-execute-request.v1";
pub const CONTAINED_PACKAGE_SCRIPT_EXECUTE_RESULT_SCHEMA: &str =
    "guard-contained-package-script-execute-result.v1";
pub const CONTAINED_WORKSPACE_WRITE_EXECUTE_REQUEST_SCHEMA: &str =
    "guard-contained-workspace-write-execute-request.v1";
pub const CONTAINED_WORKSPACE_WRITE_EXECUTE_RESULT_SCHEMA: &str =
    "guard-contained-workspace-write-execute-result.v1";
pub const CONTAINED_EXECUTE_REQUEST_SCHEMA: &str = "guard-contained-execute-request.v1";
pub const CONTAINED_EXECUTE_RESULT_SCHEMA: &str = "guard-contained-execute-result.v1";
pub const CONTAINED_TEST_HOOK_REQUEST_SCHEMA: &str = "guard-contained-test-hook-request.v1";
pub const CONTAINED_TEST_HOOK_RESULT_SCHEMA: &str = "guard-contained-test-hook-result.v1";
pub const SHIM_ADMIN_REQUEST_SCHEMA: &str = "guard-shim-admin-request.v1";
pub const SHIM_ADMIN_RESULT_SCHEMA: &str = "guard-shim-admin-result.v1";
pub const MCP_STDIO_PROBE_REQUEST_SCHEMA: &str = "guard-mcp-stdio-probe-request.v1";
pub const MCP_STDIO_PROBE_RESULT_SCHEMA: &str = "guard-mcp-stdio-probe-result.v1";

// ---------------------------------------------------------------------------
// Contained execution — per-op request/result pairs.
//
// `command_text` is the raw shell text the shim received. `manager` + `argv`
// carry the caller's pre-parsed invocation so the resident never has to
// `shlex`-join an argv back into text. `evidence` is the caller-built
// `LocalPackageExecutionEvidence` serialized via `to_dict`; the resident
// re-validates it against `argv`/`manager` before use.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedNodeExecuteRequestV1 {
    pub schema: String,
    pub workspace: String,
    pub manager: String,
    pub argv: Vec<String>,
    pub command_text: String,
    pub evidence: Option<Value>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedNodeExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedTypescriptExecuteRequestV1 {
    pub schema: String,
    pub workspace: String,
    pub manager: String,
    pub argv: Vec<String>,
    pub command_text: String,
    pub evidence: Option<Value>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedTypescriptExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedPackageScriptExecuteRequestV1 {
    pub schema: String,
    pub workspace: String,
    pub manager: String,
    pub argv: Vec<String>,
    pub command_text: String,
    /// Shim bin directory (PATH pin target); resident scrubs it from PATH.
    pub shim_directory: String,
    /// Scrubbed child environment (caller already stripped secret material).
    pub environment: BTreeMap<String, String>,
    pub timeout_seconds: u64,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedPackageScriptExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedWorkspaceWriteExecuteRequestV1 {
    pub schema: String,
    pub workspace: String,
    pub command_text: String,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedWorkspaceWriteExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedExecuteRequestV1 {
    pub schema: String,
    /// Canonical `ContainmentRequest` payload (carries `schema_version`).
    pub request: Value,
    /// Canonical `ContainmentPolicy` payload (carries `schema_version`).
    pub policy: Value,
    pub guard_home: String,
    pub run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedTestHookRequestV1 {
    pub schema: String,
    pub workspace: String,
    pub command_text: String,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedTestHookResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

// ---------------------------------------------------------------------------
// Shim admin — `subop` multiplexes the five admin ops over one feature gate.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShimAdminRequestV1 {
    pub schema: String,
    /// One of `probe_intercepts` | `status` | `activate` | `repair` |
    /// `supported_managers`.
    pub subop: String,
    /// `probe_intercepts`: explicit managers (None = all installed).
    pub managers: Option<Vec<String>>,
    /// `probe_intercepts`: workspace override.
    pub workspace_dir: Option<String>,
    /// `probe_intercepts`: allow probing when PATH is inactive.
    pub allow_inactive_path: Option<bool>,
    /// `probe_intercepts`: probe timeout seconds.
    pub timeout_seconds: Option<i64>,
    /// `status`/`activate`/`repair`: PATH override (None = process env).
    pub path_env: Option<String>,
    /// `activate`/`repair`: managers to install (None = all supported).
    pub install_managers: Option<Vec<String>>,
    /// `repair`: force reinstall even when integrity matches.
    pub repair: Option<bool>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShimAdminResultV1 {
    pub schema: String,
    /// `status`/`activate`/`repair`/`probe_intercepts` return an object;
    /// `supported_managers` returns an array. `None` when the subop
    /// could not run (fail-closed — caller falls back to Python).
    pub result: Option<Value>,
}

// ---------------------------------------------------------------------------
// MCP stdio probe
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStdioProbeRequestV1 {
    pub schema: String,
    /// Raw command text to probe.
    pub command_text: String,
    /// Working directory the shim observed.
    pub cwd: String,
    /// `HOME` for env resolution.
    pub home_dir: Option<String>,
    /// Caller-scrubbed extra env (already stripped of secret material).
    pub extra_env: Option<BTreeMap<String, String>>,
    /// Probe timeout in seconds (None = default).
    pub timeout_seconds: Option<f64>,
    /// Emit `reason` on failure when true; `None` result on false.
    pub report_failure: bool,
    /// Optional connection identity hash for attestation binding.
    pub connection_identity_hash: Option<String>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStdioProbeResultV1 {
    pub schema: String,
    /// `{"status": "ok", "tools": [...], ...}` on success; `{"status":
    /// "failed", "reason": ...}` on probe failure; `None` when the command is
    /// not an MCP launch (caller falls back to the legacy path).
    pub result: Option<Value>,
}
