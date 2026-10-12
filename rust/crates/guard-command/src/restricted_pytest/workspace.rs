//! Native launch plan for `workspace-contained-v1`.
use super::*;
use crate::pretool::generic::workspace_redirects;
use crate::pretool::workspace_git_config::workspace_write_denials;
use crate::pretool::workspace_git_environment::GitVariables;
use crate::pretool::{command_shape, WORKSPACE_PROFILE};
use crate::{parse_command, CommandModelRequestV1};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    text: String,
    workspace: PathBuf,
    cwd: PathBuf,
    platform: String,
    backend_executable: Option<PathBuf>,
    search_path: String,
    home: Option<PathBuf>,
    /// The caller's exported Git configuration variables, by value.
    git_environment: BTreeMap<String, String>,
}

fn invalid(message: &str) -> RestrictedPytestError {
    RestrictedPytestError::new(PYTEST_INVALID_COMMAND_REASON_CODE, message)
}

/// The canonical workspace for `cwd`, or `None` for a missing directory or a
/// filesystem, home, temporary or credential-directory root.
pub(crate) fn workspace_admissible(cwd: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let resolved = cwd.canonicalize().ok()?;
    (resolved.is_dir() && !workspace_is_broad_or_sensitive_for_home(&resolved, home))
        .then_some(resolved)
}

fn prepare(input: &Input) -> Result<Value, RestrictedPytestError> {
    if input.platform != "darwin" {
        return Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "The workspace sandbox profile is only available on macOS.",
        ));
    }
    let (backend, backend_executable) = select_backend(
        &input.platform,
        input.backend_executable.as_deref(),
        &input.search_path,
    )?;
    let workspace =
        workspace_admissible(&input.workspace, input.home.as_deref()).ok_or_else(|| {
            RestrictedPytestError::new(
                PYTEST_INVALID_WORKSPACE_REASON_CODE,
                "The workspace is not an admissible sandbox workspace.",
            )
        })?;
    if input.cwd.canonicalize().ok().as_deref() != Some(workspace.as_path()) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "The workspace sandbox runs only from the workspace root.",
        ));
    }
    // Re-derive the decision from the exact bytes about to run. Literal-path
    // redirects are classified without them; the raw text still runs.
    let shape = match workspace_redirects::project(&input.text) {
        Some(projected) => {
            workspace_redirects::contained_shape(&input.text, &projected, &workspace)
        }
        None => {
            let model = parse_command(&CommandModelRequestV1 {
                command: input.text.clone(),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .map_err(|_| invalid("The command could not be parsed."))?;
            command_shape(&model, &workspace, Some(&input.text))
        }
    }
    .ok_or_else(|| invalid("The command is not eligible for the workspace sandbox."))?;
    let variables: GitVariables = input
        .git_environment
        .iter()
        .map(|(name, value)| (name.clone(), Some(value.clone())))
        .collect();
    let write_denials = workspace_write_denials(&workspace, input.home.as_deref(), &variables)
        .ok_or_else(|| invalid("The repository configuration is not eligible."))?;
    let text = shape
        .remainder
        .clone()
        .unwrap_or_else(|| input.text.clone());
    let (exec_roots, sandbox_path) =
        workspace_exec_roots(&input.search_path, input.home.as_deref(), &workspace);
    Ok(json!({
        "profile_version": WORKSPACE_PROFILE,
        "backend": backend,
        "backend_executable": backend_executable,
        "workspace": workspace,
        "cwd": workspace,
        "executable": "/bin/sh",
        "command": ["/bin/sh", "-c", text],
        "command_sha256": hex::encode(Sha256::digest(text.as_bytes())),
        "allowed_executables": [],
        "read_only_roots": [],
        "exec_roots": exec_roots,
        "write_denials": write_denials,
        "sandbox_path": sandbox_path,
        "bootstrap_git": shape.bootstrap,
        "prefix_command": shape.prefix,
        "denied_capabilities": [
            "network", "host-home-read", "host-secret-environment", "docker-socket",
            "workspace-credential-read", "git-execution-config-write", "privileged-operation"
        ],
    }))
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if operation != "prepare_workspace_contained" {
        return None;
    }
    let result = serde_json::from_value::<Input>(input.clone())
        .map_err(|_| invalid("Invalid restricted execution request."))
        .and_then(|input| prepare(&input));
    Some(match result {
        Ok(value) => json!({"value": value}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}
