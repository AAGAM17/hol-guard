//! Native command/effect-composition evaluator.
//!
//! `command_effect_decide` resident op (RTM-008). The contract lives in
//! `guard-contracts::command_effect`; this module owns the evaluator. The
//! factor/lattice/decision plane is ported verbatim in
//! `guard-command::command_evaluation::evaluate_command` (36/36 oracle
//! parity); the shell-read model (`shell_read_floor_factors` →
//! `assess_shell_reads`) is ported in `guard-command`. This op wires the
//! request fields into the typed evaluator:
//!   - `canonical_command` → `CanonicalCommandV1` → `CanonicalCommand`
//!   - `control_layers`    → wire layer dicts → `ExtensionControlLayer`
//!   - `control_snapshot`  → `NativeCommandControlBindingV1`
//!   - `workflow_authorization` → `GitHubWorkflowAuthorizationV1`
//!   - `read_factors`      → `shell_read_floor_factors(command_text, …)`
//!   - `write_redirect`    → any `>`/`>>`/`>|` redirect on the rich model

use std::path::PathBuf;

use guard_command::{
    canonical_command::CanonicalCommand,
    command_shell_read_factors::shell_read_floor_factors,
    github_workflow_authorization::GitHubWorkflowAuthorizationV1,
    native_command_catalog::packaged_command_catalog, parse_shell_command,
    CommandModelRequestV1, CanonicalCommandV1,
};
use guard_command::extension_control::{
    ControlLayerKind, ControlState, ControlTarget, ControlTargetKind,
    ExtensionControl, ExtensionControlLayer,
};
use guard_contracts::{
    CommandEffectRequestV1, CommandEffectResultV1, NativeCommandControlBindingV1,
    COMMAND_EFFECT_REQUEST_SCHEMA,
    COMMAND_EFFECT_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde::Deserialize;
use super::context_digest_json::write_canonical_json_with_limit;


fn request_digest(request: &CommandEffectRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_command_effect_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_command_effect_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

/// Wire `ExtensionControlLayer` (extension_control_authority `_layer_to_value`
/// :189-202): `controls` entries carry flattened `target_kind`/`target_id`/
/// `state` instead of the typed `ControlTarget`.
#[derive(Deserialize)]
struct WireControl {
    target_kind: ControlTargetKind,
    target_id: String,
    state: ControlState,
}

#[derive(Deserialize)]
struct WireControlLayer {
    schema_version: String,
    kind: ControlLayerKind,
    catalog_digest: String,
    global_lockdown: bool,
    controls: Vec<WireControl>,
}

fn control_layers_from_value(value: &serde_json::Value) -> Result<Vec<ExtensionControlLayer>, String> {
    let wire: Vec<WireControlLayer> =
        serde_json::from_value(value.clone()).map_err(|_| "native_command_effect_invalid_control_layers".to_owned())?;
    let mut layers = Vec::with_capacity(wire.len());
    for layer in wire {
        let mut controls = Vec::with_capacity(layer.controls.len());
        for control in layer.controls {
            let target = ControlTarget::new(control.target_kind, control.target_id)
                .map_err(|_| "native_command_effect_invalid_control_target".to_owned())?;
            controls.push(ExtensionControl { target, state: control.state });
        }
        let layer = ExtensionControlLayer {
            schema_version: layer.schema_version,
            kind: layer.kind,
            catalog_digest: layer.catalog_digest,
            global_lockdown: layer.global_lockdown,
            controls,
        };
        layer
            .validate()
            .map_err(|_| "native_command_effect_invalid_control_layer".to_owned())?;
        layers.push(layer);
    }
    Ok(layers)
}

pub(crate) fn evaluate_command_effect_request(
    request: &CommandEffectRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let result = evaluate(request);
    let (status, code, payload) = match result {
        Ok(evaluation) => ("ok".to_owned(), "ok".to_owned(), Some(evaluation.to_payload())),
        Err(code) => ("error".to_owned(), code, None),
    };
    let result = CommandEffectResultV1 {
        schema: COMMAND_EFFECT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    };
    crate::encode_response(&result)
}

fn evaluate(request: &CommandEffectRequestV1) -> Result<guard_command::CompositeCommandEvaluation, String> {
    if request.schema != COMMAND_EFFECT_REQUEST_SCHEMA {
        return Err("native_command_effect_schema_mismatch".to_owned());
    }
    let cwd = PathBuf::from(&request.cwd);
    let home_dir = PathBuf::from(&request.home_dir);
    // Rich parse for redirects (write_redirect) and segment model; the eval
    // `CanonicalCommand` projects the wire `canonical_command` when present,
    // else parses on its own.
    let rich = parse_shell_command(
        &request.command_text,
        Some(&cwd),
        Some(&home_dir),
        "posix",
        "shell_string",
        "guard-shell",
        false,
    );
    let write_redirect = rich.redirects.iter().any(|r| {
        let op = r.operator.trim_start_matches(|c: char| c.is_ascii_digit());
        op == ">" || op == ">>" || op == ">|"
    });
    let canonical_v1: CanonicalCommandV1 = match &request.canonical_command {
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|_| "native_command_effect_invalid_canonical_command".to_owned())?,
        None => {
            // Parse via the command-model op path (no request envelope here —
            // the fields the V1 needs are on the wire request).
            let model_request = CommandModelRequestV1 {
                command: request.command_text.clone(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "guard-shell".to_owned(),
            };
            guard_command::parse_command(&model_request)
                .map_err(|_| "native_command_effect_invalid_canonical_command".to_owned())?
        }
    };
    let canonical = CanonicalCommand::from_v1(&canonical_v1);
    let registry = packaged_command_catalog()
        .map_err(|_| "native_command_effect_catalog_unavailable".to_owned())?;
    let control_snapshot: NativeCommandControlBindingV1 = request
        .control_snapshot
        .as_ref()
        .ok_or_else(|| "native_command_effect_missing_control_snapshot".to_owned())
        .and_then(|v| {
            serde_json::from_value(v.clone())
                .map_err(|_| "native_command_effect_invalid_control_snapshot".to_owned())
        })?;
    let control_layers = control_layers_from_value(&request.control_layers)?;
    let workflow_authorization: Option<GitHubWorkflowAuthorizationV1> = request
        .workflow_authorization
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|_| "native_command_effect_invalid_workflow_authorization".to_owned())?;
    let read_factors = shell_read_floor_factors(
        &request.command_text,
        &canonical.security_identity,
        Some(&cwd),
        Some(&home_dir),
    );
    guard_command::evaluate_command(
        &canonical,
        &request.native_extension_evidence,
        &registry,
        &control_snapshot,
        &control_layers,
        request.compatibility_action_class.as_deref(),
        request.compatibility_reason.as_deref(),
        workflow_authorization.as_ref(),
        &read_factors,
        write_redirect,
    )
    .map_err(|code| format!("native_command_effect_{code}"))
}

/// CLI byte-path entry (`--stdin`).
#[allow(dead_code)]
pub(crate) fn evaluate_command_effect_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: CommandEffectRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_command_effect_invalid_json".to_owned())?;
    evaluate_command_effect_request(&request)
}
