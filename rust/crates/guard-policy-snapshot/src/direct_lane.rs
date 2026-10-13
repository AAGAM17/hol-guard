//! Freshness binding carried by a policy push for the direct resident hook lane.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DIRECT_LANE_MAX_WORKSPACES: usize = 512;
pub const DIRECT_LANE_MAX_HARNESS_POSTURES: usize = 32;
pub const DIRECT_LANE_HARNESS_POSTURES: &[&str] = &["protected", "extra_careful", "watch"];
pub const DIRECT_LANE_MAX_INPUTS: usize = 256;
pub const DIRECT_LANE_MAX_PATH_BYTES: usize = 4096;
pub const DIRECT_LANE_MAX_SINK_ARGS: usize = 8;
pub const DIRECT_LANE_MAX_SINK_ARG_BYTES: usize = 16_384;
pub const DIRECT_LANE_MAX_INTEGRITY_KEY_B64_BYTES: usize = 2048;
pub const DIRECT_LANE_MAX_INTEGRITY_KEY_ID_BYTES: usize = 256;

/// Publisher-observed state that a pushed snapshot was compiled against.
///
/// `workspaces` are the workspace roots whose overlays the snapshot settled.
/// `inputs` are the non-database policy files the publisher watched, each
/// with the stat identity observed before compilation, or `None` when the
/// file was absent. The resident re-observes the inputs before using the
/// snapshot without the daemon.
///
/// The remaining fields carry daemon state that the snapshot itself does not:
/// the daemon's home directory, the per-harness posture overrides it binds to
/// the same ACK, and whether any custom command-line block rule existed when
/// the snapshot was compiled. A direct hook defers whenever one is absent.
/// `evidence_drain` says the daemon drains the evidence of direct answers;
/// without it the resident answers nothing directly.
/// `contained_sink_command` is the argv prefix that starts the daemon's
/// Guard CLI, which the daemon puts in front of a contained execution
/// rewrite; without it such a rewrite stays with the daemon.
/// `integrity_key_b64` and `integrity_key_id` are the policy-integrity key the
/// daemon signs and verifies hook authority state with, as the daemon sends
/// it on every hook authority state request. Without both, a hook that needs
/// that state stays with the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneBindingV1 {
    pub workspaces: Vec<String>,
    pub inputs: Vec<DirectLaneInputV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_postures: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_cli_block_rules: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_drain: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contained_sink_command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_b64: Option<DirectLaneSecretV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_id: Option<String>,
}

/// Key material whose `Debug` output never shows the value.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct DirectLaneSecretV1(pub String);

impl std::fmt::Debug for DirectLaneSecretV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DirectLaneSecretV1(..)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneInputV1 {
    pub path: String,
    pub stat: Option<DirectLaneStatV1>,
}

/// The `(mtime_ns, size, ino, ctime_ns)` identity of a followed `stat`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneStatV1 {
    pub mtime_ns: i64,
    pub size: u64,
    pub ino: u64,
    pub ctime_ns: i64,
}

impl DirectLaneBindingV1 {
    pub fn is_valid(&self) -> bool {
        if self.workspaces.len() > DIRECT_LANE_MAX_WORKSPACES
            || self.inputs.len() > DIRECT_LANE_MAX_INPUTS
        {
            return false;
        }
        let mut seen = std::collections::BTreeSet::new();
        for workspace in &self.workspaces {
            if !direct_lane_path_valid(workspace) || !seen.insert(workspace.as_str()) {
                return false;
            }
        }
        seen.clear();
        for input in &self.inputs {
            if !direct_lane_path_valid(&input.path) || !seen.insert(input.path.as_str()) {
                return false;
            }
        }
        if self
            .home_dir
            .as_deref()
            .is_some_and(|home_dir| !direct_lane_path_valid(home_dir))
        {
            return false;
        }
        if let Some(postures) = &self.harness_postures {
            if postures.len() > DIRECT_LANE_MAX_HARNESS_POSTURES
                || postures.iter().any(|(harness, posture)| {
                    harness.is_empty()
                        || harness.len() > 64
                        || !DIRECT_LANE_HARNESS_POSTURES.contains(&posture.as_str())
                })
            {
                return false;
            }
        }
        if let Some(command) = &self.contained_sink_command {
            if command.is_empty()
                || command.len() > DIRECT_LANE_MAX_SINK_ARGS
                || !direct_lane_path_valid(&command[0])
                || command.iter().any(|argument| {
                    argument.is_empty()
                        || argument.len() > DIRECT_LANE_MAX_SINK_ARG_BYTES
                        || argument.contains('\0')
                })
            {
                return false;
            }
        }
        match (&self.integrity_key_b64, &self.integrity_key_id) {
            (None, None) => {}
            (Some(key), Some(key_id)) => {
                if key.0.is_empty()
                    || key.0.len() > DIRECT_LANE_MAX_INTEGRITY_KEY_B64_BYTES
                    || !key
                        .0
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                    || key_id.is_empty()
                    || key_id.len() > DIRECT_LANE_MAX_INTEGRITY_KEY_ID_BYTES
                    || key_id.chars().any(char::is_control)
                {
                    return false;
                }
            }
            _ => return false,
        }
        true
    }
}

fn direct_lane_path_valid(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= DIRECT_LANE_MAX_PATH_BYTES
        && !path.contains('\0')
        && std::path::Path::new(path).is_absolute()
}
