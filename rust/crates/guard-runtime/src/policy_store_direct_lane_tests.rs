use super::super::tests::{install_test_key, signed_snapshot, test_root};
use super::{now_ms, PolicySnapshotStore};
use super::{
    observe_input, DirectLaneDefer, DIRECT_LANE_ACK_DIRECTORY, DIRECT_LANE_ACK_FILE_NAME,
    DIRECT_LANE_ACK_SCHEMA,
};
use guard_policy_snapshot::{PolicySnapshotV3, POLICY_SNAPSHOT_PUSH_SCHEMA};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

struct Fixture {
    root: std::path::PathBuf,
    store: PolicySnapshotStore,
    snapshot: PolicySnapshotV3,
    input: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture(label: &str) -> Fixture {
    let root = test_root(&format!("direct-lane-{label}"));
    let key = install_test_key(&root, 9);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(1, &key, &root);
    let input = root.join("config.toml");
    fs::write(&input, b"mode = \"enforce\"\n").unwrap();
    Fixture {
        root,
        store,
        snapshot,
        input,
    }
}

fn binding(fixture: &Fixture, workspace: &str) -> Value {
    let absent = fixture.root.join("absent.toml");
    json!({
        "workspaces": [workspace],
        "inputs": [
            {"path": fixture.input.to_str().unwrap(), "stat": observe_input(fixture.input.to_str().unwrap())},
            {"path": absent.to_str().unwrap(), "stat": null},
        ],
    })
}

fn push(fixture: &Fixture, direct_lane: Option<Value>) -> Result<Vec<u8>, String> {
    let mut request = json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": fixture.snapshot,
    });
    if let Some(direct_lane) = direct_lane {
        request["direct_lane"] = direct_lane;
    }
    fixture.store.push(&request)
}

fn write_ack(
    root: &Path,
    generation: u64,
    policy_digest: &str,
    lease_expires_at_ms: u64,
    mode: u32,
) {
    let directory = root.join(DIRECT_LANE_ACK_DIRECTORY);
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join(DIRECT_LANE_ACK_FILE_NAME);
    let _ = fs::remove_file(&path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&path)
        .unwrap();
    let body = json!({
        "schema": DIRECT_LANE_ACK_SCHEMA,
        "generation": generation,
        "policy_digest": policy_digest,
        "lease_expires_at_ms": lease_expires_at_ms,
    });
    file.write_all(&serde_json::to_vec(&body).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write_current_ack(fixture: &Fixture) {
    write_ack(
        &fixture.root,
        fixture.snapshot.generation,
        &fixture.snapshot.policy_digest,
        now_ms().unwrap() + 30_000,
        0o600,
    );
}

#[test]
fn bound_snapshot_is_admitted_while_ack_and_inputs_hold() {
    let fixture = fixture("admit");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMissing)
    );
    write_current_ack(&fixture);
    let admitted = fixture.store.admit_direct_lane("/work/repo").unwrap();
    assert_eq!(admitted.generation, fixture.snapshot.generation);
    assert_eq!(
        fixture.store.admit_direct_lane("/work/other").err(),
        Some(DirectLaneDefer::WorkspaceUnknown)
    );
}

#[test]
fn withdrawn_or_stale_ack_defers() {
    let fixture = fixture("ack");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    let digest = fixture.snapshot.policy_digest.clone();
    let wrong_digest = "0".repeat(64);
    let now = now_ms().unwrap();
    for (generation, digest, lease, mode, expected) in [
        (
            1,
            digest.as_str(),
            now.saturating_sub(1),
            0o600,
            DirectLaneDefer::AckExpired,
        ),
        (
            2,
            digest.as_str(),
            now + 30_000,
            0o600,
            DirectLaneDefer::AckMismatch,
        ),
        (
            1,
            wrong_digest.as_str(),
            now + 30_000,
            0o600,
            DirectLaneDefer::AckMismatch,
        ),
        (
            1,
            digest.as_str(),
            now + 600_000,
            0o600,
            DirectLaneDefer::AckMismatch,
        ),
        (
            1,
            digest.as_str(),
            now + 30_000,
            0o644,
            DirectLaneDefer::AckMismatch,
        ),
    ] {
        write_ack(&fixture.root, generation, digest, lease, mode);
        assert_eq!(
            fixture.store.admit_direct_lane("/work/repo").err(),
            Some(expected)
        );
    }
    let directory = fixture.root.join(DIRECT_LANE_ACK_DIRECTORY);
    write_current_ack(&fixture);
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMismatch)
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(directory.join(DIRECT_LANE_ACK_FILE_NAME)).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMissing)
    );
    fs::remove_dir(&directory).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMissing)
    );
}

#[test]
fn changed_or_created_input_defers() {
    let fixture = fixture("inputs");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    write_current_ack(&fixture);
    assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
    fs::write(fixture.root.join("absent.toml"), b"x = 1\n").unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::InputChanged)
    );
    fs::remove_file(fixture.root.join("absent.toml")).unwrap();
    assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
    fs::write(&fixture.input, b"mode = \"observe\"\n").unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::InputChanged)
    );
}

#[test]
fn idempotent_push_rebinds_and_unbound_push_closes_the_lane() {
    let fixture = fixture("rebind");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    write_current_ack(&fixture);
    fs::write(&fixture.input, b"mode = \"enforce\" # touched\n").unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::InputChanged)
    );
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
    push(&fixture, None).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::Unbound)
    );
}

#[test]
fn malformed_binding_rejects_the_push_without_installing_it() {
    let fixture = fixture("malformed");
    for direct_lane in [
        json!({"workspaces": ["relative/repo"], "inputs": []}),
        json!({"workspaces": ["/a", "/a"], "inputs": []}),
        json!({"workspaces": [], "inputs": [{"path": "/a", "stat": null}, {"path": "/a", "stat": null}]}),
        json!({"workspaces": [], "inputs": [], "extra": true}),
        json!({"workspaces": [], "inputs": [{"path": "/a", "stat": {"mtime_ns": 1, "size": 1, "ino": 1}}]}),
    ] {
        assert!(push(&fixture, Some(direct_lane)).is_err());
        assert_eq!(fixture.store.current_generation(), None);
    }
    assert_eq!(
        fixture.store.admit_direct_lane("/a").err(),
        Some(DirectLaneDefer::Unbound)
    );
}

#[test]
fn defer_reasons_name_the_daemon_path() {
    assert_eq!(
        DirectLaneDefer::Unsupported.code(),
        "direct_lane_unsupported"
    );
    assert_eq!(DirectLaneDefer::Unbound.code(), "direct_lane_unbound");
    assert_eq!(
        DirectLaneDefer::SnapshotUnavailable.code(),
        "direct_lane_snapshot_unavailable"
    );
    assert_eq!(
        DirectLaneDefer::AckMissing.code(),
        "direct_lane_ack_missing"
    );
    assert_eq!(
        DirectLaneDefer::AckMismatch.code(),
        "direct_lane_ack_mismatch"
    );
    assert_eq!(
        DirectLaneDefer::AckExpired.code(),
        "direct_lane_ack_expired"
    );
    assert_eq!(
        DirectLaneDefer::WorkspaceUnknown.code(),
        "direct_lane_workspace_unknown"
    );
    assert_eq!(
        DirectLaneDefer::InputChanged.code(),
        "direct_lane_input_changed"
    );
}
