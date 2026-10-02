//! Native-runtime admission: manifest verification + bundled-candidate policy.
//!
//! Port of `native_runtime.py` (`_manifest_for_bundled_identity`,
//! `_is_bundled_candidate`, `_restore_bundled_runtime_execute_bit`,
//! `_windows_native_dll_directories`, `_isolated_environment`). These are the
//! admission gate for a runtime artifact: the manifest is read through
//! `guard-secure-fs::read_bounded` (regular file, single link, no write bits,
//! symlink leaf rejected, identity revalidated), decoded by
//! `guard_contracts::decode_runtime_manifest`, then cross-checked against the
//! runtime's `FileIdentity` and the caller-supplied package version.
//!
//! The isolated spawn environment lives here too so a one-shot runtime launch
//! never inherits user-controlled PATH/loader vars. The capabilities-probe
//! spawn leg (`_run_native_process` / `_capabilities_for_identity`) stays in
//! Python until the `run_isolated_hook_process` kernel lands (RTM-011).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use guard_contracts::{decode_runtime_manifest, NativeRuntimeManifestV1};
use guard_secure_fs::{read_bounded, SecureReadError};

/// `_NATIVE_MANIFEST_NAME` (`native_runtime.py:57`).
pub const NATIVE_MANIFEST_NAME: &str = "runtime-manifest.json";
/// `_NATIVE_MANIFEST_SCHEMA` (`native_runtime.py:58`).
pub const NATIVE_MANIFEST_SCHEMA: &str = "hol-guard-native-runtime.v1";
/// `_MAX_MANIFEST_BYTES` (`native_runtime.py:59`).
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;
/// `_NATIVE_PROTOCOL_VERSION` — keep in lockstep with the resident protocol.
pub const NATIVE_MANIFEST_PROTOCOL_VERSION: i64 = 1;

/// Caller-supplied runtime identity, mirroring `NativeRuntimeIdentity`
/// (`native_runtime_values.py:58-62`) — path + size + sha256 are the fields the
/// manifest cross-check consumes. `mtime_ns` is carried for parity/debugging.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeIdentity {
    pub path: PathBuf,
    pub size: i64,
    pub mtime_ns: u64,
    pub sha256: String,
}

/// The reason-code contract is stable across the Python/Rust boundary —
/// `native_runtime_status` surfaces these to `integrity reasons`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestReject {
    /// `native_manifest_missing`
    Missing,
    /// `native_manifest_invalid` (bad type, size, perms, owner, or decode)
    Invalid,
    /// `native_manifest_runtime_mismatch` (size/sha256 vs the binary)
    RuntimeMismatch,
    /// `native_manifest_version_mismatch` (vs the installed package version)
    VersionMismatch,
}

impl ManifestReject {
    /// Python reason string (`native_runtime_values.py:_INTEGRITY_FAILURE_REASONS`).
    pub fn reason(self) -> &'static str {
        match self {
            Self::Missing => "native_manifest_missing",
            Self::Invalid => "native_manifest_invalid",
            Self::RuntimeMismatch => "native_manifest_runtime_mismatch",
            Self::VersionMismatch => "native_manifest_version_mismatch",
        }
    }
}

/// `_manifest_for_bundled_identity` (`native_runtime.py:151-181`).
///
/// `package_version` is `_python_package_version()` resolved by the caller —
/// the Python wheel's version is not knowable in Rust; `None` skips the
/// version cross-check exactly as Python does. Returns the decoded manifest or
/// a stable reject reason. Fail-closed: any malformed/oversized/wrong-owner
/// manifest rejects before decode.
pub fn manifest_for_bundled_identity(
    identity: &RuntimeIdentity,
    package_version: Option<&str>,
) -> Result<NativeRuntimeManifestV1, ManifestReject> {
    let manifest_path = identity.path.with_file_name(NATIVE_MANIFEST_NAME);

    // Owner check must precede read: `read_bounded` enforces type/perm/link
    // but does not restrict uid. Mirror `st_uid in {0, euid}` (unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&manifest_path)
            .map_err(|e| map_err(&e))?;
        let mode = meta.mode();
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(ManifestReject::Invalid);
        }
        if meta.size() == 0 || meta.size() > MAX_MANIFEST_BYTES as u64 {
            return Err(ManifestReject::Invalid);
        }
        if mode & 0o022 != 0 {
            return Err(ManifestReject::Invalid);
        }
        let uid = nix::unistd::geteuid().as_raw();
        let owner = meta.uid();
        if owner != 0 && owner != uid {
            return Err(ManifestReject::Invalid);
        }
    }
    // Read through the digest-bound bounded read so the bytes we decode are
    // the bytes whose identity was admitted (TOCTOU-safe).
    let read = match read_bounded(&manifest_path, MAX_MANIFEST_BYTES) {
        Ok(r) => r,
        Err(e) => {
            // SecureReadError has no NotFound variant: a missing leaf surfaces
            // as UnresolvedPath/ReadFailed/PermissionDenied. Re-probe to
            // distinguish "absent" from "present but unreadable".
            use SecureReadError as E;
            return Err(match e {
                E::UnresolvedPath | E::ReadFailed | E::PermissionDenied => {
                    if manifest_path.exists() {
                        ManifestReject::Invalid
                    } else {
                        ManifestReject::Missing
                    }
                }
                _ => ManifestReject::Invalid,
            });
        }
    };

    let payload: serde_json::Value =
        serde_json::from_slice(&read.bytes).map_err(|_| ManifestReject::Invalid)?;
    let manifest = decode_runtime_manifest(
        &payload,
        NATIVE_MANIFEST_SCHEMA,
        NATIVE_MANIFEST_PROTOCOL_VERSION,
    )
    .ok_or(ManifestReject::Invalid)?;

    if manifest.runtime_size != identity.size || manifest.runtime_sha256 != identity.sha256 {
        return Err(ManifestReject::RuntimeMismatch);
    }
    if let Some(expected) = package_version {
        if manifest.package_version != expected {
            return Err(ManifestReject::VersionMismatch);
        }
    }
    Ok(manifest)
}

#[cfg(unix)]
fn map_err(e: &std::io::Error) -> ManifestReject {
    if e.kind() == std::io::ErrorKind::NotFound {
        ManifestReject::Missing
    } else {
        ManifestReject::Invalid
    }
}

/// `_is_bundled_candidate` (`native_runtime.py:184-188`). `bundled` is the
/// resolved `_bundled_runtime_candidate()` path supplied by the caller —
/// resolving `__file__` is a Python-packaging detail that stays host-side.
pub fn is_bundled_candidate(candidate: &Path, bundled: &Path) -> bool {
    match (
        candidate.canonicalize().or_else(|_| Ok::<PathBuf, std::io::Error>(expanduser(candidate))),
        bundled.canonicalize().or_else(|_| Ok::<PathBuf, std::io::Error>(bundled.to_path_buf())),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn expanduser(p: &Path) -> PathBuf {
    p.to_path_buf()
}

/// `_restore_bundled_runtime_execute_bit` (`native_runtime.py:191-206`).
/// PyInstaller DATA extracts without the owner-exec bit; spawn needs it.
/// Only touches the bundled candidate; no-op on Windows or on a file that
/// already has exec, has write bits, is a symlink/non-regular, or is owned by
/// someone else. Fail-silent like Python.
#[cfg(unix)]
pub fn restore_bundled_runtime_execute_bit(path: &Path, bundled: &Path) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !is_bundled_candidate(path, bundled) {
        return;
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let mode = meta.mode();
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || mode & 0o022 != 0
        || mode & 0o100 != 0
    {
        return;
    }
    let uid = nix::unistd::geteuid().as_raw();
    if meta.uid() != 0 && meta.uid() != uid {
        return;
    }
    let _ = std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(mode | 0o111),
    );
}
#[cfg(not(unix))]
pub fn restore_bundled_runtime_execute_bit(_path: &Path, _bundled: &Path) {}

/// `_windows_native_dll_directories` (`native_runtime.py:209-241`).
/// Windows-only CRT search path for the dynamically-linked runtime. Order
/// preserved, deduped by casefold. `base_prefix` is `sys.base_prefix`; the
/// caller resolves it. Non-Windows returns empty.
#[cfg(target_os = "windows")]
pub fn windows_native_dll_directories(base_prefix: Option<&Path>, bundled: &Path) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    let system_root = std::env::var("SYSTEMROOT")
        .ok()
        .or_else(|| std::env::var("WINDIR").ok());
    if let Some(sr) = system_root {
        if !sr.is_empty() {
            roots.push(Path::new(&sr).join("System32").to_string_lossy().into_owned());
        }
    }
    if let Some(bp) = base_prefix {
        let has_crt = ["vcruntime140.dll", "vcruntime140_1.dll"]
            .iter()
            .any(|n| bp.join(n).is_file());
        if has_crt {
            roots.push(bp.to_string_lossy().into_owned());
        }
    }
    let runtime_dir = bundled.parent().map(Path::to_path_buf);
    if let Some(rd) = runtime_dir {
        if rd.is_dir() {
            roots.push(rd.to_string_lossy().into_owned());
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut unique = Vec::new();
    for r in roots {
        let key = r.to_lowercase();
        if seen.insert(key) {
            unique.push(r);
        }
    }
    unique
}
#[cfg(not(target_os = "windows"))]
pub fn windows_native_dll_directories(_bp: Option<&Path>, _bundled: &Path) -> Vec<String> {
    Vec::new()
}

/// `_isolated_environment` (`native_runtime.py:244-264`).
/// The allowlist blocklist — only the named vars + `LC_*` survive, so the
/// child never inherits user PATH/LD_*/credential env. On Windows the only
/// PATH the child sees is the CRT search dirs (DLL isolation); POSIX children
/// get no PATH at all (spawn resolves the binary by absolute path).
pub fn isolated_environment(
    base_env: &BTreeMap<String, String>,
    base_prefix: Option<&Path>,
    bundled: &Path,
) -> BTreeMap<String, String> {
    const ALLOWED: &[&str] = &[
        "COMSPEC",
        "HOME",
        "LANG",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    ];
    let mut environment = BTreeMap::new();
    for (key, value) in base_env {
        let upper = key.to_uppercase();
        if ALLOWED.contains(&upper.as_str()) || upper.starts_with("LC_") {
            environment.insert(key.clone(), value.clone());
        }
    }
    #[cfg(target_os = "windows")]
    {
        let dll = windows_native_dll_directories(base_prefix, bundled);
        if !dll.is_empty() {
            environment.insert("PATH".to_string(), dll.join(";"));
        }
        let _ = base_prefix;
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (base_prefix, bundled);
    }
    environment
}


#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    fn tmp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "nra-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        fs::create_dir_all(&p).expect("create tmp dir");
        // `/var` is a symlink on macOS; read_bounded walks every component, so
        // hand the caller the canonical (symlink-free) path.
        fs::canonicalize(&p).expect("canonicalize tmp dir")
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, bytes).expect("write fixture");
        p
    }

    /// `read_bounded` rejects any leaf write bit (`0o222`); the real bundled
    /// manifest is installed read-only. Mirror that in fixtures.
    fn write_readonly(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = write(dir, name, bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o444);
            fs::set_permissions(&p, perm).unwrap();
        }
        p
    }

    /// Build the `RuntimeIdentity` for an on-disk binary the same way the
    /// bundled-candidate probe does: path + size + mtime_ns + sha256.
    fn identity_of(bin: &Path) -> RuntimeIdentity {
        let meta = fs::metadata(bin).expect("bin metadata");
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        RuntimeIdentity {
            path: bin.to_path_buf(),
            size: meta.len() as i64,
            mtime_ns,
            sha256: format!("{:x}", sha2::Sha256::digest(fs::read(bin).unwrap())),
        }
    }

    fn valid_manifest(size: i64, sha: &str) -> serde_json::Value {
        serde_json::json!({
            "schema": NATIVE_MANIFEST_SCHEMA,
            "protocol_version": NATIVE_MANIFEST_PROTOCOL_VERSION,
            "package_version": "3.16.5",
            "target": "aarch64-apple-darwin",
            "platform_tag": "macosx_14_0_arm64",
            "source_sha": "a".repeat(40),
            "rule_digest": "b".repeat(64),
            "runtime_size": size,
            "runtime_sha256": sha,
        })
    }

    #[test]
    fn missing_manifest_file_is_missing() {
        let dir = tmp_dir("missing_manifest");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::Missing);
    }

    #[test]
    fn malformed_manifest_json_is_invalid() {
        let dir = tmp_dir("malformed_manifest");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        write_readonly(&dir, NATIVE_MANIFEST_NAME, b"{not-json");
        let id = identity_of(&bin);
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::Invalid);
    }

    #[test]
    fn wrong_manifest_schema_is_invalid() {
        let dir = tmp_dir("wrong_schema");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let m = serde_json::json!({"schema":"other","protocol_version":1,"runtime_size":6,"runtime_sha256":"x"});
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let id = identity_of(&bin);
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::Invalid);
    }

    #[test]
    fn size_mismatch_is_runtime_mismatch() {
        let dir = tmp_dir("size_mismatch");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        // manifest claims a different size than the on-disk identity.
        let m = valid_manifest(id.size + 1, &id.sha256);
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::RuntimeMismatch);
    }

    #[test]
    fn sha_mismatch_is_runtime_mismatch() {
        let dir = tmp_dir("sha_mismatch");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        let m = valid_manifest(id.size, &"00".repeat(32));
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::RuntimeMismatch);
    }

    #[test]
    fn version_mismatch_flagged() {
        let dir = tmp_dir("version_mismatch");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        // Real sha/size of the file so only the package_version check fails.
        let mut m = valid_manifest(id.size, &id.sha256);
        m["package_version"] = serde_json::json!("9.9.9");
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let err = manifest_for_bundled_identity(&id, Some("3.16.5")).unwrap_err();
        assert_eq!(err, ManifestReject::VersionMismatch);
    }

    #[test]
    fn valid_manifest_accepted() {
        let dir = tmp_dir("valid_manifest");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        let m = valid_manifest(id.size, &id.sha256);
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let got = manifest_for_bundled_identity(&id, Some("3.16.5")).expect("accepted");
        assert_eq!(got.runtime_size, id.size);
        assert_eq!(got.runtime_sha256, id.sha256);
        assert_eq!(got.package_version, "3.16.5");
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_manifest_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("writable_manifest");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        let mp = write_readonly(&dir, NATIVE_MANIFEST_NAME, valid_manifest(id.size, &id.sha256).to_string().as_bytes());
        let mut perm = fs::metadata(&mp).unwrap().permissions();
        perm.set_mode(0o666);
        fs::set_permissions(&mp, perm).unwrap();
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::Invalid);
    }

    #[test]
    fn isolated_env_drops_injected_keys() {
        let mut base = BTreeMap::new();
        base.insert("PATH".to_string(), "/evil".to_string());
        base.insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
        base.insert("AWS_SECRET".to_string(), "x".to_string());
        base.insert("HOME".to_string(), "/u".to_string());
        base.insert("LC_ALL".to_string(), "C".to_string());
        base.insert("TMPDIR".to_string(), "/tmp".to_string());
        let env = isolated_environment(&base, None, Path::new("/bundled"));
        assert!(env.get("PATH").is_none() || cfg!(windows));
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("AWS_SECRET"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/u"));
        assert_eq!(env.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(env.get("TMPDIR").map(String::as_str), Some("/tmp"));
    }

    #[test]
    fn reject_reason_strings_stable() {
        assert_eq!(ManifestReject::Missing.reason(), "native_manifest_missing");
        assert_eq!(ManifestReject::Invalid.reason(), "native_manifest_invalid");
        assert_eq!(ManifestReject::RuntimeMismatch.reason(), "native_manifest_runtime_mismatch");
        assert_eq!(ManifestReject::VersionMismatch.reason(), "native_manifest_version_mismatch");
    }
}
