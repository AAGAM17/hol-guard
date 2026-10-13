//! The bridge's own process identity: a port of `current_process_identity`
//! in `live_process_identity.py`. The daemon uses it to tell whether the
//! hook process still waits on a browser approval, so the start token must
//! match what the Python verifier recomputes for the same PID.

/// `current_process_identity()`: this process's PID and start token.
pub(crate) fn current_process_identity() -> Option<(u32, String)> {
    let pid = std::process::id();
    process_start_token(pid).map(|token| (pid, token))
}

/// `_process_start_token(pid)` on Windows.
///
/// TODO(windows-process-identity): Python answers `windows:<creation time>`
/// from the process creation time. Until that is ported no token is
/// produced, so the bridge never asks the daemon to wait on its process.
#[cfg(windows)]
pub(crate) fn process_start_token(_pid: u32) -> Option<String> {
    None
}

#[cfg(unix)]
#[path = "codex_hook_identity_posix.rs"]
mod posix;
#[cfg(unix)]
pub(crate) use posix::process_start_token;
