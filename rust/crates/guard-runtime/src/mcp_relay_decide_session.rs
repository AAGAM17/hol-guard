//! Whether the resident can decide a relay session's calls at all.
//!
//! Some deferrals do not depend on the call: they follow from the config the
//! lane binds or from what the store holds. A session under such a binding
//! would defer, and refuse, every call the proxy would prompt for, observe or
//! read remote policy for. The relay asks before it starts the MCP server and
//! hands such a session to the Python proxy, which decides those calls as it
//! does without the relay:
//!
//! - an unparsable view, an unbound harness or unverified extension layers;
//! - `mode = "observe"`, whose observe-forward route the resident does not
//!   take;
//! - a blocked-request mode other than `safe-alternative` as every bound
//!   config resolves it (`ask`, or configs that disagree), or a receipt
//!   redaction level the configs do not agree on, since the queue route is
//!   native only under `safe-alternative` with a bound level;
//! - a store holding a policy bundle, remote policy rows, or saved rows whose
//!   integrity state is not the protected one the daemon published.
//!
//! This only steers which launcher runs. Each call is still admitted by
//! `mcp_relay_decide`, which repeats every check and refuses whatever it does
//! not decide, so a binding or store that changes mid-session still fails
//! closed.

use std::path::Path;

use super::{store, view};
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;

/// `blocked_request_mode`, under which the queue route blocks natively.
const SAFE_ALTERNATIVE_MODE: &str = "safe-alternative";
const SESSION_OBSERVE: &str = "mcp_relay_session_observe";
const SESSION_REVIEW_MODE: &str = "mcp_relay_session_review_mode";
const SESSION_REDACTION_UNBOUND: &str = "mcp_relay_session_redaction_unbound";

/// `Ok` when the binding and store leave every call to the resident.
pub(crate) fn session_decidable(
    binding: &DirectLaneBinding,
    guard_home: &str,
    harness: &str,
) -> Result<(), &'static str> {
    let view = view::harness_view(binding.mcp_relay.as_ref(), harness)?;
    if view.mode == "observe" {
        return Err(SESSION_OBSERVE);
    }
    if binding.review.blocked_request_mode.as_deref() != Some(SAFE_ALTERNATIVE_MODE) {
        return Err(SESSION_REVIEW_MODE);
    }
    if view.receipt_redaction_level.is_none() {
        return Err(SESSION_REDACTION_UNBOUND);
    }
    if let Some(connection) = store::open(Path::new(guard_home))? {
        store::saved(&connection, binding, guard_home)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "mcp_relay_decide_session_tests.rs"]
mod tests;
