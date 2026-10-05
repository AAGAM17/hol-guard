//! Worker-private reusable account. No enrollment, token export or send grant.
use super::{GoogleSendCredential, GrantPurpose};
use crate::{
    worker_input::{GoogleWorkerInput, GoogleWorkerInputError},
    GoogleIdentityEvidence,
};
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum GoogleSendAccountError {
    Unavailable,
    IdentityChanged,
}

/// A registered worker may retain this owner across distinct transactions.
/// Each input remains consumable once and still needs native policy/review.
/// No Clone, Debug, serialization, token getter or credential reload exists.
pub struct GoogleSendAccount {
    credential: GoogleSendCredential,
    active: Arc<RwLock<bool>>,
    epoch: String,
}

impl GoogleSendAccount {
    pub fn new(credential: GoogleSendCredential) -> Result<Self, GoogleSendAccountError> {
        if credential.purpose != GrantPurpose::Send
            || !credential.is_current()
            || credential.account_lease.is_some()
        {
            return Err(GoogleSendAccountError::Unavailable);
        }
        Ok(Self {
            epoch: new_epoch()?,
            credential,
            active: Arc::new(RwLock::new(true)),
        })
    }

    pub fn identity(&self) -> &GoogleIdentityEvidence {
        self.credential.identity()
    }

    pub fn is_current(&self) -> bool {
        self.active.read().is_ok_and(|active| *active) && self.credential.is_current()
    }

    pub fn prepare_command(
        &self,
        command: String,
    ) -> Result<GoogleWorkerInput, GoogleWorkerInputError> {
        if !self.is_current() {
            return Err(GoogleWorkerInputError::Expired);
        }
        // Only access material is leased; refresh material stays with the owner.
        let identity = &self.credential.identity;
        GoogleSendCredential {
            account_lease: Some(Arc::clone(&self.active)),
            account_epoch: Some(self.epoch.clone()),
            purpose: GrantPurpose::Send,
            access_token: Zeroizing::new(self.credential.access_token.as_str().to_owned()),
            refresh_token: None,
            identity: GoogleIdentityEvidence {
                account_binding: identity.account_binding.clone(),
                tenant_binding: identity.tenant_binding.clone(),
                expires_at: identity.expires_at,
                sender: identity.sender.as_ref().map(|sender| sender.worker_copy()),
            },
            expires_at: self.credential.expires_at,
            expires_monotonic: self.credential.expires_monotonic,
        }
        .prepare_command(command)
    }

    /// Replace with fresh worker-verified authorization for this exact account.
    /// Failed replacement leaves the current account intact. Success invalidates
    /// every pending input from the previous epoch.
    pub fn replace(
        &mut self,
        replacement: GoogleSendCredential,
    ) -> Result<(), GoogleSendAccountError> {
        if !self.active.read().is_ok_and(|active| *active)
            || replacement.purpose != GrantPurpose::Send
            || replacement.account_lease.is_some()
            || !replacement.is_current()
        {
            return Err(GoogleSendAccountError::Unavailable);
        }
        if replacement.identity.account_binding != self.credential.identity.account_binding
            || replacement.identity.tenant_binding != self.credential.identity.tenant_binding
            || !self
                .credential
                .identity
                .sender
                .as_ref()
                .is_some_and(|sender| {
                    replacement
                        .identity
                        .sender
                        .as_ref()
                        .is_some_and(|other| sender.same_mailbox(other))
                })
        {
            return Err(GoogleSendAccountError::IdentityChanged);
        }
        let epoch = new_epoch()?;
        self.revoke();
        self.credential = replacement;
        self.active = Arc::new(RwLock::new(true));
        self.epoch = epoch;
        Ok(())
    }

    /// Waits for an admitted bounded call, then invalidates pending inputs.
    /// It cannot undo an HTTP call that has already been admitted.
    pub fn revoke(&self) {
        *self
            .active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
    }
}

fn new_epoch() -> Result<String, GoogleSendAccountError> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| GoogleSendAccountError::Unavailable)?;
    Ok(hex::encode(random))
}

impl Drop for GoogleSendAccount {
    fn drop(&mut self) {
        self.revoke();
    }
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;
