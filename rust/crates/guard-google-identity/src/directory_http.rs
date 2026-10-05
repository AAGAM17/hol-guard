//! Private fixed-host, read-only Directory transport; never a model-selected
//! URL, verb, scope or bearer relay. Payloads remain owned inside the worker.

use super::{GoogleSendCredential, GrantPurpose};
use crate::directory::DirectoryError;
use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;
use zeroize::Zeroizing;

impl GoogleSendCredential {
    pub(crate) fn directory_user(
        &self,
        address: &str,
    ) -> Result<Zeroizing<Vec<u8>>, DirectoryError> {
        if self.purpose != GrantPurpose::Directory || !crate::sender::supported_mailbox(address) {
            return Err(DirectoryError::Invalid);
        }
        if !self.is_current() {
            return Err(DirectoryError::Expired);
        }
        let encoded: String =
            oauth2::url::form_urlencoded::byte_serialize(address.as_bytes()).collect();
        let uri = format!("https://admin.googleapis.com/admin/directory/v1/users/{encoded}?projection=basic&viewType=admin_view&fields=kind,id,primaryEmail,customerId,suspended,archived,aliases,nonEditableAliases,etag");
        static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
        let agent = AGENT.get_or_init(|| {
            ureq::Agent::config_builder()
                .https_only(true)
                .proxy(None)
                .max_redirects(0)
                .max_response_header_size(16 * 1024)
                .timeout_global(Some(Duration::from_secs(5)))
                .http_status_as_error(false)
                .build()
                .into()
        });
        let authorization = Zeroizing::new(format!("Bearer {}", self.access_token.as_str()));
        let mut response = agent
            .get(&uri)
            .header("Authorization", authorization.as_str())
            .call()
            .map_err(|_| DirectoryError::Unavailable)?;
        match response.status().as_u16() {
            200 => {}
            404 | 403 => return Err(DirectoryError::Unresolved),
            429 | 500..=599 => return Err(DirectoryError::Unavailable),
            _ => return Err(DirectoryError::Invalid),
        }
        let values = response
            .headers()
            .get_all("content-type")
            .iter()
            .collect::<Vec<_>>();
        if values.len() != 1
            || values[0]
                .to_str()
                .ok()
                .and_then(|s| s.split(';').next())
                .is_none_or(|s| !s.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(DirectoryError::Invalid);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(64 * 1024 + 1));
        response
            .body_mut()
            .as_reader()
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| DirectoryError::Unavailable)?;
        if bytes.len() > 64 * 1024 {
            return Err(DirectoryError::Invalid);
        }
        if !self.is_current() {
            return Err(DirectoryError::Expired);
        }
        Ok(bytes)
    }
}
