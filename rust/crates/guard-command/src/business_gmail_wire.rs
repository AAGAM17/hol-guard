#![forbid(unsafe_code)]

//! Bounded, owned Gmail send wire input for native semantic extraction.
//! This decodes private bytes only; it neither validates MIME semantics nor
//! authenticates a provider account, makes an allow decision, or dispatches.

use base64::{engine::general_purpose, Engine};
use guard_contracts::MAX_BUSINESS_INLINE_BYTES;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const GWS_GMAIL_SEND_SOURCE_VERSION: &str = "0.22.5";
pub const GWS_GMAIL_SEND_SCHEMA_DIGEST: &str =
    "4c3fb4da34519808a4fff1428b742edb66b220543aa7eabccadd3708cbdd581d";
pub const GMAIL_SEND_MAX_PARAM_BYTES: usize = 4096;
const INPUT_DOMAIN: &[u8] = b"hol-guard.gmail-send-wire-input.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmailSendWireErrorV1 {
    Invalid,
    BoundsExceeded,
    UnsupportedPrincipalSelector,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendParams {
    #[serde(rename = "userId")]
    user_id: String,
}

fn present_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(d).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendBody {
    raw: String,
    #[serde(default, rename = "threadId", deserialize_with = "present_string")]
    thread_id: Option<String>,
}

/// Private source bytes and decoded MIME, with no Debug/Serialize/Clone or
/// mutable accessors. The producer must first pin executable, route, endpoint
/// and schema. `me` still requires authenticated principal/tenant resolution.
/// Resource ownership, audience/content parsing, inspection and authorization
/// remain mandatory even when this constructor succeeds.
pub struct GmailSendWireInputV1 {
    params: Box<[u8]>,
    body: Box<[u8]>,
    mime: Box<[u8]>,
    thread_id: Option<String>,
    binding: String,
}

impl GmailSendWireInputV1 {
    pub fn from_owned_json(params: Vec<u8>, body: Vec<u8>) -> Result<Self, GmailSendWireErrorV1> {
        use GmailSendWireErrorV1 as Error;
        if params.len() > GMAIL_SEND_MAX_PARAM_BYTES
            || params
                .len()
                .checked_add(body.len())
                .is_none_or(|total| total as u128 > u128::from(MAX_BUSINESS_INLINE_BYTES))
        {
            return Err(Error::BoundsExceeded);
        }
        let parsed_params: SendParams =
            serde_json::from_slice(&params).map_err(|_| Error::Invalid)?;
        if parsed_params.user_id != "me" {
            return Err(Error::UnsupportedPrincipalSelector);
        }
        let parsed_body: SendBody = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
        if parsed_body
            .thread_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        {
            return Err(Error::Invalid);
        }
        // Gmail uses URL-safe base64. Accept both canonical padded and unpadded
        // forms; the engines reject mixed alphabets, whitespace, bad padding and
        // nonzero trailing bits. Input bounds precede all decoding allocations.
        let engine = if parsed_body.raw.ends_with('=') {
            &general_purpose::URL_SAFE
        } else {
            &general_purpose::URL_SAFE_NO_PAD
        };
        let mime = engine
            .decode(parsed_body.raw.as_bytes())
            .map_err(|_| Error::Invalid)?;
        if mime.is_empty() {
            return Err(Error::Invalid);
        }
        if mime.len() as u128 > u128::from(MAX_BUSINESS_INLINE_BYTES) {
            return Err(Error::BoundsExceeded);
        }
        // Commit the pinned interpretation and every original wire byte. This
        // is a preparation identity, not a policy/review/dispatch capability.
        let mut hash = Sha256::new();
        hash.update(INPUT_DOMAIN);
        hash.update(GWS_GMAIL_SEND_SCHEMA_DIGEST.as_bytes());
        for bytes in [&params, &body] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Ok(Self {
            params: params.into_boxed_slice(),
            body: body.into_boxed_slice(),
            mime: mime.into_boxed_slice(),
            thread_id: parsed_body.thread_id,
            binding: hex::encode(hash.finalize()),
        })
    }

    pub fn params_bytes(&self) -> &[u8] {
        &self.params
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn mime_bytes(&self) -> &[u8] {
        &self.mime
    }

    pub fn thread_id(&self) -> Option<&str> {
        self.thread_id.as_deref()
    }

    pub fn input_binding(&self) -> &str {
        &self.binding
    }
}
