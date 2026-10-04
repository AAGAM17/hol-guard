//! Worker-owned registered Google send authorization. No public RPC, token
//! export, account enrollment, custody proof or execution authority is added.

use super::{bounded_ascii, now, GoogleIdentityEvidence, GoogleLoginChallenge, IdentityError};
use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenType,
};
use oauth2::{
    AccessToken, AuthType, AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RefreshToken, Scope, StandardRevocableToken, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const SEND_SCOPE: &str = "https://www.googleapis.com/auth/gmail.send";

type RegisteredClient = Client<
    BasicErrorResponse,
    GoogleTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

/// Configuration must come from the authenticated worker, not callback/tool
/// arguments. The client session binding is owned by that worker's authorized
/// client session and must be re-derived from the authenticated callback session.
pub struct GoogleSendAuthorization {
    client: RegisteredClient,
    client_secret: Zeroizing<String>,
    challenge: GoogleLoginChallenge,
    state: Zeroizing<String>,
    verifier: Zeroizing<String>,
    client_session_binding: String,
    authorization_url: Zeroizing<String>,
}

/// Private credential material remains in the worker. No Clone, Debug,
/// serialization or token getter. A successful callback is not enrollment.
pub struct GoogleSendCredential {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    identity: GoogleIdentityEvidence,
    expires_at: u64,
    expires_monotonic: Instant,
}
impl GoogleSendCredential {
    pub fn identity(&self) -> &GoogleIdentityEvidence {
        &self.identity
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn has_refresh_credential(&self) -> bool {
        self.refresh_token.is_some()
    }
    pub fn is_current(&self) -> bool {
        bounded_ascii(&self.access_token, 8192)
            && Instant::now() < self.expires_monotonic
            && now().is_ok_and(|time| time < self.expires_at && time < self.identity.expires_at())
    }
}

impl GoogleSendAuthorization {
    pub fn begin(
        challenge: GoogleLoginChallenge,
        registered_client_secret: String,
        registered_redirect_uri: String,
        authenticated_client_session_binding: String,
    ) -> Result<Self, IdentityError> {
        let client_secret = Zeroizing::new(registered_client_secret);
        challenge.check_time(now()?)?;
        if !bounded_ascii(&client_secret, 4096)
            || !valid_session_binding(&authenticated_client_session_binding)
            || registered_redirect_uri.len() > 2048
        {
            return Err(IdentityError::Invalid);
        }
        let redirect =
            RedirectUrl::new(registered_redirect_uri).map_err(|_| IdentityError::Invalid)?;
        let url = redirect.url();
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
        {
            return Err(IdentityError::Invalid);
        }
        let client = Client::new(ClientId::new(challenge.client_id.clone()))
            .set_auth_type(AuthType::RequestBody)
            .set_auth_uri(
                AuthUrl::new(AUTHORIZE_URL.to_owned()).map_err(|_| IdentityError::Invalid)?,
            )
            .set_token_uri(TokenUrl::new(TOKEN_URL.to_owned()).map_err(|_| IdentityError::Invalid)?)
            .set_redirect_uri(redirect);
        let (pkce, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_owned()))
            .add_scope(Scope::new(SEND_SCOPE.to_owned()))
            .set_pkce_challenge(pkce)
            .add_extra_param("nonce", challenge.nonce())
            .add_extra_param("access_type", "offline")
            .add_extra_param("include_granted_scopes", "false")
            .add_extra_param("prompt", "select_account consent")
            .url();
        Ok(Self {
            client,
            client_secret,
            challenge,
            state: Zeroizing::new(state.into_secret()),
            verifier: Zeroizing::new(verifier.into_secret()),
            client_session_binding: authenticated_client_session_binding,
            authorization_url: Zeroizing::new(url.into()),
        })
    }

    /// A browser may receive this authorization URL; it contains no client
    /// secret or PKCE verifier. Do not log callback codes or token responses.
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    /// Consumes the session even on failure. The session binding must come
    /// from authenticated server context, never a callback query/body field.
    pub fn complete(
        self,
        callback_state: &str,
        code: String,
        authenticated_client_session_binding: &str,
    ) -> Result<GoogleSendCredential, IdentityError> {
        self.complete_with(
            callback_state,
            code,
            authenticated_client_session_binding,
            exchange_http,
            |challenge, id, access| challenge.verify(id, access),
        )
    }

    fn complete_with<E: std::error::Error + 'static>(
        self,
        callback_state: &str,
        code: String,
        session_binding: &str,
        transport: impl Fn(HttpRequest) -> Result<HttpResponse, E>,
        verify_identity: impl FnOnce(
            GoogleLoginChallenge,
            &str,
            &str,
        ) -> Result<GoogleIdentityEvidence, IdentityError>,
    ) -> Result<GoogleSendCredential, IdentityError> {
        let code = Zeroizing::new(code);
        self.challenge.check_time(now()?)?;
        if !bounded_ascii(callback_state, 256)
            || !bounded_ascii(&code, 8192)
            || !same_state(&self.state, callback_state)
            || self.client_session_binding != session_binding
        {
            return Err(IdentityError::Invalid);
        }
        let start = ExchangeStart {
            wall: now()?,
            monotonic: Instant::now(),
        };
        // The registered secret stays zeroizing in the pending session. The
        // SDK needs transient owned copies while constructing this request;
        // it does not provide zeroization for those internal allocations.
        let client = self
            .client
            .set_client_secret(ClientSecret::new(self.client_secret.to_string()));
        let response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(self.verifier.to_string()))
            .request(&transport)
            .map_err(|_| IdentityError::Invalid)?;
        if response.token_type != BasicTokenType::Bearer
            || !bounded_ascii(response.access_token.secret(), 8192)
            || !bounded_ascii(&response.id_token, super::MAX_TOKEN)
            || response.expires_in == 0
            || response.expires_in > 3600
            || response.scopes.len() != 2
            || !response
                .scopes
                .iter()
                .any(|scope| scope.as_str() == "openid")
            || !response
                .scopes
                .iter()
                .any(|scope| scope.as_str() == SEND_SCOPE)
            || response
                .refresh_token
                .as_ref()
                .is_some_and(|token| !bounded_ascii(token.secret(), 8192))
        {
            return Err(IdentityError::Invalid);
        }
        let received_at = now()?;
        self.challenge.check_time(received_at)?;
        let identity = verify_identity(
            self.challenge,
            &response.id_token,
            response.access_token.secret(),
        )?;
        // Google verification may fetch keys; both clocks are checked again.
        let observed = now()?;
        let (expires_at, expires_monotonic) = credential_deadline(
            &start,
            received_at,
            observed,
            identity.expires_at(),
            response.expires_in,
            Instant::now(),
        )?;
        Ok(GoogleSendCredential {
            access_token: Zeroizing::new(response.access_token.secret().to_owned()),
            refresh_token: response
                .refresh_token
                .as_ref()
                .map(|value| Zeroizing::new(value.secret().to_owned())),
            identity,
            expires_at,
            expires_monotonic,
        })
    }
}

fn same_state(expected: &str, presented: &str) -> bool {
    let expected = CsrfToken::new(expected.to_owned());
    let presented = CsrfToken::new(presented.to_owned());
    let same = expected == presented;
    // Preserve the SDK's timing-resistant comparison, then recover and wipe
    // the temporary comparison strings through its supported ownership API.
    drop(Zeroizing::new(expected.into_secret()));
    drop(Zeroizing::new(presented.into_secret()));
    same
}

struct ExchangeStart {
    wall: u64,
    monotonic: Instant,
}
fn credential_deadline(
    start: &ExchangeStart,
    received: u64,
    observed: u64,
    identity_expiry: u64,
    lifetime: u64,
    monotonic: Instant,
) -> Result<(u64, Instant), IdentityError> {
    let expiry = start.wall.saturating_add(lifetime).min(identity_expiry);
    let access_deadline = start.monotonic + Duration::from_secs(lifetime);
    if received < start.wall
        || observed < received
        || observed >= expiry
        || monotonic >= access_deadline
    {
        return Err(IdentityError::Expired);
    }
    Ok((
        expiry,
        access_deadline.min(monotonic + Duration::from_secs(expiry - observed)),
    ))
}

fn valid_session_binding(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Known duplicates fail Serde struct decoding. No token response diagnostic or
// serialization can expose its code/token material through generic utilities.
#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: AccessToken,
    #[serde(deserialize_with = "bearer_type")]
    token_type: BasicTokenType,
    expires_in: u64,
    refresh_token: Option<RefreshToken>,
    #[serde(rename = "scope", deserialize_with = "granted_scopes")]
    scopes: Vec<Scope>,
    id_token: String,
}
impl Drop for GoogleTokenResponse {
    fn drop(&mut self) {
        self.id_token.zeroize();
        let access = std::mem::replace(&mut self.access_token, AccessToken::new(String::new()));
        drop(Zeroizing::new(access.into_secret()));
        if let Some(refresh) = self.refresh_token.take() {
            drop(Zeroizing::new(refresh.into_secret()));
        }
    }
}
impl fmt::Debug for GoogleTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GoogleTokenResponse(REDACTED)")
    }
}
impl Serialize for GoogleTokenResponse {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "credential serialization disabled",
        ))
    }
}
impl TokenResponse for GoogleTokenResponse {
    type TokenType = BasicTokenType;
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    fn token_type(&self) -> &BasicTokenType {
        &self.token_type
    }
    fn expires_in(&self) -> Option<Duration> {
        Some(Duration::from_secs(self.expires_in))
    }
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    fn scopes(&self) -> Option<&Vec<Scope>> {
        Some(&self.scopes)
    }
}
fn bearer_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BasicTokenType, D::Error> {
    let value = String::deserialize(d)?;
    if value.eq_ignore_ascii_case("bearer") {
        Ok(BasicTokenType::Bearer)
    } else {
        Err(serde::de::Error::custom("unsupported token type"))
    }
}
fn granted_scopes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Scope>, D::Error> {
    let value = String::deserialize(d)?;
    if value.len() > 4096
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() && byte != b' ')
    {
        return Err(serde::de::Error::custom("invalid scope"));
    }
    Ok(value
        .split_ascii_whitespace()
        .map(|scope| Scope::new(scope.to_owned()))
        .collect())
}

#[derive(Debug)]
struct ExchangeTransportError;
impl fmt::Display for ExchangeTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Google token exchange unavailable")
    }
}
impl std::error::Error for ExchangeTransportError {}

fn token_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(16 * 1024)
            .timeout_global(Some(Duration::from_secs(5)))
            .build();
        ureq::Agent::new_with_config(config)
    })
}

fn json_media_type(headers: &oauth2::http::HeaderMap) -> bool {
    let mut types = headers.get_all("content-type").iter();
    let Some(value) = types.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    types.next().is_none()
        && value
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn exchange_http(request: HttpRequest) -> Result<HttpResponse, ExchangeTransportError> {
    if request.method() != "POST" || *request.uri() != TOKEN_URL || request.body().len() > 16 * 1024
    {
        return Err(ExchangeTransportError);
    }
    let body = Zeroizing::new(request.into_body());
    let mut response = token_agent()
        .post(TOKEN_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .send(body.as_slice())
        .map_err(|_| ExchangeTransportError)?;
    if response.status().as_u16() != 200 || !json_media_type(response.headers()) {
        return Err(ExchangeTransportError);
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_vec()
        .map_err(|_| ExchangeTransportError)?;
    oauth2::http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(bytes)
        .map_err(|_| ExchangeTransportError)
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
