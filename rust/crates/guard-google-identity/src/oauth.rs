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
use std::time::Duration;
use zeroize::Zeroizing;

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
    challenge: GoogleLoginChallenge,
    state: CsrfToken,
    verifier: PkceCodeVerifier,
    client_session_binding: String,
    authorization_url: String,
}

/// Private credential material remains in the worker. No Clone, Debug,
/// serialization or token getter. A successful callback is not enrollment.
pub struct GoogleSendCredential {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    identity: GoogleIdentityEvidence,
    expires_at: u64,
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
        challenge.check_time(now()?)?;
        if !bounded_ascii(&registered_client_secret, 4096)
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
            .set_client_secret(ClientSecret::new(registered_client_secret))
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
            challenge,
            state,
            verifier,
            client_session_binding: authenticated_client_session_binding,
            authorization_url: url.to_string(),
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
        self.challenge.check_time(now()?)?;
        if !bounded_ascii(callback_state, 256)
            || !bounded_ascii(&code, 8192)
            || self.state != CsrfToken::new(callback_state.to_owned())
            || self.client_session_binding != session_binding
        {
            return Err(IdentityError::Invalid);
        }
        let response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(self.verifier)
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
        let expires_at = received_at
            .saturating_add(response.expires_in)
            .min(identity.expires_at());
        if observed >= expires_at || !bounded_ascii(response.access_token.secret(), 8192) {
            return Err(IdentityError::Expired);
        }
        Ok(GoogleSendCredential {
            access_token: Zeroizing::new(response.access_token.secret().to_owned()),
            refresh_token: response
                .refresh_token
                .as_ref()
                .map(|value| Zeroizing::new(value.secret().to_owned())),
            identity,
            expires_at,
        })
    }
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

fn exchange_http(request: HttpRequest) -> Result<HttpResponse, ExchangeTransportError> {
    if request.method() != "POST" || *request.uri() != TOKEN_URL || request.body().len() > 16 * 1024
    {
        return Err(ExchangeTransportError);
    }
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .max_response_header_size(16 * 1024)
        .timeout_global(Some(Duration::from_secs(5)))
        .build();
    let mut response = ureq::Agent::new_with_config(config)
        .post(TOKEN_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .send(request.body())
        .map_err(|_| ExchangeTransportError)?;
    if response.status().as_u16() != 200 {
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
