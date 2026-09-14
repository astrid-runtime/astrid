//! OAuth 2.1 protected-resource validation for `astrid mcp http`.
//!
//! This module is a resource server: it validates bearer JWTs against a JWKS
//! and never issues tokens or starts an authorization server.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use astrid_config::gateway::McpHttpOauthSection;
use astrid_core::PrincipalId;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::{Value, json};

/// Why a bearer JWT was rejected. HTTP mapping is always 401.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OauthError {
    /// JWT is missing, malformed, unsigned, or otherwise unverifiable.
    InvalidToken,
    /// Header `alg` is HMAC (`HS256`/`HS384`/`HS512`).
    HmacAlgorithm,
    /// No matching `kid` after the cached JWKS (and one refresh, if any).
    UnknownKey,
    /// Matched JWK is an octet/HMAC key.
    SymmetricKey,
    /// `exp` is in the past.
    Expired,
    /// `nbf` is in the future.
    Immature,
    /// `iss` is not the configured issuer.
    InvalidIssuer,
    /// `aud` does not contain the configured resource.
    InvalidAudience,
    /// Principal claim is missing or not the process principal.
    PrincipalMismatch,
    /// Token is missing a required scope.
    MissingScope,
    /// `azp` is absent or outside the allowlist.
    AzpDenied,
}

/// Asymmetric JWT resource server bound to one process principal.
#[derive(Clone)]
pub(super) struct ResourceServer {
    config: McpHttpOauthSection,
    principal: PrincipalId,
    jwks: Arc<RwLock<JwkSet>>,
    client: Option<reqwest::Client>,
    refresh: Arc<tokio::sync::Mutex<Option<Instant>>>,
}

#[derive(Debug, Deserialize)]
struct AccessClaims {
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(flatten)]
    rest: serde_json::Map<String, Value>,
}

/// Minimum interval between JWKS refresh attempts after an unknown key ID.
///
/// Initial JWKS retrieval still happens before bind. This backoff prevents an
/// unauthenticated client from turning arbitrary `kid` values into an outbound
/// request flood while allowing key rotation to become visible promptly.
const JWKS_REFRESH_BACKOFF: Duration = Duration::from_mins(1);

impl ResourceServer {
    /// Fetch JWKS over HTTPS and fail closed before the listener binds.
    pub(super) async fn connect(
        config: McpHttpOauthSection,
        principal: PrincipalId,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(10))
            .build()
            .context("build JWKS HTTPS client")?;
        let jwks = fetch_jwks(&client, &config.jwks_url).await?;
        Ok(Self {
            config,
            principal,
            jwks: Arc::new(RwLock::new(jwks)),
            client: Some(client),
            refresh: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    /// Install a static JWKS with no network client (tests).
    #[cfg(test)]
    pub(super) fn with_jwks(
        config: McpHttpOauthSection,
        principal: PrincipalId,
        jwks: JwkSet,
    ) -> Self {
        Self {
            config,
            principal,
            jwks: Arc::new(RwLock::new(jwks)),
            client: None,
            refresh: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Validate a compact JWT against this resource and process principal.
    pub(super) async fn authenticate_token(&self, token: &str) -> Result<(), OauthError> {
        let header = decode_header(token).map_err(|_| OauthError::InvalidToken)?;
        reject_hmac(header.alg)?;
        let kid = header.kid.as_deref().ok_or(OauthError::UnknownKey)?;
        let jwk = self.resolve_jwk(kid).await?;
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            return Err(OauthError::SymmetricKey);
        }
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| OauthError::InvalidToken)?;
        let claims = decode_access_claims(token, &key, header.alg, &self.config)?;
        self.authorize_claims(&claims)
    }

    /// RFC 6750 challenge advertising RFC 9728 metadata at the resource origin.
    #[must_use]
    pub(super) fn challenge(&self) -> String {
        let mut header = format!(
            "Bearer realm=\"mcp\", resource_metadata=\"{}\"",
            protected_resource_metadata_url(&self.config.resource)
        );
        if !self.config.scopes.is_empty() {
            header.push_str(", scope=\"");
            header.push_str(&self.config.scopes.join(" "));
            header.push('"');
        }
        header
    }

    #[must_use]
    pub(super) fn invalid_token_challenge(&self) -> String {
        format!("{}, error=\"invalid_token\"", self.challenge())
    }

    #[must_use]
    pub(super) fn insufficient_scope_challenge(&self) -> String {
        format!("{}, error=\"insufficient_scope\"", self.challenge())
    }

    /// Host values RMCP should accept in addition to the loopback bind.
    #[must_use]
    pub(super) fn resource_hosts(&self) -> Vec<String> {
        resource_hosts(&self.config.resource)
    }

    /// Unauthenticated RFC 9728 metadata routes. Call [`Router::with_state`].
    pub(super) fn metadata_router() -> Router<Self> {
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource_metadata),
            )
            .route(
                "/.well-known/oauth-protected-resource/{*suffix}",
                get(path_aware_metadata),
            )
    }

    fn metadata(&self) -> Value {
        json!({
            "resource": self.config.resource,
            "authorization_servers": [self.config.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": self.config.scopes,
            "resource_name": "Astrid MCP",
        })
    }

    fn path_suffix(&self) -> Option<String> {
        resource_path_suffix(&self.config.resource)
    }

    fn authorize_claims(&self, claims: &AccessClaims) -> Result<(), OauthError> {
        self.check_principal(claims)?;
        self.check_scopes(claims)?;
        self.check_azp(claims)
    }

    fn check_principal(&self, claims: &AccessClaims) -> Result<(), OauthError> {
        let Some(Value::String(value)) = claims.rest.get(&self.config.principal_claim) else {
            return Err(OauthError::PrincipalMismatch);
        };
        if value == self.principal.as_str() {
            Ok(())
        } else {
            Err(OauthError::PrincipalMismatch)
        }
    }

    fn check_scopes(&self, claims: &AccessClaims) -> Result<(), OauthError> {
        if self.config.scopes.is_empty() {
            return Ok(());
        }
        let granted: Vec<&str> = claims
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if self
            .config
            .scopes
            .iter()
            .all(|required| granted.contains(&required.as_str()))
        {
            Ok(())
        } else {
            Err(OauthError::MissingScope)
        }
    }

    fn check_azp(&self, claims: &AccessClaims) -> Result<(), OauthError> {
        if self.config.allowed_azp.is_empty() {
            return Ok(());
        }
        let Some(azp) = claims.azp.as_deref() else {
            return Err(OauthError::AzpDenied);
        };
        if self.config.allowed_azp.iter().any(|allowed| allowed == azp) {
            Ok(())
        } else {
            Err(OauthError::AzpDenied)
        }
    }

    async fn resolve_jwk(&self, kid: &str) -> Result<Jwk, OauthError> {
        if let Some(jwk) = self.find_jwk(kid) {
            return Ok(jwk);
        }
        if self.client.is_some() {
            self.refresh_jwks().await?;
            if let Some(jwk) = self.find_jwk(kid) {
                return Ok(jwk);
            }
        }
        Err(OauthError::UnknownKey)
    }

    fn find_jwk(&self, kid: &str) -> Option<Jwk> {
        let guard = self.jwks.read().ok()?;
        guard.find(kid).cloned()
    }

    async fn refresh_jwks(&self) -> Result<(), OauthError> {
        let client = self.client.as_ref().ok_or(OauthError::UnknownKey)?;
        let mut last_attempt = self.refresh.lock().await;
        let now = Instant::now();
        if !jwks_refresh_due(*last_attempt, now) {
            return Err(OauthError::UnknownKey);
        }
        *last_attempt = Some(now);
        let jwks = fetch_jwks(client, &self.config.jwks_url)
            .await
            .map_err(|_| OauthError::UnknownKey)?;
        let Ok(mut guard) = self.jwks.write() else {
            return Err(OauthError::InvalidToken);
        };
        *guard = jwks;
        Ok(())
    }
}

fn jwks_refresh_due(last_attempt: Option<Instant>, now: Instant) -> bool {
    last_attempt
        .is_none_or(|attempt| now.saturating_duration_since(attempt) >= JWKS_REFRESH_BACKOFF)
}

async fn fetch_jwks(client: &reqwest::Client, url: &str) -> Result<JwkSet> {
    let url = reqwest::Url::parse(url).context("parse JWKS URL")?;
    anyhow::ensure!(
        url.scheme() == "https" && url.host().is_some(),
        "JWKS URL must use HTTPS and include a host"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "JWKS URL must not contain userinfo"
    );
    let response = client.get(url).send().await.context("fetch JWKS")?;
    anyhow::ensure!(
        response.status().is_success(),
        "JWKS HTTP {}",
        response.status()
    );
    let jwks = response.json::<JwkSet>().await.context("parse JWKS")?;
    anyhow::ensure!(!jwks.keys.is_empty(), "JWKS contains no keys");
    Ok(jwks)
}

fn reject_hmac(alg: Algorithm) -> Result<(), OauthError> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => Err(OauthError::HmacAlgorithm),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::EdDSA => Ok(()),
    }
}

fn decode_access_claims(
    token: &str,
    key: &DecodingKey,
    alg: Algorithm,
    config: &McpHttpOauthSection,
) -> Result<AccessClaims, OauthError> {
    let mut validation = Validation::new(alg);
    validation.validate_nbf = true;
    validation.leeway = 0;
    validation.set_issuer(std::slice::from_ref(&config.issuer));
    validation.set_audience(std::slice::from_ref(&config.resource));
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    decode::<AccessClaims>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|error| map_jwt_error(&error))
}

fn map_jwt_error(error: &jsonwebtoken::errors::Error) -> OauthError {
    match error.kind() {
        ErrorKind::ExpiredSignature => OauthError::Expired,
        ErrorKind::ImmatureSignature => OauthError::Immature,
        ErrorKind::InvalidIssuer => OauthError::InvalidIssuer,
        ErrorKind::InvalidAudience => OauthError::InvalidAudience,
        _ => OauthError::InvalidToken,
    }
}

fn protected_resource_metadata_url(resource: &str) -> String {
    let Ok(url) = url::Url::parse(resource) else {
        return resource.to_owned();
    };
    let origin = url.origin().ascii_serialization();
    match resource_path_suffix(resource) {
        Some(suffix) => format!("{origin}/.well-known/oauth-protected-resource/{suffix}"),
        None => format!("{origin}/.well-known/oauth-protected-resource"),
    }
}

fn resource_hosts(resource: &str) -> Vec<String> {
    let Ok(url) = url::Url::parse(resource) else {
        return Vec::new();
    };
    let Some(host) = url.host() else {
        return Vec::new();
    };
    let host = match host {
        url::Host::Domain(value) => value.to_owned(),
        url::Host::Ipv4(value) => value.to_string(),
        url::Host::Ipv6(value) => format!("[{value}]"),
    };
    let mut hosts = vec![host.clone()];
    if let Some(port) = url.port() {
        hosts.push(format!("{host}:{port}"));
    }
    hosts
}

fn resource_path_suffix(resource: &str) -> Option<String> {
    let url = url::Url::parse(resource).ok()?;
    let path = url.path().trim_matches('/');
    if path.is_empty() {
        None
    } else {
        Some(path.to_owned())
    }
}

async fn protected_resource_metadata(State(server): State<ResourceServer>) -> Response {
    match server.path_suffix() {
        None => Json(server.metadata()).into_response(),
        Some(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn path_aware_metadata(
    State(server): State<ResourceServer>,
    Path(suffix): Path<String>,
) -> Response {
    match server.path_suffix() {
        Some(expected) if expected == suffix => Json(server.metadata()).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
pub(super) fn test_config() -> McpHttpOauthSection {
    McpHttpOauthSection {
        resource: "https://mcp.example.com/mcp".to_owned(),
        issuer: "https://issuer.example.com".to_owned(),
        jwks_url: "https://issuer.example.com/jwks".to_owned(),
        scopes: vec!["mcp".to_owned()],
        principal_claim: "sub".to_owned(),
        allowed_azp: Vec::new(),
    }
}

#[cfg(test)]
pub(super) fn test_jwks() -> JwkSet {
    use jsonwebtoken::jwk::{CommonParameters, KeyAlgorithm, RSAKeyParameters, RSAKeyType};
    JwkSet {
        keys: vec![Jwk {
            common: CommonParameters {
                key_id: Some("test".to_owned()),
                key_algorithm: Some(KeyAlgorithm::RS256),
                ..CommonParameters::default()
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: TEST_N.to_owned(),
                e: "AQAB".to_owned(),
            }),
        }],
    }
}

#[cfg(test)]
pub(super) fn test_principal() -> PrincipalId {
    PrincipalId::new("agent-1").unwrap()
}

#[cfg(test)]
pub(super) fn test_server() -> ResourceServer {
    ResourceServer::with_jwks(test_config(), test_principal(), test_jwks())
}

#[cfg(test)]
pub(super) fn valid_claims() -> Value {
    let now = jsonwebtoken::get_current_timestamp();
    json!({
        "iss": "https://issuer.example.com",
        "aud": "https://mcp.example.com/mcp",
        "sub": "agent-1",
        "exp": now.saturating_add(3600),
        "nbf": now.saturating_sub(60),
        "scope": "mcp",
    })
}

#[cfg(test)]
pub(super) fn encode_rs256(claims: &Value) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test".to_owned());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(TEST_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[cfg(test)]
const TEST_N: &str = "rYIn6Ek0mVKErKHq9S5YuQGVjSrtfLNiKDy4Xk-d6-6EcT21VCeYtFvKWnIjNVs_ZnsWuHd9_fBKpHG89BQcI_6viIe0Ijzry_WneGC1aqpp-8meM0sWg3YK6uRB_KyfP_8lEeHAqT5cqIMZXTGjlU7sJUV6Aauf3y47KKf8rTRH0zni47kFa4HxTyxKiJLmGbQnVYglg2A7S5GbfBxUKsheGRbeQ5TbGefEKrHcwcQx3LL2gWyklZYAQPOREDwsu4GGpiKhDlVapLoebaWaZ4xbyJhSXWxtSroV1Q_548jJcRdmTUSLp6-upihMd7wanXbg_Km27NgK9-6gUOvdSQ";

#[cfg(test)]
const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtgifoSTSZUoSs
oer1Lli5AZWNKu18s2IoPLheT53r7oRxPbVUJ5i0W8paciM1Wz9mexa4d3398Eqk
cbz0FBwj/q+Ih7QiPOvL9ad4YLVqqmn7yZ4zSxaDdgrq5EH8rJ8//yUR4cCpPlyo
gxldMaOVTuwlRXoBq5/fLjsop/ytNEfTOeLjuQVrgfFPLEqIkuYZtCdViCWDYDtL
kZt8HFQqyF4ZFt5DlNsZ58QqsdzBxDHcsvaBbKSVlgBA85EQPCy7gYamIqEOVVqk
uh5tpZpnjFvImFJdbG1KuhXVD/njyMlxF2ZNRIunr66mKEx3vBqdduD8qbbs2Ar3
7qBQ691JAgMBAAECggEAO2IWgnu7ktYZLnRkU/G+z+Lo6l3M1icW6yqM90pMhFkn
3xH9o4XBz8iyou35euN1+X8bMZtD9ctt4IZE40yWrQMX1KSNVEKBeVbkMGD49j7I
8zH4ARor5GZcKjRhGTeDcYXDjDE1nTcIw2vLHIhGsm1GiSMUNMomd139RVbpNeXk
LCYsGwIXWpsDnf/JvtQ3ysWrg+XqSB5hoZH7RKJ9NDvSN0+9BJ/RwpfWDFDqqAEn
qccN+hGzf3yS1LxKeFwyCOMjwxtuTMj09Bndi1pBOhJW6MyW6AIJLZkMN1WmLY3q
QzcGIvpDZOPjBwpxZXwdnBUzSQbqZXDkGAF33LB0+QKBgQDhwi4kzH9B65W+y8M3
DYyvJRiN7ao36W2IEY/jbvk4uE1MkVzXhqJUAUhSQ+zdlA9n0OKUh5xZYmSMSvTB
4G2AjIRfhUX3Q1O69Zy6xnQGQd49EkLBWWz5N5sskA56ZseHi0tENPxeyyC/+ft+
bxMwsEIhA9lA7VCmGdwluaJUuwKBgQDEwDCyI5KT5fneLi7NgpSN2E8ap5ruGmiO
efLH4svvM3e7DNoMWWn5iz1aEZqenJO3oyVebMWdqKhr42D+11jE0up5KgwmN9oX
VC/tsb3o692K2f680CAJRfnMHZvVggaT/e7ny7eQjgsKlDC52yBaTK4r8GOVs0Ao
WA/4LlO3ywKBgBgewQNZffczDmq2JoNJRVCpK/ht/hO/Mt6o0bDA+Iug1VFq7npw
fgNvp6RycWozGXpEDRFFc+Tw6EE8+O2F5u0nFjWGbbU/UkDVYQtrjJXmj7ICs3Mo
9MWjtUaLlaBqPsMylLYS2yvdlAAu2znk8C3xhv80BBA1yroUZTr6nGdlAoGAP6nI
l/u2tDCYF3JuJoV4OCWkAwX0tdLJvkBrdI5IWtAWj+nqrFBKYDrT0U8c7vHPQn6B
2vnrP8aRKMfcXNmlmZp90FLwt3UfFqlhENKQlsurVgCP0tytYRLJb2itQfre0gg6
w7pBXX74x6WH1ru2zkE9om4YaxojSmqkUDP9Vt0CgYEAlsZ2NJWgmoeBL0l6qhl+
QM6BuVI8x6b3GMgG58yNIX5pfEN+YZgml9D56lrQUcDjZN6v/EgaMzGjCcXY6K46
uX/Mk+OX4GcSBr7NBltGuhNB1qrdYBMr5zhwD2Ijg7UMWS38VA8iIAemGaMWxstV
Ab2kTTqrGmX1ZmCvBNVTU/I=
-----END PRIVATE KEY-----
";

#[cfg(test)]
const ALG_NONE_TOKEN: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vbWNwLmV4YW1wbGUuY29tL21jcCIsInN1YiI6ImFnZW50LTEiLCJleHAiOjQxMDI0NDQ4MDB9.";

#[cfg(test)]
pub(super) fn invalid_bearer_samples() -> Vec<(&'static str, String)> {
    invalid_token_cases()
        .into_iter()
        .map(|(name, token, _)| (name, token))
        .collect()
}

#[cfg(test)]
fn invalid_token_cases() -> Vec<(&'static str, String, OauthError)> {
    let now = jsonwebtoken::get_current_timestamp();
    let mut wrong_iss = valid_claims();
    wrong_iss["iss"] = json!("https://other.example");
    let mut wrong_aud = valid_claims();
    wrong_aud["aud"] = json!("https://mcp.example.com/other");
    let mut expired = valid_claims();
    expired["exp"] = json!(now.saturating_sub(10));
    let mut immature = valid_claims();
    immature["nbf"] = json!(now.saturating_add(120));
    let mut foreign = valid_claims();
    foreign["sub"] = json!("agent-2");
    let mut missing_scope = valid_claims();
    missing_scope.as_object_mut().unwrap().remove("scope");
    vec![
        ("iss", encode_rs256(&wrong_iss), OauthError::InvalidIssuer),
        ("aud", encode_rs256(&wrong_aud), OauthError::InvalidAudience),
        ("exp", encode_rs256(&expired), OauthError::Expired),
        ("nbf", encode_rs256(&immature), OauthError::Immature),
        (
            "principal",
            encode_rs256(&foreign),
            OauthError::PrincipalMismatch,
        ),
        (
            "scope",
            encode_rs256(&missing_scope),
            OauthError::MissingScope,
        ),
        ("none", ALG_NONE_TOKEN.to_owned(), OauthError::InvalidToken),
        ("hmac", encode_hs256(), OauthError::HmacAlgorithm),
    ]
}

#[cfg(test)]
fn encode_hs256() -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test".to_owned());
    encode(
        &header,
        &valid_claims(),
        &EncodingKey::from_secret(b"hmac-secret-material-for-test"),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn valid_rs256_token_is_accepted() {
        let token = encode_rs256(&valid_claims());
        assert_eq!(test_server().authenticate_token(&token).await, Ok(()));
    }

    #[tokio::test]
    async fn invalid_tokens_map_to_exact_oauth_errors() {
        let server = test_server();
        for (name, token, expected) in invalid_token_cases() {
            let result = server.authenticate_token(&token).await;
            assert_eq!(result, Err(expected), "{name}");
        }
    }

    #[tokio::test]
    async fn azp_allowlist_rejects_unknown_parties() {
        let mut config = test_config();
        config.allowed_azp = vec!["trusted-client".to_owned()];
        let server = ResourceServer::with_jwks(config, test_principal(), test_jwks());
        let mut claims = valid_claims();
        claims["azp"] = json!("other-client");
        let token = encode_rs256(&claims);
        assert_eq!(
            server.authenticate_token(&token).await,
            Err(OauthError::AzpDenied)
        );
        claims["azp"] = json!("trusted-client");
        let token = encode_rs256(&claims);
        assert_eq!(server.authenticate_token(&token).await, Ok(()));
    }

    #[test]
    fn jwks_refresh_attempts_are_backed_off() {
        let now = Instant::now();
        assert!(jwks_refresh_due(None, now));
        assert!(!jwks_refresh_due(Some(now), now));
        assert!(!jwks_refresh_due(
            now.checked_sub(Duration::from_secs(59)),
            now
        ));
        assert!(jwks_refresh_due(now.checked_sub(JWKS_REFRESH_BACKOFF), now));
    }

    #[test]
    fn metadata_url_and_host_preserve_resource_authority() {
        assert_eq!(
            protected_resource_metadata_url("https://mcp.example.com/mcp"),
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            protected_resource_metadata_url("https://[2001:db8::1]:8443/mcp"),
            "https://[2001:db8::1]:8443/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            resource_hosts("https://[2001:db8::1]:8443/mcp"),
            vec!["[2001:db8::1]", "[2001:db8::1]:8443"]
        );
    }
}
