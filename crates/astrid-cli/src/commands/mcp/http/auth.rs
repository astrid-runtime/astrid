//! Bearer authentication before any RMCP dispatch or broker work.

use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{AuthMode, oauth};

/// Private file-backed bearer credential.
#[derive(Clone)]
pub(super) struct BearerToken(Zeroizing<Vec<u8>>);

impl BearerToken {
    pub(super) fn read(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::io::Read;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
                .with_context(|| format!("open private MCP token file {}", path.display()))?;
            let meta = file.metadata()?;
            anyhow::ensure!(
                meta.is_file() && meta.permissions().mode().trailing_zeros() >= 6,
                "MCP token must be a regular private file (chmod 600)"
            );
            anyhow::ensure!(
                meta.len() <= 514,
                "MCP token file exceeds the credential format limit"
            );
            let mut bytes = Zeroizing::new(Vec::new());
            // Credential format ceiling, not an operational request limit.
            file.take(514).read_to_end(&mut bytes)?;
            while bytes.last().is_some_and(|b| matches!(b, b'\n' | b'\r')) {
                bytes.pop();
            }
            Self::from_bytes(bytes)
        }
        #[cfg(not(unix))]
        anyhow::bail!(
            "MCP HTTP token file ACL validation is not yet supported on this platform: {}",
            path.display()
        )
    }

    fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        anyhow::ensure!(
            (32..=512).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_graphic),
            "MCP bearer token must contain 32..512 printable non-space ASCII bytes"
        );
        Ok(Self(bytes))
    }

    fn accepts(&self, presented: &[u8]) -> bool {
        bool::from(self.0.as_slice().ct_eq(presented))
    }
}

/// Return the single `Authorization: Bearer` value, or `None` if missing/duplicate.
pub(super) fn bearer_value(request: &Request) -> Option<&[u8]> {
    let mut headers = request.headers().get_all(header::AUTHORIZATION).iter();
    let value = headers.next()?;
    if headers.next().is_some() {
        return None;
    }
    let bytes = value.as_bytes();
    let scheme = bytes.get(..7)?;
    scheme
        .eq_ignore_ascii_case(b"Bearer ")
        .then_some(&bytes[7..])
}

pub(super) async fn authorize(
    State(mode): State<AuthMode>,
    request: Request,
    next: Next,
) -> Response {
    // This endpoint serves native MCP clients, not browser scripts. Reject all
    // browser origins (including null) rather than enabling credentialed CORS.
    if request.headers().contains_key(header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match &mode {
        AuthMode::Token(token) => authorize_token(token, request, next).await,
        AuthMode::Oauth(server) => authorize_oauth(server, request, next).await,
    }
}

async fn authorize_token(token: &Arc<BearerToken>, request: Request, next: Next) -> Response {
    match bearer_value(&request) {
        Some(presented) if token.accepts(presented) => next.run(request).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response(),
    }
}

async fn authorize_oauth(server: &oauth::ResourceServer, request: Request, next: Next) -> Response {
    let Some(presented) = bearer_value(&request).and_then(|value| std::str::from_utf8(value).ok())
    else {
        return oauth_unauthorized(server);
    };
    match server.authenticate_token(presented).await {
        Ok(()) => next.run(request).await,
        Err(oauth::OauthError::MissingScope) => (
            StatusCode::FORBIDDEN,
            [(
                header::WWW_AUTHENTICATE,
                server.insufficient_scope_challenge(),
            )],
        )
            .into_response(),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, server.invalid_token_challenge())],
        )
            .into_response(),
    }
}

fn oauth_unauthorized(server: &oauth::ResourceServer) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, server.challenge())],
    )
        .into_response()
}

#[cfg(test)]
pub(super) fn test_token() -> BearerToken {
    BearerToken::from_bytes(Zeroizing::new(vec![b'a'; 32])).unwrap()
}
