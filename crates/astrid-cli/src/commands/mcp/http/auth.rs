//! Bearer authentication before any RMCP dispatch or broker work.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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

    fn accepts(&self, request: &Request) -> bool {
        let mut headers = request.headers().get_all(header::AUTHORIZATION).iter();
        let Some(value) = headers.next() else {
            return false;
        };
        if headers.next().is_some() {
            return false;
        }
        let bytes = value.as_bytes();
        let Some(scheme) = bytes.get(..7) else {
            return false;
        };
        scheme.eq_ignore_ascii_case(b"Bearer ") && bool::from(self.0.as_slice().ct_eq(&bytes[7..]))
    }
}

pub(super) async fn authorize(
    State(token): State<Arc<BearerToken>>,
    request: Request,
    next: Next,
) -> Response {
    // This endpoint serves native MCP clients, not browser scripts. Reject all
    // browser origins (including null) rather than enabling credentialed CORS.
    if request.headers().contains_key(header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !token.accepts(&request) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
pub(super) fn test_token() -> BearerToken {
    BearerToken::from_bytes(Zeroizing::new(vec![b'a'; 32])).unwrap()
}
