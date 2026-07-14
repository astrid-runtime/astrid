//! MCP session guard: keep one daemon uplink alive for the MCP process lifetime.
//!
//! `astrid mcp serve` is itself the Codex/Claude session handle. The daemon may
//! still be ephemeral: once this process exits, its guard uplink drops and the
//! normal idle timer can shut the daemon down. While this process is alive,
//! though, the daemon should see an authenticated client and should not age out.

use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::commands::daemon;

const INITIAL_RETRY_BACKOFF: Duration = Duration::from_secs(2);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Run until the MCP process exits and Tokio drops this task.
pub(super) async fn run(principal: astrid_core::PrincipalId) {
    let mut retry_backoff = INITIAL_RETRY_BACKOFF;
    loop {
        match hold_guard_uplink(&principal).await {
            Ok(never) => match never {},
            Err(e) => {
                warn!(error = %e, %principal, "MCP session guard: daemon connection unavailable");
                tokio::time::sleep(retry_backoff).await;
                retry_backoff = retry_backoff.saturating_mul(2).min(MAX_RETRY_BACKOFF);
            },
        }
    }
}

async fn hold_guard_uplink(
    principal: &astrid_core::PrincipalId,
) -> Result<std::convert::Infallible> {
    daemon::ensure_daemon_quiet("mcp-session-guard").await?;

    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let c = crate::socket_client::connect_for_workspace(session, principal.clone())
        .await
        .context("failed to connect guard uplink to daemon")?;

    validate_guard_auth(principal, c.is_authenticated())?;

    debug!(%principal, "MCP session guard: daemon uplink established");
    let mut client = c;
    loop {
        match client.read_raw_frame().await {
            Ok(Some(_)) => {},
            Ok(None) => anyhow::bail!("daemon closed guard uplink"),
            Err(e) => return Err(e).context("guard uplink read failed"),
        }
    }
}

fn validate_guard_auth(principal: &astrid_core::PrincipalId, authenticated: bool) -> Result<()> {
    if authenticated || *principal == astrid_core::PrincipalId::anonymous() {
        return Ok(());
    }

    anyhow::bail!(
        "guard uplink authenticated as anonymous instead of requested principal '{principal}'"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_auth_accepts_authenticated_principal() {
        let principal = astrid_core::PrincipalId::new("sibyl-code").unwrap();
        assert!(validate_guard_auth(&principal, true).is_ok());
    }

    #[test]
    fn guard_auth_rejects_anonymous_fallback_for_named_principal() {
        let principal = astrid_core::PrincipalId::new("sibyl-code").unwrap();
        let err = validate_guard_auth(&principal, false)
            .expect_err("named principal must not silently fall back to anonymous");
        assert_eq!(
            err.to_string(),
            "guard uplink authenticated as anonymous instead of requested principal 'sibyl-code'"
        );
    }

    #[test]
    fn guard_auth_allows_explicit_anonymous() {
        assert!(validate_guard_auth(&astrid_core::PrincipalId::anonymous(), false).is_ok());
    }
}
