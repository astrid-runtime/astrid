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

use super::generation_fence::{HostGenerationFence, HostGenerationMismatch};
use crate::commands::daemon;

const INITIAL_RETRY_BACKOFF: Duration = Duration::from_secs(2);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Run until the MCP process exits and Tokio drops this task.
pub(super) async fn run(
    principal: astrid_core::PrincipalId,
    generation_fence: HostGenerationFence,
) {
    let mut retry_backoff = INITIAL_RETRY_BACKOFF;
    loop {
        match hold_guard_uplink(&principal, &generation_fence).await {
            Ok(never) => match never {},
            Err(e) => {
                if is_generation_mismatch(&e) {
                    warn!(error = %e, %principal, "MCP session guard: host session is stale; stopping reconnects");
                    return;
                }
                warn!(error = %e, %principal, "MCP session guard: daemon connection unavailable");
                tokio::time::sleep(retry_backoff).await;
                retry_backoff = retry_backoff.saturating_mul(2).min(MAX_RETRY_BACKOFF);
            },
        }
    }
}

fn is_generation_mismatch(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<astrid_core::DaemonGenerationMismatch>() || cause.is::<HostGenerationMismatch>()
    })
}

async fn hold_guard_uplink(
    principal: &astrid_core::PrincipalId,
    generation_fence: &HostGenerationFence,
) -> Result<std::convert::Infallible> {
    generation_fence
        .validate()
        .context("host generation changed before guard connection")?;
    daemon::ensure_daemon_quiet("mcp-session-guard").await?;

    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let c = crate::socket_client::connect_for_workspace(session, principal.clone(), None)
        .await
        .context("failed to connect guard uplink to daemon")?;

    validate_guard_auth(principal, c.is_authenticated())?;

    debug!(%principal, "MCP session guard: daemon uplink established");
    let mut client = c;
    let mut generation_check = tokio::time::interval(Duration::from_secs(1));
    generation_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            frame = client.read_raw_frame() => match frame {
                Ok(Some(_)) => {},
                Ok(None) => anyhow::bail!("daemon closed guard uplink"),
                Err(e) => return Err(e).context("guard uplink read failed"),
            },
            _ = generation_check.tick() => {
                generation_fence
                    .validate()
                    .context("host generation changed while guard was connected")?;
            },
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

    #[test]
    fn daemon_generation_mismatch_is_terminal() {
        let expected = astrid_core::DaemonGeneration::parse("astrid:1.0.0:new").unwrap();
        let actual = astrid_core::DaemonGeneration::parse("astrid:1.0.0:old").unwrap();
        let error = anyhow::Error::new(astrid_core::DaemonGenerationMismatch::new(
            expected,
            Some(actual),
        ))
        .context("guard connection failed");
        assert!(is_generation_mismatch(&error));
        assert!(!is_generation_mismatch(&anyhow::anyhow!("socket closed")));
    }
}
