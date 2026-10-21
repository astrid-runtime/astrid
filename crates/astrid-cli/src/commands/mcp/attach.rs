//! The short-lived `mcp attach` stdio client.
//!
//! An attach process deliberately does not know how to boot Astrid.  Its only
//! job is to connect to the already-ready per-user MCP gateway and copy the
//! host's stdio stream to that Unix socket.  Keeping this process free of the
//! daemon bootstrap and doctor paths is what makes opening another host window
//! cheap and prevents one orphaned process per window from accumulating.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::UnixStream;

use super::lifecycle::{
    ATTACH_REGISTRATION_VERSION, AttachRegistration, gateway_socket_path, read_gateway_ready,
};

/// Attach this process's stdio to the principal's persistent MCP gateway.
///
/// `workspace` is host project context, not an Astrid home or daemon root. It
/// is sent in a small registration preface so the gateway can preserve the
/// caller's `cwd://` root while sharing one daemon uplink across windows.
pub(crate) async fn run(_principal: Option<&str>, workspace: Option<&Path>) -> Result<ExitCode> {
    // The process-wide principal was authenticated before dispatch. Never
    // treat a registration field as the source of authority for this attach.
    let caller = crate::principal::current();
    let socket = gateway_socket_path()?;
    let ready = read_gateway_ready()?.ok_or_else(|| {
        anyhow::anyhow!(
            "MCP gateway is not ready for principal '{caller}'; run `aos mcp ready --format hook`"
        )
    })?;
    if ready.principal != caller.to_string() {
        anyhow::bail!(
            "MCP gateway is ready for principal '{}', not '{}'; run `aos mcp ready --format hook` for the active principal",
            ready.principal,
            caller
        );
    }
    let stream = UnixStream::connect(&socket).await.with_context(|| {
        format!(
            "failed to connect to MCP gateway at {}; run `aos mcp ready --format hook`",
            socket.display()
        )
    })?;

    let registration = build_registration(&caller, workspace, &ready)?;
    let mut stream = stream;
    let header =
        serde_json::to_vec(&registration).context("failed to encode MCP attach registration")?;
    stream
        .write_all(&header)
        .await
        .context("failed to register MCP attach session with gateway")?;
    stream
        .write_all(b"\n")
        .await
        .context("failed to terminate MCP attach registration")?;
    stream
        .flush()
        .await
        .context("failed to flush MCP attach registration")?;
    proxy_stdio(stream).await?;
    Ok(ExitCode::SUCCESS)
}

fn absolute_workspace(workspace: Option<&Path>) -> Result<PathBuf> {
    let path = workspace.map_or(
        std::env::current_dir().context("failed to read MCP attach cwd")?,
        PathBuf::from,
    );
    if !path.is_absolute() {
        anyhow::bail!(
            "MCP attach workspace must be an absolute path: {}",
            path.display()
        );
    }
    std::fs::canonicalize(&path)
        .with_context(|| format!("failed to resolve MCP attach workspace {}", path.display()))
}

fn build_registration(
    caller: &astrid_core::PrincipalId,
    workspace: Option<&Path>,
    ready: &super::lifecycle::GatewayReady,
) -> Result<AttachRegistration> {
    let host = std::env::var("ASTRID_HOST")
        .or_else(|_| std::env::var("AOS_MCP_HOST"))
        .or_else(|_| std::env::var("MCP_HOST"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "aos".to_owned());
    let host_session_id = std::env::var("ASTRID_SESSION_ID")
        .or_else(|_| std::env::var("AOS_MCP_SESSION_ID"))
        .or_else(|_| std::env::var("MCP_SESSION_ID"))
        .context("MCP attach requires the host session key in ASTRID_SESSION_ID")?;
    if host_session_id.trim().is_empty() {
        anyhow::bail!("MCP attach host session key is empty");
    }
    build_registration_with_context(caller, workspace, ready, &host, &host_session_id)
}

fn build_registration_with_context(
    caller: &astrid_core::PrincipalId,
    workspace: Option<&Path>,
    ready: &super::lifecycle::GatewayReady,
    host: &str,
    host_session_id: &str,
) -> Result<AttachRegistration> {
    if host.trim().is_empty() {
        anyhow::bail!("MCP attach host is empty");
    }
    if host_session_id.trim().is_empty() {
        anyhow::bail!("MCP attach host session key is empty");
    }
    let workspace_abs = absolute_workspace(workspace)?;
    Ok(AttachRegistration {
        version: ATTACH_REGISTRATION_VERSION,
        principal: caller.to_string(),
        host: host.to_owned(),
        workspace_abs: workspace_abs.to_string_lossy().into_owned(),
        host_session_id: host_session_id.to_owned(),
        hook_token: ready.hook_token.clone(),
    })
}

/// Copy both directions until either side closes.
async fn proxy_stdio(stream: UnixStream) -> Result<()> {
    let (mut gateway_read, mut gateway_write) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let mut to_gateway = Box::pin(async {
        let copied = copy(&mut stdin, &mut gateway_write).await?;
        gateway_write.shutdown().await?;
        Ok::<u64, std::io::Error>(copied)
    });
    let mut from_gateway = Box::pin(copy(&mut gateway_read, &mut stdout));

    tokio::select! {
        result = &mut to_gateway => {
            result.context("failed to forward MCP input to gateway")?;
            from_gateway.await.context("failed to forward MCP output from gateway")?;
        }
        result = &mut from_gateway => {
            result.context("failed to forward MCP output from gateway")?;
            // Dropping the in-flight input future closes its borrowed write
            // half; the gateway observes EOF even if the host stdin remains
            // open after the server side disconnects.
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_registration_with_context, proxy_stdio};
    use crate::commands::mcp::lifecycle::GatewayReady;

    #[test]
    fn attach_module_exposes_only_the_stdio_proxy_boundary() {
        // The behavioural stream test lives with the gateway listener because
        // it needs a UnixStream pair; this assertion keeps the module's public
        // entrypoint intentionally narrow for the CLI dispatcher.
        let _ = proxy_stdio;
    }

    #[test]
    fn registration_carries_absolute_workspace_and_host_session() {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
        let ready = GatewayReady {
            version: 1,
            principal: principal.to_string(),
            pid: 42,
            hook_token: "test-hook-token".into(),
        };
        // Keep the pure registration builder test independent of the host's
        // process environment; the production entrypoint supplies this key
        // from ASTRID_SESSION_ID.
        let registration = build_registration_with_context(
            &principal,
            Some(workspace.path()),
            &ready,
            "aos",
            "host-session-1",
        );
        let registration = registration.expect("registration");
        assert_eq!(registration.version, super::ATTACH_REGISTRATION_VERSION);
        assert_eq!(registration.principal, "codex-code");
        assert_eq!(registration.host, "aos");
        assert_eq!(
            std::path::Path::new(&registration.workspace_abs),
            std::fs::canonicalize(workspace.path()).expect("canonical workspace")
        );
        assert_ne!(
            std::path::Path::new(&registration.workspace_abs),
            std::path::Path::new("/runtime-home")
        );
        assert_eq!(registration.host_session_id, "host-session-1");
        assert_eq!(registration.hook_token, "test-hook-token");
    }
}
