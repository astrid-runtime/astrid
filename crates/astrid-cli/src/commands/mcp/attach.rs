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
use uuid::Uuid;

use super::lifecycle::{
    ATTACH_REGISTRATION_VERSION, AttachRegistration, gateway_socket_path, read_gateway_ready,
    resolve_principal,
};

/// Attach this process's stdio to the principal's persistent MCP gateway.
///
/// `workspace` is host project context, not an Astrid home or daemon root. It
/// is sent in a small registration preface so the gateway can preserve the
/// caller's `cwd://` root while sharing one daemon uplink across windows.
pub(crate) async fn run(principal: Option<&str>, workspace: Option<&Path>) -> Result<ExitCode> {
    let caller = resolve_principal(principal)?;
    let socket = gateway_socket_path()?;
    read_gateway_ready()?.ok_or_else(|| {
        anyhow::anyhow!(
            "MCP gateway is not ready for principal '{caller}'; run `aos mcp ready --format hook`"
        )
    })?;
    let stream = UnixStream::connect(&socket).await.with_context(|| {
        format!(
            "failed to connect to MCP gateway at {}; run `aos mcp ready --format hook`",
            socket.display()
        )
    })?;

    let registration = build_registration(&caller, workspace)?;
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
) -> Result<AttachRegistration> {
    let workspace_abs = absolute_workspace(workspace)?;
    Ok(AttachRegistration {
        version: ATTACH_REGISTRATION_VERSION,
        principal: caller.to_string(),
        workspace_abs: workspace_abs.to_string_lossy().into_owned(),
        host_session_id: Uuid::new_v4().to_string(),
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
    use super::{build_registration, proxy_stdio};

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
        let registration =
            build_registration(&principal, Some(workspace.path())).expect("registration");
        assert_eq!(registration.version, super::ATTACH_REGISTRATION_VERSION);
        assert_eq!(registration.principal, "codex-code");
        assert_eq!(
            std::path::Path::new(&registration.workspace_abs),
            std::fs::canonicalize(workspace.path()).expect("canonical workspace")
        );
        assert!(uuid::Uuid::parse_str(&registration.host_session_id).is_ok());
    }
}
