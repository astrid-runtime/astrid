//! CLI re-export shim for the shared
//! [`astrid_uplink::SocketClient`](::astrid_uplink::socket_client::SocketClient).
//!
//! Everything except the CLI-specific `send_input` resolution lives in
//! the shared crate now; this module keeps the historical import path
//! (`crate::socket_client::*`) working without churning every caller.

pub(crate) use astrid_uplink::socket_client::{
    SocketClient, pid_path, proxy_socket_path, readiness_path,
};

use std::future::Future;

use anyhow::Result;
use astrid_uplink::KernelClient;

enum KernelConnectionScope<'a> {
    Workspace(Option<&'a std::path::Path>),
    Recovery,
}

impl<'a> KernelConnectionScope<'a> {
    const fn requires_workspace_check(&self) -> bool {
        matches!(self, Self::Workspace(_))
    }

    fn workspace_root(self) -> Option<&'a std::path::Path> {
        match self {
            Self::Workspace(workspace_root) => workspace_root,
            Self::Recovery => None,
        }
    }
}

pub(crate) async fn connect_for_workspace(
    session: astrid_core::SessionId,
    principal: astrid_core::PrincipalId,
    workspace_root: Option<&std::path::Path>,
) -> WorkspaceConnectionResult<SocketClient> {
    connect_workspace_client(workspace_root, || SocketClient::connect(session, principal)).await
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkspaceConnectionError {
    #[error("{0:#}")]
    Selection(#[source] anyhow::Error),
    #[error("{0:#}")]
    Connect(#[source] anyhow::Error),
}

pub(crate) type WorkspaceConnectionResult<T> = std::result::Result<T, WorkspaceConnectionError>;

/// Connect any workspace-sensitive daemon client between two selection checks.
///
/// Checking before the connection prevents authentication against the wrong
/// daemon. Checking again afterwards catches a daemon restart that retargeted
/// the global socket during the handshake.
pub(crate) async fn connect_workspace_client<T, Connect, ConnectFuture>(
    workspace_root: Option<&std::path::Path>,
    connect: Connect,
) -> WorkspaceConnectionResult<T>
where
    Connect: FnOnce() -> ConnectFuture,
    ConnectFuture: Future<Output = Result<T>>,
{
    connect_between_workspace_checks(
        || crate::commands::daemon::ensure_daemon_workspace_matches(workspace_root),
        connect,
    )
    .await
}

/// Connect a kernel-management client for state belonging to the selected
/// project and workspace layout.
///
/// Readiness metadata must match before the management socket is opened, so a
/// mismatched CLI neither authenticates nor issues a project-sensitive request
/// to a daemon owned by another project.
pub(crate) async fn connect_kernel_for_workspace(
    workspace_root: Option<&std::path::Path>,
) -> Result<KernelClient> {
    connect_kernel(KernelConnectionScope::Workspace(workspace_root)).await
}

/// Connect for a daemon lifecycle recovery operation.
///
/// Recovery must remain possible when the running daemon belongs to another
/// project or layout. Keep this restricted to operations such as `stop` that
/// terminate the process and do not read or mutate project-owned daemon state.
pub(crate) async fn connect_kernel_for_recovery() -> Result<KernelClient> {
    connect_kernel(KernelConnectionScope::Recovery).await
}

async fn connect_kernel(scope: KernelConnectionScope<'_>) -> Result<KernelClient> {
    if scope.requires_workspace_check() {
        let workspace_root = scope.workspace_root();
        return Ok(connect_workspace_client(workspace_root, || {
            KernelClient::connect(crate::principal::current())
        })
        .await?);
    }
    KernelClient::connect(crate::principal::current()).await
}

async fn connect_between_workspace_checks<T, Check, CheckFuture, Connect, ConnectFuture>(
    mut check: Check,
    connect: Connect,
) -> WorkspaceConnectionResult<T>
where
    Check: FnMut() -> CheckFuture,
    CheckFuture: Future<Output = Result<()>>,
    Connect: FnOnce() -> ConnectFuture,
    ConnectFuture: Future<Output = Result<T>>,
{
    check().await.map_err(WorkspaceConnectionError::Selection)?;
    let client = connect().await.map_err(WorkspaceConnectionError::Connect)?;
    check().await.map_err(WorkspaceConnectionError::Selection)?;
    Ok(client)
}

/// Send a user prompt over an established uplink.
///
/// The connection is already bound to the process principal (resolved
/// once at startup from `--principal` / `ASTRID_PRINCIPAL` / `default`),
/// so [`SocketClient::send_input`] stamps that identity — no per-call
/// resolution. Kept as a thin named seam so callers read intent
/// (`send_input_as_active_agent`) without re-resolving.
///
/// # Errors
/// Returns an error if the underlying send fails.
pub(crate) async fn send_input_as_active_agent(
    client: &mut SocketClient,
    text: String,
) -> Result<()> {
    client.send_input(text).await
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future;
    use std::path::Path;

    use super::{
        KernelConnectionScope, WorkspaceConnectionError, connect_between_workspace_checks,
    };

    #[test]
    fn kernel_connection_scope_checks_project_reads_but_keeps_recovery_global() {
        let explicit = Path::new("/selected/project");
        let explicit_scope = KernelConnectionScope::Workspace(Some(explicit));
        assert!(explicit_scope.requires_workspace_check());
        assert_eq!(explicit_scope.workspace_root(), Some(explicit));

        let default_scope = KernelConnectionScope::Workspace(None);
        assert!(default_scope.requires_workspace_check());
        assert_eq!(default_scope.workspace_root(), None);

        let recovery_scope = KernelConnectionScope::Recovery;
        assert!(!recovery_scope.requires_workspace_check());
        assert_eq!(recovery_scope.workspace_root(), None);
    }

    #[tokio::test]
    async fn workspace_mismatch_prevents_connection() {
        let connected = Cell::new(false);
        let result = connect_between_workspace_checks(
            || future::ready(Err(anyhow::anyhow!("workspace mismatch"))),
            || async {
                connected.set(true);
                Ok(())
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(WorkspaceConnectionError::Selection(_))
        ));
        assert!(!connected.get());
    }

    #[tokio::test]
    async fn post_connection_mismatch_rejects_retargeted_client() {
        let checks = Cell::new(0_u8);
        let connected = Cell::new(false);
        let result = connect_between_workspace_checks(
            || {
                checks.set(checks.get() + 1);
                future::ready(if checks.get() == 1 {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("daemon restarted for another workspace"))
                })
            },
            || async {
                connected.set(true);
                Ok(())
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(result, WorkspaceConnectionError::Selection(_)));
        assert!(connected.get());
        assert_eq!(checks.get(), 2);
    }

    #[tokio::test]
    async fn matching_workspace_connects_between_two_checks() {
        let checks = Cell::new(0_u8);
        let client = connect_between_workspace_checks(
            || {
                checks.set(checks.get() + 1);
                future::ready(Ok(()))
            },
            || async { Ok(42_u8) },
        )
        .await
        .unwrap();

        assert_eq!(client, 42);
        assert_eq!(checks.get(), 2);
    }
}
