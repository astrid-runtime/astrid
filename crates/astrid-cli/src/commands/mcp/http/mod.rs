//! Streamable HTTP transport over the same authenticated broker as stdio.
//!
//! One endpoint has one operator-selected principal and workspace. HTTP client
//! metadata never selects authority. The shared handler also preserves MRTR
//! keys and one-time redemption across independent stateless requests.

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Router, middleware};
use rmcp::ServerHandler;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

mod auth;
mod handler;
#[cfg(test)]
mod tests;

/// Start an explicitly managed, authenticated loopback MCP listener.
pub(crate) async fn run(
    listen: Option<SocketAddr>,
    token_file: Option<&Path>,
    workspace: Option<&Path>,
) -> Result<ExitCode> {
    let root = std::env::current_dir().context("read MCP runtime directory")?;
    let config =
        astrid_config::Config::load_with_layout(Some(&root), crate::workspace_layout::current())?
            .config;
    let settings = &config.gateway.mcp_http;
    let bind = listen.unwrap_or(settings.listen);
    validate_bind(bind)?;
    let token = auth::BearerToken::read(
        token_file
            .or(settings.token_file.as_deref())
            .context("MCP HTTP requires --token-file or gateway.mcp_http.token_file")?,
    )?;
    let principal = crate::principal::current();
    anyhow::ensure!(
        principal != astrid_core::PrincipalId::anonymous(),
        "MCP HTTP requires a named principal"
    );
    let workspace = workspace
        .unwrap_or(&root)
        .canonicalize()
        .context("resolve MCP workspace")?;
    // Bind and validate credentials before starting any runtime process.
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .context("bind MCP HTTP listener")?;
    let address = listener.local_addr()?;
    crate::commands::daemon::ensure_daemon_quiet("mcp-http", Some(&root)).await?;
    let daemon_pid =
        crate::commands::daemon_control::read_pid_file(&crate::socket_client::pid_path())
            .map(|(pid, _)| pid);
    let session = astrid_core::SessionId::from_uuid(uuid::Uuid::new_v4());
    let mut client =
        crate::socket_client::connect_for_workspace(session, principal.clone(), Some(&root))
            .await?;
    super::require_authenticated_unless_anonymous(&principal, client.is_authenticated())?;
    super::readiness::wait_for_broker(&mut client, &principal).await?;
    let server = Arc::new(super::server::AstridMcpServer::new(
        Arc::new(Mutex::new(client)),
        principal.clone(),
        root.clone(),
        workspace,
    )?);
    let shutdown = CancellationToken::new();
    let endpoint_principal = principal.clone();
    let app = router(
        move || {
            Ok(handler::HttpHandler::new(
                server.clone(),
                endpoint_principal.clone(),
                root.clone(),
            ))
        },
        token,
        address,
        shutdown.clone(),
    );
    eprintln!("MCP Streamable HTTP ready at http://{address}/mcp (principal {principal})");
    let stop = shutdown.clone();
    let serving = axum::serve(listener, app).with_graceful_shutdown(async move {
        shutdown_signal().await;
        stop.cancel();
    });
    let result = serving.await.context("serve MCP HTTP");
    shutdown.cancel();
    crate::commands::daemon::retire_disconnected_projection(daemon_pid).await?;
    result.map(|()| ExitCode::SUCCESS)
}

fn validate_bind(address: SocketAddr) -> Result<()> {
    anyhow::ensure!(
        address.ip().is_loopback(),
        "MCP HTTP must bind to loopback; use an authenticated tunnel for remote access"
    );
    Ok(())
}

fn router<S: ServerHandler + 'static>(
    factory: impl Fn() -> std::io::Result<S> + Send + Sync + 'static,
    token: auth::BearerToken,
    address: SocketAddr,
    shutdown: CancellationToken,
) -> Router {
    // The SDK always serves 2026 statelessly; retain the SDK's session
    // compatibility for older clients, not a separate legacy SSE server.
    let mut config = StreamableHttpServerConfig::default();
    config.json_response = true;
    config.cancellation_token = shutdown;
    config.allowed_hosts = vec![address.to_string(), format!("localhost:{}", address.port())];
    let service =
        StreamableHttpService::new(factory, Arc::new(LocalSessionManager::default()), config);
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(
            Arc::new(token),
            auth::authorize,
        ))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            },
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            },
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
