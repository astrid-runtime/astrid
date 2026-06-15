//! `astrid mcp serve` — a Model Context Protocol stdio server.
//!
//! This subcommand turns the `astrid` CLI into a generic MCP server that
//! a third-party MCP client (Claude Desktop, an IDE, another agent
//! runtime) can launch over stdio. It is a thin **shim**: it speaks the
//! MCP wire protocol on stdin/stdout and translates every `tools/list`
//! and `tools/call` into the daemon's sanitized broker surface over a
//! single long-lived `astrid-cli` uplink.
//!
//! ## Topology
//!
//! ```text
//!   MCP client  <--stdio JSON-RPC-->  astrid mcp serve  <--Unix socket-->  daemon
//!                                       (this module)        (sage-mcp broker)
//! ```
//!
//! * `tools/list`  -> publish `astrid.v1.request.mcp.tools.list`,
//!   await `astrid.v1.response.<req_id>`, reshape to [`ListToolsResult`].
//! * `tools/call`  -> publish `astrid.v1.request.mcp.tool.call`,
//!   await `astrid.v1.response.<req_id>`, reshape to [`CallToolResult`].
//!
//! The broker (`sage-mcp`) mirrors `req_id` into the reply body and
//! publishes on the single-segment topic `astrid.v1.response.<req_id>`,
//! which the shim correlates by matching that exact topic. Each request
//! gets a fresh, charset-clean `req_id` so concurrent in-flight calls
//! never collide on the response topic.
//!
//! ## stdout discipline
//!
//! The MCP transport owns stdout: only JSON-RPC frames may be written
//! there. Every diagnostic in this module goes through `tracing` — never
//! `println!`. `bootstrap::init_logging` forces the log target off stdout
//! for `mcp serve` (to the log file, else stderr) regardless of operator
//! config, so a stray diagnostic can never corrupt the protocol stream.

mod elicit;
mod ingress;
mod server;
mod watch;

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use rmcp::ServiceExt;
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;

use crate::socket_client::SocketClient;

use server::AstridMcpServer;

/// Run the MCP stdio server until the client closes stdin (EOF) or the
/// process is signalled.
///
/// `principal` is the `--principal` flag value; when absent it falls
/// back to the active CLI agent context (or the `default` principal).
/// The resolved principal is stamped onto every outbound IPC message so
/// the kernel scopes tool discovery and execution to that identity.
///
/// # Errors
///
/// Returns an error if the daemon socket is unreachable, the principal
/// is invalid, or the MCP transport fails to initialize.
pub(crate) async fn serve(principal: Option<&str>) -> Result<ExitCode> {
    let caller = crate::context::resolve_agent(principal)
        .context("Failed to resolve principal for `astrid mcp serve`")?;

    let socket_path = crate::socket_client::proxy_socket_path();
    if !socket_path.exists() {
        anyhow::bail!(
            "No Astrid daemon is running (socket not found at {}). \
             Start it with `astrid start` before launching `astrid mcp serve`.",
            socket_path.display()
        );
    }

    // The shim holds ONE uplink connection for its whole lifetime. The
    // session id is ephemeral — it only scopes this transport's frames,
    // not a chat session; the kernel attributes work via the per-message
    // `principal`, not the session.
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let client = SocketClient::connect(session)
        .await
        .context("Failed to connect to the Astrid daemon socket")?;

    info!(
        principal = %caller,
        "astrid mcp serve: uplink established, starting MCP stdio transport"
    );

    let server = AstridMcpServer::new(Arc::new(Mutex::new(client)), caller.to_string());

    // `rmcp::transport::stdio()` yields the (stdin, stdout) pair the MCP
    // transport drives. `serve` performs the MCP handshake and spawns the
    // request loop; `waiting()` blocks until the peer disconnects (EOF)
    // or the service is cancelled.
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .context("Failed to start MCP stdio transport")?;

    // Hot-reload bridge: read the kernel's `capsules_loaded` auto-broadcast
    // (delivered to every uplink; no explicit subscribe) on a dedicated
    // uplink and push `tools/list_changed` to the connected client whenever
    // the broker's tool surface changes. The held
    // peer (cloned from the running service) is the only handle the
    // background task needs; it never touches stdout. The task is detached —
    // if the watch uplink dies, tool-list pushes simply stop, but the server
    // keeps serving `tools/list`/`tools/call` on demand.
    let peer = running.peer().clone();
    tokio::spawn(watch::run(peer, caller.to_string()));

    let quit_reason = running
        .waiting()
        .await
        .context("MCP stdio transport terminated abnormally")?;

    info!(?quit_reason, "astrid mcp serve: MCP transport closed");
    Ok(ExitCode::SUCCESS)
}
