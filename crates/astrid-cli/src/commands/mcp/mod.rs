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

/// Refuse to serve the MCP bridge silently as the no-capability `anonymous`
/// identity.
///
/// `astrid mcp serve --principal X` connects, but if `X` has no keypair the
/// handshake falls to the legacy single-frame path and the daemon stamps the
/// connection `anonymous`. The bridge would then come up "successfully" yet
/// every `tools/call` fails the ingress-trust and capability checks — to a
/// client it just hangs/times out, with no hint why. This turns that silent,
/// confusing failure into a loud, actionable error at startup.
///
/// Requesting `anonymous` explicitly (`--principal anonymous`) is allowed:
/// serving unauthenticated is then a deliberate choice, not an accident.
fn require_authenticated_unless_anonymous(
    caller: &astrid_core::PrincipalId,
    authenticated: bool,
) -> Result<()> {
    if authenticated || *caller == astrid_core::PrincipalId::anonymous() {
        return Ok(());
    }
    anyhow::bail!(
        "could not authenticate as principal '{caller}' for `astrid mcp serve`: \
         no keypair found (keys/{caller}.key), so the daemon would bind this \
         connection to the no-capability `anonymous` identity. Every tool call \
         would then fail the ingress-trust and capability checks and appear to \
         hang. Refusing to serve the MCP bridge as `anonymous`.\n\n\
         Fix: run `astrid agent create {caller}` to mint its keypair (or \
         back-fill an existing keyless principal's), then retry. To serve \
         unauthenticated on purpose, pass `--principal anonymous`."
    );
}

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
    // The subcommand `--principal` is an explicit per-invocation
    // override; when absent, fall back to the process-wide principal
    // (the global `--principal` / `ASTRID_PRINCIPAL`, already validated
    // at startup) so every uplink this CLI opens attributes to one
    // identity.
    let caller = match principal {
        Some(p) => astrid_core::PrincipalId::new(p)
            .with_context(|| format!("invalid principal for `astrid mcp serve`: {p}"))?,
        None => crate::principal::current(),
    };

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
    let client = SocketClient::connect(session, caller.clone())
        .await
        .context("Failed to connect to the Astrid daemon socket")?;

    // The uplink connected, but a non-`anonymous` principal with no keypair is
    // silently stamped `anonymous` by the daemon — every tool call would then
    // fail the ingress-trust / capability checks and appear to hang. Fail loud
    // instead of serving a broken bridge.
    require_authenticated_unless_anonymous(&caller, client.is_authenticated())?;

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

#[cfg(test)]
mod fail_loud_tests {
    use super::require_authenticated_unless_anonymous;
    use astrid_core::PrincipalId;

    #[test]
    fn authenticated_principal_is_allowed() {
        let p = PrincipalId::new("claude-code").unwrap();
        assert!(require_authenticated_unless_anonymous(&p, true).is_ok());
    }

    #[test]
    fn unauthenticated_non_anonymous_is_refused_with_actionable_message() {
        let p = PrincipalId::new("claude-code").unwrap();
        let err = require_authenticated_unless_anonymous(&p, false)
            .expect_err("an unauthenticated non-anonymous principal must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("anonymous"),
            "explains the anonymous fallback: {msg}"
        );
        assert!(msg.contains("claude-code"), "names the principal: {msg}");
        assert!(msg.contains("agent create"), "gives the fix: {msg}");
    }

    #[test]
    fn explicit_anonymous_is_allowed_even_unauthenticated() {
        // Serving unauthenticated on purpose is fine.
        assert!(require_authenticated_unless_anonymous(&PrincipalId::anonymous(), false).is_ok());
    }
}
