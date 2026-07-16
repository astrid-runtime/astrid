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
mod grant;
mod ingress;
// Parent-death detection reads `getppid()` (Unix-only); the module and its use
// site are target-gated so the CLI still compiles on non-Unix targets.
#[cfg(unix)]
mod parent_death;
mod server;
mod session_guard;
mod watch;

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use rmcp::ServiceExt;
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;

use server::AstridMcpServer;

fn require_service_topic(response: KernelResponse, topic: &str) -> Result<()> {
    match response {
        KernelResponse::Success(value)
            if value.get("topic").and_then(serde_json::Value::as_str) == Some(topic)
                && value.get("ready").and_then(serde_json::Value::as_bool) == Some(true) =>
        {
            Ok(())
        },
        KernelResponse::Success(value)
            if value.get("topic").and_then(serde_json::Value::as_str) == Some(topic)
                && value.get("ready").and_then(serde_json::Value::as_bool) == Some(false) =>
        {
            anyhow::bail!(
                "the selected principal has no live capsule serving '{topic}'; install its MCP pack and retry"
            )
        },
        KernelResponse::Error(message) => {
            anyhow::bail!("the daemon could not prepare the MCP service: {message}")
        },
        other => anyhow::bail!("unexpected daemon response while preparing MCP: {other:?}"),
    }
}

fn require_topic_readiness_feature(supported: bool) -> Result<()> {
    if supported {
        return Ok(());
    }
    anyhow::bail!(
        "the running daemon predates caller-scoped MCP readiness; restart the daemon with the newly installed runtime, then retry"
    )
}

async fn ensure_mcp_service_ready(caller: astrid_core::PrincipalId) -> Result<()> {
    let mut client = crate::socket_client::connect_kernel_for_workspace_as(caller, None)
        .await
        .context("failed to connect to the daemon management surface")?;
    require_topic_readiness_feature(
        client.server_supports(astrid_core::session_token::FEATURE_ENSURE_TOPIC_READY),
    )?;
    let response = client
        .request(KernelRequest::EnsureTopicReady {
            topic: server::TOOLS_LIST_TOPIC.to_string(),
        })
        .await
        .context("failed to prepare the selected principal's capsule view")?;
    require_service_topic(response, server::TOOLS_LIST_TOPIC)?;
    Ok(())
}

/// Refuse to serve the MCP bridge silently as the no-capability `anonymous`
/// identity.
///
/// `astrid --principal X mcp serve` connects, but if `X` has no keypair the
/// handshake falls to the legacy single-frame path and the daemon stamps the
/// connection `anonymous`. The bridge would then come up "successfully" yet
/// every `tools/call` fails the ingress-trust and capability checks — to a
/// client it just hangs/times out, with no hint why. This turns that silent,
/// confusing failure into a loud, actionable error at startup.
///
/// Requesting `anonymous` explicitly (`astrid --principal anonymous mcp serve`) is allowed:
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
         unauthenticated on purpose, pass `--principal anonymous` before `mcp serve`."
    );
}

/// Run the MCP stdio server until the client closes stdin (EOF), its launching
/// session dies (parent-death reaping), or the process is signalled.
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

    // `mcp serve` owns stdout for JSON-RPC, so daemon bootstrap must be quiet.
    crate::commands::daemon::ensure_daemon_quiet("mcp-serve")
        .await
        .context("failed to ensure Astrid daemon for `astrid mcp serve`")?;

    // The shim holds ONE uplink connection for its whole lifetime. The
    // session id is ephemeral — it only scopes this transport's frames,
    // not a chat session; the kernel attributes work via the per-message
    // `principal`, not the session.
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let client = crate::socket_client::connect_for_workspace(session, caller.clone(), None)
        .await
        .context("Failed to connect to the Astrid daemon socket")?;

    // The uplink connected, but a non-`anonymous` principal with no keypair is
    // silently stamped `anonymous` by the daemon — every tool call would then
    // fail the ingress-trust / capability checks and appear to hang. Fail loud
    // instead of serving a broken bridge.
    require_authenticated_unless_anonymous(&caller, client.is_authenticated())?;
    require_topic_readiness_feature(
        client.server_supports(astrid_core::session_token::FEATURE_ENSURE_TOPIC_READY),
    )?;

    // Do not expose MCP stdio until this principal's live capsule view contains
    // the broker front door. The management request waits for the real profile
    // load and receives keepalives while slow work is progressing; no startup
    // delay or retry timer is used.
    ensure_mcp_service_ready(caller.clone()).await?;

    info!(
        principal = %caller,
        "astrid mcp serve: uplink established, starting MCP stdio transport"
    );

    tokio::spawn(session_guard::run(caller.clone()));

    let server = AstridMcpServer::new(Arc::new(Mutex::new(client)), caller.clone());

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

    // Race the normal stdin-EOF quit against parent-death. `waiting()` only
    // returns when the client closes stdin; an MCP client that DIES without
    // closing stdin would otherwise leave this shim blocked forever, an orphan
    // pinning >=2 daemon uplinks (observed: a 4-day orphan). When the launching
    // session dies we drop `running` so the transport closes and those uplinks
    // are freed.
    // Parent-death detection is Unix-only (`getppid`); on other targets fall
    // back to a never-resolving future so the shim relies solely on stdin EOF.
    #[cfg(unix)]
    let parent_death_fut = parent_death::wait_for_parent_death();
    #[cfg(not(unix))]
    let parent_death_fut = std::future::pending::<()>();

    tokio::select! {
        biased;
        () = parent_death_fut => {
            info!("astrid mcp serve: launching session ended (reparented); closing MCP bridge");
            // `running` (moved into the losing `waiting()` future) is dropped
            // here → transport closes → daemon uplinks freed.
            Ok(ExitCode::SUCCESS)
        }
        quit = running.waiting() => {
            let quit_reason = quit.context("MCP stdio transport terminated abnormally")?;
            info!(?quit_reason, "astrid mcp serve: MCP transport closed");
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[cfg(test)]
mod fail_loud_tests {
    use super::{
        require_authenticated_unless_anonymous, require_service_topic,
        require_topic_readiness_feature,
    };
    use astrid_core::PrincipalId;
    use astrid_core::kernel_api::KernelResponse;

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

    #[test]
    fn live_service_topic_is_accepted() {
        let response = KernelResponse::Success(serde_json::json!({
            "topic": "astrid.v1.request.mcp.tools.list",
            "ready": true,
        }));
        assert!(require_service_topic(response, "astrid.v1.request.mcp.tools.list").is_ok());
    }

    #[test]
    fn missing_service_topic_fails_before_stdio_starts() {
        let response = KernelResponse::Success(serde_json::json!({
            "topic": "astrid.v1.request.mcp.tools.list",
            "ready": false,
        }));
        let error = require_service_topic(response, "astrid.v1.request.mcp.tools.list")
            .expect_err("a missing broker must fail startup");
        assert!(error.to_string().contains("no live capsule"));
    }

    #[test]
    fn old_daemon_without_readiness_feature_fails_with_restart_guidance() {
        let error = require_topic_readiness_feature(false)
            .expect_err("an old daemon must be rejected before sending the new request");
        let message = error.to_string();
        assert!(message.contains("predates"));
        assert!(message.contains("restart"));
    }
}
