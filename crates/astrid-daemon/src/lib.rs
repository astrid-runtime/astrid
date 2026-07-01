//! Astrid Daemon — shared library for the background kernel process.
//!
//! This crate provides the daemon entry point as a library function so it can
//! be reused by both the standalone `astrid-daemon` binary and the `astrid`
//! CLI binary (which ships both via `cargo install astrid`).

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]

use anyhow::{Context, Result};
use clap::Parser;

/// Astrid Daemon - Background kernel process
#[derive(Parser)]
#[command(name = "astrid-daemon")]
#[command(author, version, about)]
pub struct Args {
    /// The session ID to bind the daemon to
    #[arg(short, long, default_value = "00000000-0000-0000-0000-000000000000")]
    pub session: String,

    /// Workspace root directory
    #[arg(short, long)]
    pub workspace: Option<std::path::PathBuf>,

    /// Enable ephemeral mode (auto-shutdown on idle timeout after last client disconnects)
    #[arg(long)]
    pub ephemeral: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Override the async-I/O host-call concurrency ceiling for capsules
    /// (HTTP, `ipc::recv`). Highest-precedence override; defaults to a
    /// host-derived value (cores-scaled, file-descriptor-clamped).
    #[arg(long, value_parser = parse_nonzero_concurrency)]
    pub host_io_concurrency: Option<usize>,

    /// Override the blocking host-call concurrency ceiling for capsules (KV,
    /// fs, identity, sys, sockets). Highest-precedence override; defaults to a
    /// host-derived value (≈ cores - 2).
    #[arg(long, value_parser = parse_nonzero_concurrency)]
    pub host_blocking_concurrency: Option<usize>,

    /// Override the max size of each capsule's dynamic instance pool (concurrent
    /// interceptor invocations). Highest-precedence override; defaults to a
    /// host-derived value (cores-scaled, replacing the old fixed 16).
    #[arg(long)]
    pub instance_pool_size: Option<usize>,
}

/// Reject a concurrency ceiling of `0` at CLI parse time. `0` would otherwise
/// parse as `Some(0)` and be silently clamped to `1` by
/// `CapsuleRuntimeLimits::resolve`, diverging from the config layer (which
/// rejects an explicit zero) and quietly serialising the gate. Failing fast
/// keeps the two configuration surfaces consistent.
fn parse_nonzero_concurrency(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(0) => Err("must be >= 1 (a concurrency ceiling of 0 would wedge the gate)".to_string()),
        Ok(n) => Ok(n),
        Err(e) => Err(format!("not a valid concurrency value: {e}")),
    }
}

fn init_logging(verbose: bool, unified_cfg: Option<&astrid_config::Config>) {
    let log_config = if let Some(cfg) = unified_cfg {
        let mut lc = astrid_telemetry::log_config_from(cfg);
        if verbose {
            "debug".clone_into(&mut lc.level);
        }
        if let Ok(home) = astrid_core::dirs::AstridHome::resolve() {
            lc.target = astrid_telemetry::LogTarget::File(home.log_dir());
        }
        lc
    } else {
        let level = if verbose { "debug" } else { "info" };
        let mut lc = astrid_telemetry::LogConfig::new(level)
            .with_format(astrid_telemetry::LogFormat::Compact);
        if let Ok(home) = astrid_core::dirs::AstridHome::resolve() {
            lc.target = astrid_telemetry::LogTarget::File(home.log_dir());
        }
        lc
    };

    if let Err(e) = astrid_telemetry::setup_logging(&log_config) {
        eprintln!("Failed to initialize logging: {e}");
    }
}

/// Resolve the capsule host-call concurrency ceilings from CLI flags, the
/// loaded config (which already folded in `ASTRID_CAPSULE_*` env), and the
/// host-derived defaults. Precedence: CLI flag > config file > env > host.
fn resolve_capsule_limits(
    args: &Args,
    cfg: Option<&astrid_config::Config>,
) -> astrid_capsule::CapsuleRuntimeLimits {
    let capsule_cfg = cfg.map(|c| &c.capsule);
    astrid_capsule::CapsuleRuntimeLimits::resolve(
        args.host_blocking_concurrency
            .or_else(|| capsule_cfg.and_then(|c| c.host_blocking_concurrency)),
        args.host_io_concurrency
            .or_else(|| capsule_cfg.and_then(|c| c.host_io_concurrency)),
        args.instance_pool_size
            .or_else(|| capsule_cfg.and_then(|c| c.instance_pool_size)),
    )
}

/// Resolve the `astrid:http` operator host policy from the `[http]` config
/// section into the typed [`HttpLimits`](astrid_capsule::HttpLimits) the kernel
/// forwards to every capsule. The timeout fields are per-request DEFAULTS (a
/// caller may override with a larger value); `max_redirects` /
/// `max_concurrent_streams` are caller ceilings; `max_response_bytes` is a
/// caller ceiling that the request path further hard-clamps to
/// `MAX_GUEST_PAYLOAD_LEN`. An absent `[http]` section yields
/// `HttpSection::default`, which equals the host's historical hardcoded
/// constants — so this resolution changes nothing unless the operator set
/// explicit `[http]` values.
fn resolve_http_limits(cfg: Option<&astrid_config::Config>) -> astrid_capsule::HttpLimits {
    let http = cfg.map(|c| c.http.clone()).unwrap_or_default();
    astrid_capsule::HttpLimits::from_config_values(
        http.default_timeout_secs,
        http.stream_connect_timeout_secs,
        http.stream_read_timeout_secs,
        http.header_deadline_secs,
        http.max_redirects,
        http.max_concurrent_streams,
        http.max_response_bytes,
    )
}

/// Run the Astrid daemon with the given arguments.
///
/// This is the shared entry point used by both the standalone `astrid-daemon`
/// binary and the `astrid` CLI's bundled daemon binary.
///
/// # Errors
///
/// Returns an error if the kernel fails to boot, the CLI proxy capsule is
/// missing, or the readiness file cannot be written.
#[expect(
    clippy::too_many_lines,
    reason = "boot sequence: sequential config resolution + kernel/capsule setup that does not benefit from splitting"
)]
pub async fn run() -> Result<()> {
    let args = Args::parse();
    let astrid_home =
        astrid_core::dirs::AstridHome::resolve().context("Failed to resolve Astrid home")?;

    // Load the unified config once: it drives both logging and the capsule
    // runtime concurrency ceilings below. Loaded against the current dir (as
    // logging always did), independent of `--workspace`.
    let workspace_root_for_cfg = std::env::current_dir().ok();
    let unified_cfg = astrid_config::Config::load_with_home(
        workspace_root_for_cfg.as_deref(),
        astrid_home.root(),
    )
    .ok()
    .map(|r| r.config);

    init_logging(args.verbose, unified_cfg.as_ref());

    let session_id = astrid_core::SessionId::from_uuid(
        uuid::Uuid::parse_str(&args.session)
            .map_err(|e| anyhow::anyhow!("Invalid UUID format: {e}"))?,
    );

    // Resolve the capsule host-call concurrency ceilings (CLI > config+env >
    // host-derived default); the kernel forwards them to every `WasmEngine`.
    // Done before `args.workspace` is consumed below.
    let runtime_limits = resolve_capsule_limits(&args, unified_cfg.as_ref());

    let ws = args.workspace.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    });

    // Operator-approved per-capsule local-egress allowlist (SSRF-airlock
    // exemptions). Operator config only — the kernel hands each capsule its
    // own slice at load time. Absent config = empty = no exemptions.
    let local_egress = unified_cfg
        .as_ref()
        .map(|c| c.security.capsule_local_egress.clone())
        .unwrap_or_default();

    // Operator ceilings for the astrid:http host (global; absent `[http]`
    // config = the host's historical constants). Forwarded to every capsule.
    let http_limits = resolve_http_limits(unified_cfg.as_ref());
    let kernel = astrid_kernel::Kernel::new(
        session_id.clone(),
        ws,
        runtime_limits,
        local_egress,
        http_limits,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to boot Kernel: {e}"))?;

    // In ephemeral mode, shut down immediately when the last client disconnects.
    if args.ephemeral {
        kernel.set_ephemeral(true);
    }

    // Load the boot-critical default view. Non-default profile principals warm
    // after readiness so a large tenant set cannot make daemon restart health
    // wait on every agent's capsule view.
    kernel.load_boot_capsules().await;

    // Verify the CLI proxy capsule loaded. Without it, the daemon
    // has no accept loop and CLI connections will always time out.
    {
        let reg = kernel.capsules.read().await;
        let has_cli_proxy = reg
            .list()
            .iter()
            .any(|id| id.as_str() == "astrid-capsule-cli");
        if !has_cli_proxy {
            tracing::error!(
                "CLI proxy capsule (astrid-capsule-cli) not found - \
                 daemon cannot accept CLI connections"
            );
            anyhow::bail!(
                "CLI proxy capsule (astrid-capsule-cli) not found. \
                 Install it with: astrid capsule install @unicity-astrid/capsule-cli"
            );
        }
    }

    // Signal readiness AFTER the default CLI/system view is loaded and
    // accepting connections. The CLI polls for this file to avoid connecting
    // before the handshake accept loop is running.
    astrid_kernel::socket::write_readiness_file().map_err(|e| {
        anyhow::anyhow!(
            "Failed to write readiness file \
             (daemon is useless without it): {e}"
        )
    })?;

    tracing::info!(
        session = %session_id.0,
        ephemeral = args.ephemeral,
        "Kernel booted successfully"
    );

    // Optionally spawn the HTTP gateway (issue #756). The gateway
    // reads `etc/gateway-http.toml`; missing file or `enabled = false`
    // → no-op so single-tenant deployments keep their old shape.
    let gateway_shutdown = match load_gateway_config().await {
        Ok(Some(cfg)) if cfg.enabled => Some(spawn_gateway(cfg, &kernel)?),
        Ok(Some(_)) => {
            tracing::debug!("astrid-gateway config present but disabled — skipping");
            None
        },
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load gateway config; gateway not started");
            None
        },
    };

    kernel.schedule_profile_principal_warm();

    // Wait for a termination signal or API shutdown request.
    let mut shutdown_rx = kernel.shutdown_tx.subscribe();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to register SIGTERM handler")?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, shutting down");
            }
            _ = shutdown_rx.wait_for(|v| *v) => {
                tracing::info!("Received API shutdown request, shutting down");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received SIGINT, shutting down");
            }
            _ = shutdown_rx.wait_for(|v| *v) => {
                tracing::info!("Received API shutdown request, shutting down");
            }
        }
    }

    if let Some(notify) = gateway_shutdown {
        notify.notify_waiters();
    }

    kernel.shutdown(Some("signal".to_string())).await;

    Ok(())
}

/// Load `etc/gateway-http.toml`. Returns `Ok(None)` when the file
/// doesn't exist (single-tenant default).
async fn load_gateway_config() -> Result<Option<astrid_gateway::GatewayConfig>> {
    let home = astrid_core::dirs::AstridHome::resolve()
        .map_err(|e| anyhow::anyhow!("resolve AstridHome: {e}"))?;
    let path = home.etc_dir().join("gateway-http.toml");
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("read {}: {e}", path.display())),
    };
    let cfg: astrid_gateway::GatewayConfig =
        toml::from_str(&text).context("parse gateway-http.toml")?;
    cfg.validate().context("validate gateway-http.toml")?;
    Ok(Some(cfg))
}

fn spawn_gateway(
    cfg: astrid_gateway::GatewayConfig,
    kernel: &std::sync::Arc<astrid_kernel::Kernel>,
) -> Result<std::sync::Arc<tokio::sync::Notify>> {
    // Plumb four kernel handles into the gateway:
    //
    //   * the event bus, so the SSE audit stream and the bus-direct
    //     admin client can subscribe / publish locally without going
    //     back over the Unix socket;
    //   * the persistent audit log, so the new
    //     `GET /api/sys/audit` historical-query route has somewhere
    //     to read from;
    //   * the session id (paired with the audit log because the
    //     log indexes entries by session);
    //   * the agent-loop readiness probe, so the `POST /api/agent/prompt`
    //     fail-fast can read live daemon health in-process — without a
    //     per-principal capability check (serviceability is global health,
    //     not authorization) or a socket round-trip.
    let bus = std::sync::Arc::clone(&kernel.event_bus);
    let audit_log = std::sync::Arc::clone(&kernel.audit_log);
    let session_id = kernel.session_id.clone();
    let readiness_probe = kernel.agent_readiness_probe();
    let topic_probe = kernel.capsule_topic_probe();
    let state = astrid_gateway::GatewayState::new(
        cfg,
        Some(bus),
        Some(audit_log),
        Some(session_id),
        Some(readiness_probe),
        Some(topic_probe),
    )
    .context("build gateway state")?;
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let notify_for_task = std::sync::Arc::clone(&notify);
    tokio::spawn(async move {
        let shutdown = async move {
            notify_for_task.notified().await;
        };
        if let Err(e) = astrid_gateway::run(state, shutdown).await {
            tracing::error!(error = %e, "astrid-gateway exited with error");
        }
    });
    Ok(notify)
}
