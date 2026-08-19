//! `astrid audit` — operator-only audit accounting and retention controls.
//!
//! The CLI talks to the kernel admin router. It never opens a native audit
//! directory, mounts a principal home, or reads entry payloads directly.

use std::process::ExitCode;

use anyhow::{Result, bail};
use astrid_core::kernel_api::{
    AdminRequestKind, AdminResponseBody, AuditHealth, AuditPruneResult, AuditStats,
};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::admin_client::{connect_as_active_agent, into_result};
use crate::value_formatter::{ValueFormat, emit_structured};

/// Audit operator subcommands.
#[derive(Subcommand, Debug, Clone)]
pub(crate) enum AuditCommand {
    /// Show O(1) global accounting and ingestion health.
    Stats(AuditStatsArgs),
    /// Prune the oldest eligible sealed segment and print its signed receipt.
    Prune(AuditPruneArgs),
    /// Show bounded ingestion queue and writer health.
    Health(AuditHealthArgs),
}

/// Top-level `audit` arguments.
#[derive(Args, Debug, Clone)]
pub(crate) struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

/// `audit stats` output options.
#[derive(Args, Debug, Clone)]
pub(crate) struct AuditStatsArgs {
    /// Output format: pretty (default), json, yaml, or toml.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// `audit prune` options.
#[derive(Args, Debug, Clone)]
pub(crate) struct AuditPruneArgs {
    /// Minimum suffix entries to retain in the selected chain.
    #[arg(long, default_value_t = 1, value_name = "N")]
    pub retain_entries: u64,
    /// Optional minimum retained canonical bytes.
    #[arg(long, value_name = "BYTES")]
    pub retain_bytes: Option<u64>,
    /// Output format: pretty (default), json, yaml, or toml.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// `audit health` output options.
#[derive(Args, Debug, Clone)]
pub(crate) struct AuditHealthArgs {
    /// Output format: pretty (default), json, yaml, or toml.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

#[derive(Debug, Clone, Serialize)]
struct AuditStatsOutput {
    stats: AuditStats,
    health: AuditHealth,
}

/// Dispatch an audit operator command through the kernel admin RPC.
pub(crate) async fn run(args: &AuditArgs) -> Result<ExitCode> {
    match &args.command {
        AuditCommand::Stats(args) => run_stats(args).await,
        AuditCommand::Prune(args) => run_prune(args).await,
        AuditCommand::Health(args) => run_health(args).await,
    }
}

async fn run_stats(args: &AuditStatsArgs) -> Result<ExitCode> {
    let mut client = connect_as_active_agent().await?;
    let stats = match into_result(client.request(AdminRequestKind::AuditStats).await?)? {
        AdminResponseBody::AuditStats(stats) => stats,
        other => bail!("unexpected response from kernel: {other:?}"),
    };
    let health = match into_result(client.request(AdminRequestKind::AuditHealth).await?)? {
        AdminResponseBody::AuditHealth(health) => health,
        other => bail!("unexpected response from kernel: {other:?}"),
    };
    let degraded = stats.degraded || health.degraded;
    let format = ValueFormat::parse(&args.format);
    if format.is_pretty() {
        print_stats_pretty(&stats, &health);
    } else {
        emit_structured(&AuditStatsOutput { stats, health }, format)?;
    }
    Ok(if degraded {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

async fn run_prune(args: &AuditPruneArgs) -> Result<ExitCode> {
    if args.retain_entries == 0 {
        bail!("--retain-entries must be at least 1");
    }
    if args.retain_bytes == Some(0) {
        bail!("--retain-bytes must be greater than 0");
    }
    let mut client = connect_as_active_agent().await?;
    let body = into_result(
        client
            .request(AdminRequestKind::AuditPrune {
                retain_entries: args.retain_entries,
                retain_bytes: args.retain_bytes,
            })
            .await?,
    )?;
    let AdminResponseBody::AuditPruned(result) = body else {
        bail!("unexpected response from kernel: {body:?}");
    };
    let format = ValueFormat::parse(&args.format);
    if format.is_pretty() {
        print_prune_pretty(&result);
    } else {
        emit_structured(&result, format)?;
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_health(args: &AuditHealthArgs) -> Result<ExitCode> {
    let mut client = connect_as_active_agent().await?;
    let body = into_result(client.request(AdminRequestKind::AuditHealth).await?)?;
    let AdminResponseBody::AuditHealth(health) = body else {
        bail!("unexpected response from kernel: {body:?}");
    };
    let degraded = health.degraded;
    let format = ValueFormat::parse(&args.format);
    if format.is_pretty() {
        print_health_pretty(&health);
    } else {
        emit_structured(&health, format)?;
    }
    Ok(if degraded {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn print_stats_pretty(stats: &AuditStats, health: &AuditHealth) {
    println!("Audit totals");
    println!("  entries:         {}", stats.total_count);
    println!("  bytes:           {}", stats.total_bytes);
    println!(
        "  segments:        {} ({} sealed)",
        stats.segments, stats.sealed_segments
    );
    println!("  eligible:        {}", stats.eligible_segments);
    println!(
        "  cap:             {} entries / {} bytes",
        stats.cap_entries, stats.cap_bytes
    );
    println!(
        "  retention:       {}",
        if stats.degraded {
            "degraded"
        } else {
            "healthy"
        }
    );
    print_health_pretty(health);
}

fn print_health_pretty(health: &AuditHealth) {
    println!("Audit ingestion");
    println!("  accepted:        {}", health.accepted);
    println!("  persisted:       {}", health.persisted);
    println!("  failed:           {}", health.failed);
    println!("  queue full:       {}", health.queue_full);
    println!("  queue depth:      {}", health.queue_depth);
    println!(
        "  worker:           {}",
        if health.worker_alive { "alive" } else { "dead" }
    );
    println!(
        "  status:           {}",
        if health.degraded {
            "degraded"
        } else {
            "healthy"
        }
    );
    if let Some(error) = &health.last_error {
        println!("  last error:       {error}");
    }
}

fn print_prune_pretty(result: &AuditPruneResult) {
    println!("Audit prune receipt");
    println!("  generation:       {}", result.generation);
    println!("  receipt hash:     {}", result.receipt_hash);
    println!("  session:           {}", result.session);
    if let Some(principal) = &result.principal {
        println!("  principal:         {principal}");
    }
    if let Some(segment) = result.segment {
        println!("  segment:           {segment}");
    }
    if let Some(ordinal) = result.seal_ordinal {
        println!("  seal ordinal:      {ordinal}");
    }
    println!(
        "  omitted:           {} entries / {} bytes",
        result.omitted_count, result.omitted_bytes
    );
    println!(
        "  retained:          {} entries / {} bytes",
        result.retained_count, result.retained_bytes
    );
    println!(
        "  physical reclaimed: {} bytes",
        result.physical_reclaimed_bytes
    );
    if result.physical_reclaim_pending {
        println!("  physical status:   pending compaction");
    }
}
