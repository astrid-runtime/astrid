//! `astrid audit` — operator-only audit accounting and retention controls.
//!
//! The CLI talks to the kernel admin router. It never opens a native audit
//! directory, mounts a principal home, or reads entry payloads directly.

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use astrid_core::kernel_api::{
    AdminRequestKind, AdminResponseBody, AuditAnchorStatusReport, AuditExportPage,
    AuditExportRequest, AuditHeadsSnapshot, AuditHealth, AuditPruneResult, AuditStats,
};
use astrid_core::{PrincipalId, SessionId};
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
    /// Print a runtime-key-signed snapshot of every audit chain head.
    Heads(AuditHeadsArgs),
    /// Print one page of a chain's raw signed entries, in chain order.
    Export(AuditExportArgs),
    /// Show how far each chain is externally anchored, and how far behind.
    AnchorStatus(AuditAnchorStatusArgs),
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

/// `audit heads` output options.
#[derive(Args, Debug, Clone)]
pub(crate) struct AuditHeadsArgs {
    /// Output format: pretty (default), json, yaml, or toml.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// `audit export` options.
#[derive(Args, Debug, Clone)]
pub(crate) struct AuditExportArgs {
    /// Session UUID of the chain, or `system` for the daemon session.
    #[arg(long, value_name = "ID")]
    pub session: String,
    /// Principal alias whose chain to export. Omit for the system chain.
    #[arg(long = "agent", value_name = "ALIAS")]
    pub principal: Option<String>,
    /// Zero-based retained index to start at. Ignored with `--cursor`.
    #[arg(long, default_value_t = 0, value_name = "INDEX")]
    pub from: u64,
    /// Resume after a page: the `next_cursor` of an earlier export.
    #[arg(long, value_name = "CURSOR")]
    pub cursor: Option<String>,
    /// Maximum entries in the page (kernel default 500, capped at 1000).
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Also print the chain's prune receipts from this generation on.
    #[arg(long, value_name = "GENERATION")]
    pub receipts_from: Option<u64>,
    /// Output format: pretty (default), json, yaml, or toml.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// `audit anchor-status` output options.
#[derive(Args, Debug, Clone)]
pub(crate) struct AuditAnchorStatusArgs {
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
        AuditCommand::Heads(args) => run_heads(args).await,
        AuditCommand::Export(args) => run_export(args).await,
        AuditCommand::AnchorStatus(args) => run_anchor_status(args).await,
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
    let body = client
        .request(AdminRequestKind::AuditPrune {
            retain_entries: args.retain_entries,
            retain_bytes: args.retain_bytes,
        })
        .await?;
    if let AdminResponseBody::Error(error) = &body
        && error.starts_with("audit prune refused")
    {
        bail!(
            "{error}\n\nNothing was pruned: the prune would remove audit history that is not \
             externally anchored. Run `astrid audit anchor-status` to see how far each chain is \
             anchored."
        );
    }
    let body = into_result(body)?;
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

async fn run_heads(args: &AuditHeadsArgs) -> Result<ExitCode> {
    let mut client = connect_as_active_agent().await?;
    let body = into_result(client.request(AdminRequestKind::AuditHeads).await?)?;
    let AdminResponseBody::AuditHeads(snapshot) = body else {
        bail!("unexpected response from kernel: {body:?}");
    };
    let format = ValueFormat::parse(&args.format);
    if format.is_pretty() {
        print_heads_pretty(&snapshot);
    } else {
        emit_structured(&snapshot, format)?;
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_export(args: &AuditExportArgs) -> Result<ExitCode> {
    let request = AuditExportRequest {
        session: parse_session(&args.session)?,
        principal: args
            .principal
            .as_deref()
            .map(PrincipalId::new)
            .transpose()
            .context("invalid --agent")?,
        from: args.from,
        cursor: args.cursor.clone(),
        limit: args.limit,
        receipts_from: args.receipts_from,
    };
    let mut client = connect_as_active_agent().await?;
    let body = into_result(
        client
            .request(AdminRequestKind::AuditExport(request))
            .await?,
    )?;
    let AdminResponseBody::AuditExport(page) = body else {
        bail!("unexpected response from kernel: {body:?}");
    };
    let format = ValueFormat::parse(&args.format);
    if format.is_pretty() {
        print_export_pretty(&page);
    } else {
        emit_structured(&page, format)?;
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_anchor_status(args: &AuditAnchorStatusArgs) -> Result<ExitCode> {
    let mut client = connect_as_active_agent().await?;
    let body = into_result(client.request(AdminRequestKind::AuditAnchorStatus).await?)?;
    let AdminResponseBody::AuditAnchorStatus(report) = body else {
        bail!("unexpected response from kernel: {body:?}");
    };
    let held = report.retention_hold.is_some();
    let format = ValueFormat::parse(&args.format);
    if format.is_pretty() {
        print_anchor_status_pretty(&report);
    } else {
        emit_structured(&report, format)?;
    }
    Ok(if held {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn print_anchor_status_pretty(report: &AuditAnchorStatusReport) {
    println!("Audit anchoring ({} chains)", report.chains.len());
    println!(
        "  anchor before prune: {}",
        if report.require_anchor_before_prune {
            "required"
        } else {
            "only for anchored chains"
        }
    );
    if let Some(hold) = &report.retention_hold {
        println!("  retention:          held over the cap: {hold}");
    }
    for chain in &report.chains {
        let principal = chain
            .principal
            .as_ref()
            .map_or("(system)", PrincipalId::as_str);
        let head = chain
            .head_position()
            .map_or_else(|| "unknown".to_owned(), |head| head.to_string());
        let lag = chain
            .lag()
            .map_or_else(|| "unknown".to_owned(), |lag| lag.to_string());
        match chain.anchored_position {
            Some(anchored) => println!(
                "  {} {principal}: head {head} anchored {anchored} lag {lag} at {}",
                chain.session,
                chain.anchored_at.as_deref().unwrap_or("?")
            ),
            None => println!("  {} {principal}: head {head} not anchored", chain.session),
        }
    }
}

/// Accept `system`, a bare UUID, or the `session:<uuid>` display form.
fn parse_session(raw: &str) -> Result<SessionId> {
    if raw == "system" {
        return Ok(SessionId::SYSTEM);
    }
    let uuid = raw.strip_prefix("session:").unwrap_or(raw);
    uuid::Uuid::parse_str(uuid)
        .map(SessionId::from_uuid)
        .with_context(|| format!("invalid --session {raw:?}: expected a UUID or `system`"))
}

fn print_heads_pretty(snapshot: &AuditHeadsSnapshot) {
    println!("Audit heads ({} chains)", snapshot.chains.len());
    println!("  snapshot ns:      {}", snapshot.snapshot_time_ns);
    println!("  runtime key:      {}", snapshot.runtime_public_key_hex);
    for chain in &snapshot.chains {
        let principal = chain
            .principal
            .as_ref()
            .map_or("(system)", PrincipalId::as_str);
        let omitted = chain
            .known_omitted_total()
            .map_or_else(|| "unknown".to_owned(), |total| total.to_string());
        println!(
            "  {} {principal}: count {} omitted {omitted} head {}",
            chain.session, chain.count, chain.head_hash_hex
        );
    }
}

fn print_export_pretty(page: &AuditExportPage) {
    let principal = page
        .principal
        .as_ref()
        .map_or("(system)", PrincipalId::as_str);
    println!("Audit export {} {principal}", page.session);
    for entry in &page.entries {
        let action = entry.entry["action"]["type"].as_str().unwrap_or("?");
        println!(
            "  #{} {} {} {action} hash {}",
            entry.index, entry.id, entry.timestamp, entry.content_hash_hex
        );
    }
    println!(
        "  entries {}..{} of {} retained{}",
        page.from,
        page.next_index,
        page.chain_count,
        if page.complete { " (complete)" } else { "" }
    );
    if let Some(cursor) = &page.next_cursor {
        println!("  next cursor:      {cursor}");
    }
    for receipt in &page.prune_receipts {
        println!(
            "  receipt #{} omitted {} hash {}",
            receipt.generation, receipt.receipt["omitted_count"], receipt.receipt_hash_hex
        );
    }
    if let Some(next) = page.next_receipts_from {
        println!("  more receipts from generation {next}");
    }
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
    if let Some(hold) = &stats.retention_hold {
        println!("  held over cap:   {hold}");
    } else if let Some(error) = &stats.last_error {
        println!("  last error:      {error}");
    }
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
