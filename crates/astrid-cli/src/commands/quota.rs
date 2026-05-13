//! `astrid quota` — per-principal resource quota inspection and edit.
//!
//! Calls Layer 6 admin IPC `astrid.v1.admin.quota.get` and
//! `astrid.v1.admin.quota.set`. The `set` flow does a get-modify-set
//! round-trip rather than requiring the operator to supply every quota
//! field on the wire (which the kernel-side `Quotas` struct demands).

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::profile::{BACKGROUND_PROCESSES_UPPER_BOUND, Quotas, TIMEOUT_SECS_UPPER_BOUND};
use astrid_types::kernel::{AdminRequestKind, AdminResponseBody};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Serialize;

use crate::admin_client::{AdminClient, into_result};
use crate::context;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum QuotaCommand {
    /// Show resource quotas (defaults to active context).
    Show(ShowArgs),
    /// Update one or more resource quotas.
    Set(SetArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ShowArgs {
    /// Agent name (defaults to active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Group (deferred — needs group-level quota IPC).
    #[arg(short, long, hide = true)]
    pub group: Option<String>,
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SetArgs {
    /// Agent name (defaults to active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Group (deferred — needs group-level quota IPC).
    #[arg(short, long, hide = true)]
    pub group: Option<String>,
    /// Maximum WASM memory per invocation (e.g. `64MB`, `1GiB`).
    #[arg(long, value_name = "SIZE")]
    pub memory: Option<String>,
    /// Maximum invocation wall-clock time (e.g. `30s`, `5m`, `1h`).
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
    /// Maximum home-directory storage (e.g. `1GB`).
    #[arg(long, value_name = "SIZE")]
    pub storage: Option<String>,
    /// Maximum concurrent background processes.
    #[arg(long, value_name = "N")]
    pub processes: Option<u32>,
    /// Maximum IPC throughput (e.g. `10MB/s`, `1MiB`).
    #[arg(long = "ipc-rate", value_name = "RATE")]
    pub ipc_rate: Option<String>,
    /// Maximum concurrent net/http streams (deferred — needs separate IPC).
    #[arg(long, value_name = "N", hide = true)]
    pub streams: Option<u32>,
}

/// Top-level dispatcher for `astrid quota`.
pub(crate) async fn run(cmd: QuotaCommand) -> Result<ExitCode> {
    match cmd {
        QuotaCommand::Show(args) => run_show(args).await,
        QuotaCommand::Set(args) => run_set(args).await,
    }
}

/// Wire-shape record emitted by `--format json|yaml|toml`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct QuotaRecord {
    /// Principal these quotas apply to.
    pub principal: String,
    /// Maximum resident memory (bytes).
    pub max_memory_bytes: u64,
    /// Maximum invocation wall-clock time (seconds).
    pub max_timeout_secs: u64,
    /// Maximum IPC throughput (bytes/sec).
    pub max_ipc_throughput_bytes: u64,
    /// Maximum concurrent background processes.
    pub max_background_processes: u32,
    /// Maximum persistent home-directory storage (bytes).
    pub max_storage_bytes: u64,
}

fn record(principal: &PrincipalId, q: &Quotas) -> QuotaRecord {
    QuotaRecord {
        principal: principal.to_string(),
        max_memory_bytes: q.max_memory_bytes,
        max_timeout_secs: q.max_timeout_secs,
        max_ipc_throughput_bytes: q.max_ipc_throughput_bytes,
        max_background_processes: q.max_background_processes,
        max_storage_bytes: q.max_storage_bytes,
    }
}

async fn fetch_quotas(target: &PrincipalId) -> Result<Quotas> {
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::QuotaGet {
            principal: target.clone(),
        })
        .await?;
    let body = into_result(body)?;
    match body {
        AdminResponseBody::Quotas(q) => Ok(q),
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    }
}

async fn run_show(args: ShowArgs) -> Result<ExitCode> {
    if args.group.is_some() {
        eprintln!("astrid: group-scoped quotas need a group quota IPC topic that has not shipped.");
        return Ok(ExitCode::from(2));
    }
    let target = context::resolve_agent(args.agent.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let q = fetch_quotas(&target).await?;
    if !format.is_pretty() {
        emit_structured(&record(&target, &q), format)?;
        return Ok(ExitCode::SUCCESS);
    }
    print_quotas_pretty(&target, &q);
    Ok(ExitCode::SUCCESS)
}

fn print_quotas_pretty(principal: &PrincipalId, q: &Quotas) {
    println!("{} {}", "Quotas for".bold(), principal.to_string().cyan());
    println!(
        "  {:<24}  {}",
        "memory".bold(),
        format_bytes(q.max_memory_bytes)
    );
    println!(
        "  {:<24}  {}",
        "timeout".bold(),
        format_duration(Duration::from_secs(q.max_timeout_secs))
    );
    println!(
        "  {:<24}  {}",
        "storage".bold(),
        format_bytes(q.max_storage_bytes)
    );
    println!(
        "  {:<24}  {}",
        "processes".bold(),
        q.max_background_processes
    );
    println!(
        "  {:<24}  {}/s",
        "ipc-rate".bold(),
        format_bytes(q.max_ipc_throughput_bytes)
    );
}

async fn run_set(args: SetArgs) -> Result<ExitCode> {
    if args.group.is_some() {
        eprintln!("astrid: group-scoped quotas need a group quota IPC topic that has not shipped.");
        return Ok(ExitCode::from(2));
    }
    if args.streams.is_some() {
        eprintln!("astrid: --streams quota needs a separate IPC topic that has not shipped.");
        return Ok(ExitCode::from(2));
    }
    if args.memory.is_none()
        && args.timeout.is_none()
        && args.storage.is_none()
        && args.processes.is_none()
        && args.ipc_rate.is_none()
    {
        eprintln!("astrid: nothing to do (specify at least one quota flag)");
        return Ok(ExitCode::from(1));
    }
    let target = context::resolve_agent(args.agent.as_deref())?;
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::QuotaGet {
            principal: target.clone(),
        })
        .await?;
    let body = into_result(body)?;
    let mut quotas = match body {
        AdminResponseBody::Quotas(q) => q,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };
    if let Some(s) = args.memory.as_deref() {
        quotas.max_memory_bytes = parse_bytes(s).context("invalid --memory")?;
    }
    if let Some(s) = args.timeout.as_deref() {
        let d = parse_duration(s).context("invalid --timeout")?;
        quotas.max_timeout_secs = d.as_secs().max(1);
        if quotas.max_timeout_secs > TIMEOUT_SECS_UPPER_BOUND {
            anyhow::bail!("timeout exceeds upper bound ({TIMEOUT_SECS_UPPER_BOUND}s)");
        }
    }
    if let Some(s) = args.storage.as_deref() {
        quotas.max_storage_bytes = parse_bytes(s).context("invalid --storage")?;
    }
    if let Some(n) = args.processes {
        if n > BACKGROUND_PROCESSES_UPPER_BOUND {
            anyhow::bail!("processes exceeds upper bound ({BACKGROUND_PROCESSES_UPPER_BOUND})");
        }
        quotas.max_background_processes = n;
    }
    if let Some(s) = args.ipc_rate.as_deref() {
        quotas.max_ipc_throughput_bytes = parse_bytes(s).context("invalid --ipc-rate")?;
    }
    let body = client
        .request(AdminRequestKind::QuotaSet {
            principal: target.clone(),
            quotas,
        })
        .await?;
    let _ = into_result(body)?;
    println!("Updated quotas for '{target}'.");
    Ok(ExitCode::SUCCESS)
}

// ── byte/duration parsers ──────────────────────────────────────────

/// Parse `"32"`, `"32B"`, `"32KB"`, `"32MB"`, `"32GB"`, `"32KiB"`,
/// `"32MiB"`, `"32GiB"`, `"32TB"`, `"32TiB"`. Lowercase accepted.
pub(crate) fn parse_bytes(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty byte specifier");
    }
    // Strip optional `/s` (used by --ipc-rate).
    let body = trimmed.strip_suffix("/s").unwrap_or(trimmed);
    let (num_part, mult) = parse_numeric_suffix(body)?;
    let num: f64 = num_part
        .parse()
        .with_context(|| format!("not a number: {num_part}"))?;
    if num.is_sign_negative() || !num.is_finite() {
        anyhow::bail!("byte value must be non-negative and finite");
    }
    #[expect(
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "guarded by sign and finite checks above"
    )]
    let bytes = (num * (mult as f64)) as u64;
    Ok(bytes)
}

fn parse_numeric_suffix(body: &str) -> Result<(&str, u64)> {
    // Find the index where the suffix (alphabetic or `i` for binary)
    // begins. Consume digits and at most one `.`.
    let split = body
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(body.len());
    let (num_part, suffix) = body.split_at(split);
    let mult = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1u64,
        "K" | "KB" => 1_000,
        "KIB" => 1024,
        "M" | "MB" => 1_000_000,
        "MIB" => 1024 * 1024,
        "G" | "GB" => 1_000_000_000,
        "GIB" => 1024 * 1024 * 1024,
        "T" | "TB" => 1_000_000_000_000,
        "TIB" => 1024_u64.pow(4),
        other => anyhow::bail!("unknown byte suffix: {other}"),
    };
    Ok((num_part, mult))
}

/// Parse `"30s"`, `"5m"`, `"1h"`, `"2h30m"`, `"500ms"`. Falls back to
/// seconds for a bare integer.
pub(crate) fn parse_duration(s: &str) -> Result<Duration> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty duration");
    }
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }
    let mut total = Duration::ZERO;
    let mut current = String::new();
    let mut iter = trimmed.chars().peekable();
    while let Some(c) = iter.next() {
        if c.is_ascii_digit() || c == '.' {
            current.push(c);
            continue;
        }
        // Collect alpha suffix.
        let mut suffix = String::new();
        suffix.push(c);
        while let Some(&n) = iter.peek() {
            if n.is_ascii_alphabetic() {
                suffix.push(n);
                iter.next();
            } else {
                break;
            }
        }
        let num: f64 = current
            .parse()
            .with_context(|| format!("invalid duration component: {current}"))?;
        let chunk = match suffix.to_ascii_lowercase().as_str() {
            "ms" => Duration::from_secs_f64(num / 1000.0),
            "s" => Duration::from_secs_f64(num),
            "m" => Duration::from_secs_f64(num * 60.0),
            "h" => Duration::from_secs_f64(num * 3600.0),
            "d" => Duration::from_secs_f64(num * 86_400.0),
            other => anyhow::bail!("unknown duration suffix: {other}"),
        };
        total = total.saturating_add(chunk);
        current.clear();
    }
    if !current.is_empty() {
        // Trailing bare number without suffix → seconds.
        let secs: u64 = current.parse().context("trailing number without suffix")?;
        total = total.saturating_add(Duration::from_secs(secs));
    }
    Ok(total)
}

/// Render a byte count as a human-readable string with binary units.
#[expect(
    clippy::cast_precision_loss,
    reason = "human-readable rendering, magnitude up to ~GiB"
)]
fn format_bytes(b: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if b >= GIB {
        format!("{:.1} GiB", b as f64 / GIB as f64)
    } else if b >= MIB {
        format!("{:.1} MiB", b as f64 / MIB as f64)
    } else if b >= KIB {
        format!("{:.1} KiB", b as f64 / KIB as f64)
    } else {
        format!("{b} B")
    }
}

/// Render a duration as `1h2m3s` / `5m` / `30s` / `500ms`.
fn format_duration(d: Duration) -> String {
    let total = d.as_secs();
    if total == 0 {
        let ms = d.subsec_millis();
        return format!("{ms}ms");
    }
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_byte_suffixes() {
        assert_eq!(parse_bytes("0").unwrap(), 0);
        assert_eq!(parse_bytes("128").unwrap(), 128);
        assert_eq!(parse_bytes("128B").unwrap(), 128);
        assert_eq!(parse_bytes("1KB").unwrap(), 1_000);
        assert_eq!(parse_bytes("1MB").unwrap(), 1_000_000);
        assert_eq!(parse_bytes("1GB").unwrap(), 1_000_000_000);
    }

    #[test]
    fn parses_binary_byte_suffixes() {
        assert_eq!(parse_bytes("1KiB").unwrap(), 1024);
        assert_eq!(parse_bytes("64MiB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_bytes("1GiB").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parses_byte_per_second() {
        assert_eq!(parse_bytes("10MB/s").unwrap(), 10_000_000);
    }

    #[test]
    fn rejects_unknown_byte_suffix() {
        assert!(parse_bytes("32XYZ").is_err());
    }

    #[test]
    fn rejects_empty_bytes() {
        assert!(parse_bytes("").is_err());
        assert!(parse_bytes("   ").is_err());
    }

    #[test]
    fn parses_simple_durations() {
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn parses_compound_durations() {
        let d = parse_duration("2h30m").unwrap();
        assert_eq!(d.as_secs(), 2 * 3600 + 30 * 60);
        let d = parse_duration("1d2h").unwrap();
        assert_eq!(d.as_secs(), 86_400 + 2 * 3600);
    }

    #[test]
    fn rejects_unknown_duration_suffix() {
        assert!(parse_duration("5z").is_err());
    }

    #[test]
    fn formats_bytes_and_durations() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(64 * 1024 * 1024), "64.0 MiB");
        assert_eq!(format_duration(Duration::from_secs(0)), "0ms");
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m05s");
        assert_eq!(
            format_duration(Duration::from_secs(3 * 3600 + 5 * 60 + 7)),
            "3h05m07s"
        );
    }
}
