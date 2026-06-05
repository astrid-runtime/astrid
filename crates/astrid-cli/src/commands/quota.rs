//! `astrid quota` — per-principal resource quota inspection and edit.
//!
//! Calls Layer 6 admin IPC `astrid.v1.admin.quota.get`,
//! `astrid.v1.admin.quota.set`, and `astrid.v1.admin.usage.get` (the
//! read-only usage-vs-budget report shown alongside `quota show`). The
//! `set` flow does a get-modify-set round-trip rather than requiring the
//! operator to supply every quota field on the wire (which the
//! kernel-side `Quotas` struct demands).

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, ResourceUsage};
use astrid_core::profile::{BACKGROUND_PROCESSES_UPPER_BOUND, Quotas, TIMEOUT_SECS_UPPER_BOUND};
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
    /// Maximum CPU rate in wasmtime fuel units per second.
    pub max_cpu_fuel_per_sec: u64,
}

fn record(principal: &PrincipalId, q: &Quotas) -> QuotaRecord {
    QuotaRecord {
        principal: principal.to_string(),
        max_memory_bytes: q.max_memory_bytes,
        max_timeout_secs: q.max_timeout_secs,
        max_ipc_throughput_bytes: q.max_ipc_throughput_bytes,
        max_background_processes: q.max_background_processes,
        max_storage_bytes: q.max_storage_bytes,
        max_cpu_fuel_per_sec: q.max_cpu_fuel_per_sec,
    }
}

async fn fetch_quotas(client: &mut AdminClient, target: &PrincipalId) -> Result<Quotas> {
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

async fn fetch_usage(client: &mut AdminClient, target: &PrincipalId) -> Result<ResourceUsage> {
    let body = client
        .request(AdminRequestKind::UsageGet {
            principal: target.clone(),
        })
        .await?;
    let body = into_result(body)?;
    match body {
        AdminResponseBody::Usage(u) => Ok(u),
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
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let q = fetch_quotas(&mut client, &target).await?;
    if !format.is_pretty() {
        emit_structured(&record(&target, &q), format)?;
        return Ok(ExitCode::SUCCESS);
    }
    // Pretty mode pairs the configured ceilings with live consumption. Fetch
    // usage over the SAME connection and BEFORE printing anything, so a failure
    // on either request surfaces as a clean error instead of half-rendered
    // output — and `astrid quota show` costs one socket handshake, not two.
    let usage = fetch_usage(&mut client, &target).await?;
    print_quotas_pretty(&target, &q);
    println!();
    print_usage_pretty(&usage);
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
    println!(
        "  {:<24}  {}",
        "cpu-rate".bold(),
        format_fuel_rate(q.max_cpu_fuel_per_sec)
    );
}

/// Render the read-only usage-vs-budget report: live consumption paired
/// with the ceilings it's measured against. CPU is the cross-capsule fuel
/// total; the per-instance memory ceiling is shown because there is no
/// per-principal RAM aggregate yet (so `memory current` reads `n/a` until
/// that lands).
fn print_usage_pretty(u: &ResourceUsage) {
    println!("{}", "Usage vs budget".bold());
    println!(
        "  {:<24}  {} fuel",
        "cpu consumed".bold(),
        format_fuel(u.cpu_fuel_consumed_total)
    );
    println!(
        "  {:<24}  {}",
        "cpu rate limit".bold(),
        format_fuel_rate(u.cpu_fuel_per_sec_limit)
    );
    // Colour the security-relevant "exempt" affirmative and dim the n/a
    // memory placeholder; the label text itself comes from pure helpers so
    // both arms stay unit-testable without asserting on ANSI codes.
    let exempt = exempt_label(u.exempt);
    let exempt = if u.exempt {
        exempt.yellow().to_string()
    } else {
        exempt
    };
    println!("  {:<24}  {}", "exempt".bold(), exempt);
    let mem_current = mem_bytes_label(u.memory_bytes_current_total);
    let mem_current = if u.memory_bytes_current_total.is_none() {
        mem_current.dimmed().to_string()
    } else {
        mem_current
    };
    println!("  {:<24}  {}", "memory current".bold(), mem_current);
    let mem_peak = mem_bytes_label(u.memory_bytes_peak_total);
    let mem_peak = if u.memory_bytes_peak_total.is_none() {
        mem_peak.dimmed().to_string()
    } else {
        mem_peak
    };
    println!("  {:<24}  {}", "memory peak".bold(), mem_peak);
    println!(
        "  {:<24}  {}",
        "memory limit/instance".bold(),
        format_bytes(u.memory_bytes_limit_per_instance)
    );
}

/// Plain text for the `exempt` row (the caller colourises the affirmative).
/// `true` means the principal holds a resources-unbounded capability, so its
/// configured limits are advisory, never enforced — the state worth flagging.
fn exempt_label(exempt: bool) -> String {
    if exempt {
        "yes (limits advisory)".to_string()
    } else {
        "no".to_string()
    }
}

/// Plain text for an optional byte total (the `memory current` / `memory peak`
/// rows). `None` renders the `n/a` placeholder the caller dims: `current` has no
/// per-principal aggregate, and `peak` is `None` until a guest grows memory.
fn mem_bytes_label(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => format_bytes(b),
        None => "n/a".to_string(),
    }
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
    let mut client = crate::admin_client::connect_as_active_agent().await?;
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

/// Render a wasmtime-fuel count with decimal SI suffixes. Fuel is a raw
/// instruction count, so decimal magnitudes (k/M/G) read more naturally
/// than the binary units used for bytes.
#[expect(
    clippy::cast_precision_loss,
    reason = "human-readable rendering, exact magnitude is not the point"
)]
fn format_fuel(n: u64) -> String {
    const K: f64 = 1_000.0;
    const M: f64 = 1_000_000.0;
    const G: f64 = 1_000_000_000.0;
    const T: f64 = 1_000_000_000_000.0;
    let f = n as f64;
    // Thresholds are `999.95 * unit`, the point at which `{:.1}` of the
    // *smaller* unit would round up to "1000.0" — so a value carries into the
    // next unit instead (e.g. 999_999 renders "1.0M", never "1000.0k"), keeping
    // the mantissa < 1000. Cumulative fuel is monotonic for the daemon's
    // lifetime, so T is reachable; above T there is no larger unit, so a huge
    // mantissa there is accepted rather than mis-rendered.
    if f >= 999.95 * G {
        format!("{:.1}T", f / T)
    } else if f >= 999.95 * M {
        format!("{:.1}G", f / G)
    } else if f >= 999.95 * K {
        format!("{:.1}M", f / M)
    } else if f >= 999.95 {
        format!("{:.1}k", f / K)
    } else {
        n.to_string()
    }
}

/// Render a fuel-per-second ceiling. The configured ceiling is always `> 0`
/// (validation rejects `0` — there is no "unlimited" sentinel; unbounded CPU is
/// a capability, surfaced separately by the `exempt` flag).
fn format_fuel_rate(n: u64) -> String {
    format!("{}/s", format_fuel(n))
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
    fn formats_fuel_counts() {
        assert_eq!(format_fuel(0), "0");
        assert_eq!(format_fuel(999), "999");
        assert_eq!(format_fuel(1_500), "1.5k");
        assert_eq!(format_fuel(2_000_000), "2.0M");
        assert_eq!(format_fuel(3_500_000_000), "3.5G");
        // Cumulative fuel scales into the trillions over a long daemon run.
        assert_eq!(format_fuel(1_500_000_000_000), "1.5T");
    }

    #[test]
    fn format_fuel_hits_exact_unit_boundaries() {
        // Pin the `>=` thresholds so a `>` off-by-one would regress.
        assert_eq!(format_fuel(1_000), "1.0k");
        assert_eq!(format_fuel(1_000_000), "1.0M");
        assert_eq!(format_fuel(1_000_000_000), "1.0G");
        assert_eq!(format_fuel(1_000_000_000_000), "1.0T");
    }

    #[test]
    fn format_fuel_carries_at_the_rounding_boundary() {
        // A value just under a unit must NOT render as "1000.0<smaller>": the
        // mantissa stays < 1000 by carrying into the next unit.
        assert_eq!(format_fuel(999_999), "1.0M");
        assert_eq!(format_fuel(999_999_999), "1.0G");
        assert_eq!(format_fuel(999_999_999_999), "1.0T");
        // Just below the carry point still renders in the smaller unit.
        assert_eq!(format_fuel(999_949), "999.9k");
    }

    #[test]
    fn record_copies_cpu_ceiling_into_wire_shape() {
        // record() feeds the --format json/yaml/toml surface; assert the
        // same-typed ceilings land in their own slots (a swap would compile).
        let p = PrincipalId::new("alice").unwrap();
        let q = Quotas {
            max_cpu_fuel_per_sec: 7_777,
            max_memory_bytes: 11,
            max_storage_bytes: 22,
            ..Quotas::default()
        };
        let r = record(&p, &q);
        assert_eq!(r.principal, "alice");
        assert_eq!(r.max_cpu_fuel_per_sec, 7_777);
        assert_eq!(r.max_memory_bytes, 11);
        assert_eq!(r.max_storage_bytes, 22);
    }

    #[test]
    fn usage_row_labels_cover_both_arms() {
        // The kernel stub returns exempt=false / memory=None today, so the
        // exempt=true and Some(memory) render paths are otherwise unexercised.
        assert_eq!(exempt_label(true), "yes (limits advisory)");
        assert_eq!(exempt_label(false), "no");
        assert_eq!(mem_bytes_label(None), "n/a");
        assert_eq!(mem_bytes_label(Some(2048)), "2.0 KiB");
    }

    #[test]
    fn formats_fuel_rate_as_per_second() {
        // The ceiling is always > 0 (validation rejects 0); unbounded CPU is
        // the `exempt` flag, never a "0 = unlimited" sentinel here.
        assert_eq!(format_fuel_rate(1_000_000_000), "1.0G/s");
        assert_eq!(format_fuel_rate(500), "500/s");
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
