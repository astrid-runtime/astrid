//! `astrid top` — live resource monitor.
//!
//! A live TUI dashboard requires per-capsule telemetry (#639) and per-
//! principal budget telemetry which are not yet wired. We render a
//! one-shot snapshot using the same data `astrid ps` and `astrid who`
//! consume, plus a footnote explaining what columns will fill in once
//! the telemetry lands. Operators get a working command today and a
//! straightforward upgrade path later — no fabricated values.

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use colored::Colorize;

use crate::commands::ps;
use crate::theme::Theme;

#[derive(Args, Debug, Clone)]
pub(crate) struct TopArgs {
    /// Output format. Currently only `pretty` is meaningful — the
    /// flag is registered for forward compatibility with the live TUI
    /// upgrade.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// Entry point for `astrid top`.
pub(crate) async fn run(args: TopArgs) -> Result<ExitCode> {
    println!(
        "{}",
        Theme::info(
            "astrid top — one-shot snapshot (live TUI deferred until telemetry #639 lands)"
        )
    );
    println!();
    println!("{}", "Capsules".bold());
    let exit = ps::run(ps::PsArgs {
        format: args.format,
    })
    .await?;
    println!();
    println!(
        "{}",
        Theme::info(
            "Per-agent budget / IPC-rate columns blocked on telemetry (#639) and budget admin IPC (#653/#656)."
        )
    );
    Ok(exit)
}
