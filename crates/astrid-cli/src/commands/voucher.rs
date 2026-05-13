//! `astrid voucher` — capability voucher management (deferred).
//!
//! All five verbs (`create`, `list`, `show`, `revoke`, `history`) are
//! registered so `astrid --help` documents the full surface, but every
//! leaf prints a "tracking #656" message and exits with code 2. The
//! voucher primitive lives kernel-side and the CLI cannot stand up a
//! useful local placeholder without it.

use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::commands::stub::{self, ISSUE_DELEGATION};

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum VoucherCommand {
    /// Create a new delegation voucher.
    Create(StubArgs),
    /// List active vouchers.
    List(StubArgs),
    /// Show voucher details.
    Show(StubArgs),
    /// Revoke a voucher immediately.
    Revoke(StubArgs),
    /// View expired/completed vouchers.
    History(StubArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct StubArgs {
    /// Free-form arguments — accepted so the deferred surface parses
    /// without choking on flags written against the future shape.
    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Top-level dispatcher for `astrid voucher`.
#[expect(
    clippy::unnecessary_wraps,
    reason = "uniform dispatcher signature; surface is deferred until #656"
)]
pub(crate) fn run(_cmd: VoucherCommand) -> Result<ExitCode> {
    Ok(stub::deferred(
        "capability voucher management",
        &[ISSUE_DELEGATION],
    ))
}
