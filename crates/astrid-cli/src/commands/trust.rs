//! `astrid trust` — cross-host A2A trust management (deferred).
//!
//! Blocked on both #656 (capability vouchers as the delegation
//! primitive) and #658 (remote auth + A2A endpoints). Without remote
//! auth a `trust add <url>` cannot fetch a verifiable Agent Card, and
//! without vouchers the trust relationship has nothing to gate.

use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::commands::stub::{self, ISSUE_DELEGATION, ISSUE_REMOTE_AUTH};

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum TrustCommand {
    /// Add trust for a remote host.
    Add(StubArgs),
    /// List trusted hosts.
    List(StubArgs),
    /// Remove trust for a remote host.
    Remove(StubArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct StubArgs {
    /// Free-form arguments — see module docs.
    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Top-level dispatcher for `astrid trust`.
#[expect(
    clippy::unnecessary_wraps,
    reason = "uniform dispatcher signature; surface is deferred until #656/#658"
)]
pub(crate) fn run(_cmd: TrustCommand) -> Result<ExitCode> {
    Ok(stub::deferred(
        "cross-host trust management",
        &[ISSUE_DELEGATION, ISSUE_REMOTE_AUTH],
    ))
}
