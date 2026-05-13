//! `astrid budget` — agent budget allocation and accounting (deferred).
//!
//! Budget admin IPC is partially designed in #653 + #656 but not yet
//! shipped: the kernel has no `admin.budget.set` / `admin.budget.get`
//! topic, no spend ledger, and no balance-tracking storage layer. The
//! CLI surface is registered so operators can run `astrid budget --help`
//! and see what's coming, but every leaf prints a tracking reference
//! and exits with code 2.

use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::commands::stub::{self, ISSUE_BUDGET, ISSUE_DELEGATION};

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum BudgetCommand {
    /// View budget allocation and spend.
    Show(StubArgs),
    /// Set budget for an agent.
    Set(StubArgs),
    /// Transfer budget between agents.
    Transfer(StubArgs),
    /// Show spending history.
    History(StubArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct StubArgs {
    /// Free-form arguments — see module docs.
    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Top-level dispatcher for `astrid budget`.
#[expect(
    clippy::unnecessary_wraps,
    reason = "uniform dispatcher signature; surface is deferred until #653/#656"
)]
pub(crate) fn run(_cmd: BudgetCommand) -> Result<ExitCode> {
    Ok(stub::deferred(
        "budget management",
        &[ISSUE_BUDGET, ISSUE_DELEGATION],
    ))
}
