//! `astrid audit` — audit trail inspection (deferred).
//!
//! Layer 7 (#675) lands the per-principal audit chain routing and
//! admin IPC for querying entries without filesystem access. Until
//! that ships, operators can read the chain directly from
//! `~/.astrid/var/audit/` — the kernel writes the `SurrealKV` files
//! there. The CLI surface is registered for forward compatibility.

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;

use crate::commands::stub::{self, ISSUE_AUDIT};

#[derive(Args, Debug, Clone)]
pub(crate) struct AuditArgs {
    /// Agent name (defaults to all when omitted; the deferred Layer 7
    /// IPC will scope reads through `audit:view:self` vs `audit:view`).
    pub name: Option<String>,
    /// Free-form additional arguments — accepted so the surface parses
    /// without choking on filter flags written against the future shape.
    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Entry point for `astrid audit`.
#[expect(
    clippy::unnecessary_wraps,
    reason = "uniform dispatcher signature; surface is deferred until #675"
)]
pub(crate) fn run(_args: &AuditArgs) -> Result<ExitCode> {
    Ok(stub::deferred("audit trail inspection", &[ISSUE_AUDIT]))
}
