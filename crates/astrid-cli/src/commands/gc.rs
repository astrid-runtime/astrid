//! `astrid gc` — garbage collect content-addressed stores.
//!
//! Today this delegates to the existing `wit gc` implementation. Kept
//! as a top-level `astrid gc` because the noun-verb redesign promotes
//! garbage collection to a system-level verb (it sweeps multiple
//! content stores, not just `wit`). Future kernels are expected to
//! extend this with `bin/` orphan removal and per-principal storage
//! reclamation; the CLI shape stays the same.

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;

use crate::commands::wit;

#[derive(Args, Debug, Clone)]
pub(crate) struct GcArgs {
    /// Delete unreferenced blobs (without this flag, only reports them).
    #[arg(long)]
    pub force: bool,
}

/// Entry point for `astrid gc`.
pub(crate) fn run(args: &GcArgs) -> Result<ExitCode> {
    wit::gc(args.force)?;
    Ok(ExitCode::SUCCESS)
}
