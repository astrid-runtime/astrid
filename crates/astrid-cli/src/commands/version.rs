//! `astrid version` — print version information.

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde::Serialize;

use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Args, Debug, Clone)]
pub(crate) struct VersionArgs {
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// JSON/YAML/TOML emission shape.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct VersionInfo {
    /// CLI binary version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Git commit hash if injected at build time, otherwise `unknown`.
    pub commit: String,
    /// Build target triple.
    pub target: String,
}

/// Entry point for `astrid version`.
pub(crate) fn run(args: &VersionArgs) -> Result<ExitCode> {
    let info = VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("ASTRID_GIT_COMMIT")
            .unwrap_or("unknown")
            .to_string(),
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
    };
    let format = ValueFormat::parse(&args.format);
    if !format.is_pretty() {
        emit_structured(&info, format)?;
        return Ok(ExitCode::SUCCESS);
    }
    println!("{} {}", "astrid".bold(), info.version.cyan());
    println!("  commit: {}", info.commit);
    println!("  target: {}", info.target);
    Ok(ExitCode::SUCCESS)
}
