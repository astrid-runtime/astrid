//! Astrid Build - Capsule compilation and packaging tool.
//!
//! Compiles Rust, `OpenClaw`, and legacy MCP projects into `.capsule` archives.
//! Typically invoked by the CLI (`astrid build`) but can be used standalone.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use clap::Parser;

mod archiver;
mod build;
mod js;
mod mcp;
mod openclaw;
mod rust;
/// WIT record → JSON Schema conversion for IPC topic schemas.
pub mod wit_schema;

/// CLI arguments for `astrid-build`.
#[derive(Parser)]
#[command(name = "astrid-build")]
#[command(author, version, about = "Capsule compilation and packaging")]
pub struct Args {
    /// Path to the project directory (defaults to current directory)
    pub path: Option<String>,

    /// Output directory for the packaged `.capsule` archive
    #[arg(short, long)]
    pub output: Option<String>,

    /// Explicitly define the project type (e.g., 'mcp' for legacy host servers)
    #[arg(short = 't', long = "type")]
    pub project_type: Option<String>,

    /// Import a legacy `mcp.json` to auto-convert
    #[arg(long)]
    pub from_mcp_json: Option<String>,

    /// Internal: run Wizer on the embedded `QuickJS` kernel (used by compiler subprocess)
    #[arg(long, hide = true)]
    pub wizer_internal: Option<std::path::PathBuf>,
}

/// Parse CLI arguments and run the build tool.
///
/// Single entry point for both the standalone and bundled binaries.
///
/// # Errors
/// Returns an error if the build fails (missing manifest, compile error, etc.).
pub fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(output) = args.wizer_internal {
        return astrid_openclaw::compiler::run_wizer_internal(&output)
            .map_err(|e| anyhow::anyhow!("wizer-internal failed: {e}"));
    }

    build::run_build(
        args.path.as_deref(),
        args.output.as_deref(),
        args.project_type.as_deref(),
        args.from_mcp_json.as_deref(),
    )
}
