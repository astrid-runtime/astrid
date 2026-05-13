//! `astrid run` — one-shot non-interactive prompt execution.
//!
//! Sends a single user prompt to the React capsule, prints the
//! response, and exits. Designed for scripting and CI. The
//! implementation reuses [`crate::commands::headless::run_headless`]
//! which already handles the prompt-injection wire format.

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;

use crate::commands::headless;
use crate::formatter::OutputFormat;

#[derive(Args, Debug, Clone)]
pub(crate) struct RunArgs {
    /// The prompt to send.
    pub prompt: String,
    /// Auto-approve every tool elicitation (alias `--yolo`).
    #[arg(short = 'y', long = "yes", alias = "yolo", alias = "autonomous")]
    pub auto_approve: bool,
    /// Resume or create a named session for multi-turn scripting.
    #[arg(long = "session")]
    pub session_name: Option<String>,
    /// Print the session ID to stderr after the response (for chaining).
    #[arg(long = "print-session")]
    pub print_session: bool,
    /// Output format: `pretty` (default), `json`, or `stream-json`.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// Top-level entry point for `astrid run`.
pub(crate) async fn run(args: RunArgs) -> Result<ExitCode> {
    let format = match args.format.as_str() {
        "json" | "stream-json" => OutputFormat::Json,
        _ => OutputFormat::Pretty,
    };
    headless::run_headless(
        args.prompt,
        format,
        args.auto_approve,
        args.session_name,
        args.print_session,
    )
    .await?;
    Ok(ExitCode::SUCCESS)
}
