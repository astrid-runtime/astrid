//! `astrid run` — one-shot non-interactive prompt execution.
//!
//! Sends a single user prompt to the React capsule, prints the
//! response, and exits. Designed for scripting and CI. The
//! implementation reuses [`crate::commands::headless::run_headless`]
//! which already handles the prompt-injection wire format.

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Args;

use crate::commands::headless;
use crate::formatter::OutputFormat;

#[derive(Args, Debug, Clone)]
pub(crate) struct RunArgs {
    /// The prompt to send.
    pub prompt: String,
    /// Unsupported approval automation (aliases `--yolo` and `--autonomous`);
    /// rejected before execution.
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
    /// Seconds to wait for the next active-run message. Overrides the
    /// client configuration; it is not a whole-request deadline.
    #[arg(
        long = "idle-timeout-secs",
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..=astrid_config::MAX_RUN_IDLE_TIMEOUT_SECS)
    )]
    pub idle_timeout_secs: Option<u64>,
}

/// Top-level entry point for `astrid run`.
pub(crate) async fn run(args: RunArgs) -> Result<ExitCode> {
    if args.auto_approve {
        anyhow::bail!(headless::AUTO_APPROVE_UNSUPPORTED_MESSAGE);
    }

    let format = match args.format.as_str() {
        "json" | "stream-json" => OutputFormat::Json,
        _ => OutputFormat::Pretty,
    };
    let client_path = if args.idle_timeout_secs.is_none() {
        astrid_config::client::production_client_config_path()
            .context("failed to resolve client configuration")?
    } else {
        None
    };
    let idle_timeout_secs =
        resolve_idle_timeout_secs(args.idle_timeout_secs, client_path.as_deref())
            .context("failed to resolve client idle timeout")?;
    let idle_timeout = headless::idle_timeout(idle_timeout_secs)?;

    let code = headless::run_headless_with_timeout(
        args.prompt,
        format,
        args.session_name,
        args.print_session,
        idle_timeout,
    )
    .await?;
    Ok(ExitCode::from(code))
}

/// An explicit invocation wins; otherwise load the isolated client file.
fn resolve_idle_timeout_secs(
    explicit: Option<u64>,
    client_path: Option<&std::path::Path>,
) -> Result<u64> {
    astrid_config::client::resolve_run_idle_timeout(explicit, client_path).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    fn parse_run_args(arguments: &[&str]) -> RunArgs {
        let mut command = crate::cli::Cli::command();
        let matches = command
            .try_get_matches_from_mut(["astrid", "run", "hello"].iter().chain(arguments))
            .unwrap();
        let (name, subcommand) = matches.subcommand().unwrap();
        assert_eq!(name, "run");
        RunArgs::from_arg_matches(subcommand).unwrap()
    }

    #[test]
    fn run_idle_timeout_defaults_to_absent() {
        assert!(parse_run_args(&[]).idle_timeout_secs.is_none());
    }

    #[tokio::test]
    async fn run_auto_approve_is_rejected_before_execution() {
        for flag in ["--yes", "--yolo", "--autonomous"] {
            let error = run(parse_run_args(&[flag]))
                .await
                .expect_err("approval automation must be rejected");

            assert!(error.to_string().contains("unsupported"));
            assert!(error.to_string().contains("correlated"));
        }
    }

    #[test]
    fn run_idle_timeout_parses_explicit_override() {
        let args = parse_run_args(&["--idle-timeout-secs", "300"]);
        assert_eq!(args.idle_timeout_secs, Some(300));
    }

    #[test]
    fn explicit_idle_timeout_bypasses_client_path_resolution() {
        assert_eq!(
            resolve_idle_timeout_secs(Some(300), Some(std::path::Path::new("/missing"))).unwrap(),
            300
        );
    }

    #[test]
    fn run_idle_timeout_rejects_zero() {
        let result = crate::cli::Cli::command().try_get_matches_from([
            "astrid",
            "run",
            "hello",
            "--idle-timeout-secs",
            "0",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn run_idle_timeout_rejects_unreasonable_values() {
        let result = crate::cli::Cli::command().try_get_matches_from([
            "astrid",
            "run",
            "hello",
            "--idle-timeout-secs",
            "86401",
        ]);
        assert!(result.is_err());
    }
}
