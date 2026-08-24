//! Thin host-hook publisher.
//!
//! The hook command is intentionally independent of daemon bootstrap,
//! workspace config, and capsule discovery. It resolves one topic, reuses the
//! small `astrid-emit` transport, and exits after one connect/write/close.

use std::process::ExitCode;

use anyhow::Result;
use astrid_emit::{DEFAULT_POLICY_TIMEOUT_MS, HookEnvValues};
use clap::Args;

/// Publish one host hook envelope without starting a second daemon/client.
#[derive(Debug, Args)]
pub(crate) struct HookArgs {
    /// Host adapter name (for example `codex` or `claude`).
    #[arg(long, value_name = "HOST")]
    pub host: String,

    /// Host session identifier carried by the envelope and topic.
    #[arg(long, value_name = "SESSION")]
    pub session: String,

    /// Host hook event name.
    #[arg(long, value_name = "EVENT")]
    pub event: String,

    /// Host workspace identifier. The hook payload remains opaque; this flag
    /// is accepted so host adapters can keep one stable invocation shape.
    #[arg(long, value_name = "WORKSPACE")]
    pub workspace: Option<String>,

    /// Maximum transport wait in milliseconds. `0` is fire-and-forget for
    /// observation hooks; policy hooks default to a bounded 1000 ms wait.
    #[arg(
        long = "timeout-ms",
        value_name = "MILLISECONDS",
        default_value_t = DEFAULT_POLICY_TIMEOUT_MS,
        value_parser = parse_timeout_ms,
    )]
    pub timeout_ms: u64,
}

fn parse_timeout_ms(value: &str) -> std::result::Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "timeout must be 0 or an integer from 200 to 2000 milliseconds".to_string())?;
    if parsed == 0 || (200..=2_000).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("timeout must be 0 or an integer from 200 to 2000 milliseconds".to_string())
    }
}

/// Resolve the topic and publish one hook event.
pub(crate) async fn run(args: HookArgs) -> Result<ExitCode> {
    let topic = match astrid_emit::hook_topic(&args.host, &args.session, &args.event) {
        Ok(topic) => topic,
        Err(error) => {
            astrid_emit::write_continue_line();
            eprintln!("astrid hook: {error}");
            return Ok(ExitCode::from(1));
        },
    };
    let token = match astrid_emit::hook_token_from_env() {
        Ok(token) => token,
        Err(error) => {
            astrid_emit::write_continue_line();
            eprintln!("astrid hook: {error}");
            return Ok(ExitCode::from(1));
        },
    };
    let principal = crate::principal::current().to_string();
    let env = HookEnvValues {
        principal_id: &principal,
        session_id: &args.session,
        token: &token,
    };
    Ok(astrid_emit::run_topic(&topic, &env, args.timeout_ms).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        args: HookArgs,
    }

    #[test]
    fn timeout_parser_allows_observation_and_policy_bounds() {
        assert_eq!(parse_timeout_ms("0").expect("observe timeout"), 0);
        assert_eq!(
            parse_timeout_ms("200").expect("minimum policy timeout"),
            200
        );
        assert_eq!(
            parse_timeout_ms("2000").expect("maximum policy timeout"),
            2000
        );
        assert!(parse_timeout_ms("1").is_err());
        assert!(parse_timeout_ms("2001").is_err());
    }

    #[test]
    fn hook_args_keep_plugin_invocation_shape() {
        let cli = TestCli::try_parse_from([
            "astrid",
            "--host",
            "codex",
            "--session",
            "s1",
            "--event",
            "pre_tool_use",
            "--workspace",
            "cwd-1",
            "--timeout-ms",
            "0",
        ])
        .expect("hook flags parse");
        assert_eq!(cli.args.host, "codex");
        assert_eq!(cli.args.session, "s1");
        assert_eq!(cli.args.event, "pre_tool_use");
        assert_eq!(cli.args.workspace.as_deref(), Some("cwd-1"));
        assert_eq!(cli.args.timeout_ms, 0);
    }
}
