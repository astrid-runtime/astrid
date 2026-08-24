//! Thin host-hook publisher.
//!
//! The hook command is intentionally independent of daemon bootstrap,
//! workspace config, and capsule discovery. It resolves one topic, reuses the
//! small `astrid-emit` transport, and exits after one connect/write/close.

use std::process::ExitCode;

use anyhow::Result;
use astrid_emit::{DEFAULT_POLICY_TIMEOUT_MS, HostHookEnvValues};
use clap::Args;

const FAIL_CLOSED_ENV: &str = "ASTRID_CODEX_HOOK_FAIL_CLOSED";

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

    /// Host workspace identifier forwarded as top-level envelope metadata.
    #[arg(long, value_name = "WORKSPACE")]
    pub workspace: Option<String>,

    /// Maximum transport wait in milliseconds. When omitted, observation
    /// events use `0` (fire-and-forget) and policy events use a bounded
    /// 1000 ms wait. Policy events must stay within 200-2000 ms.
    #[arg(
        long = "timeout-ms",
        value_name = "MILLISECONDS",
        value_parser = parse_timeout_ms,
    )]
    pub timeout_ms: Option<u64>,
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

/// Codex hooks that can gate an operation need a bounded transport wait.
/// Everything else is observation-only and defaults to connect/write/close
/// without an outer timer.
fn is_policy_event(event: &str) -> bool {
    matches!(event, "pre_tool_use" | "permission_request")
}

fn default_timeout_ms(event: &str) -> u64 {
    if is_policy_event(event) {
        DEFAULT_POLICY_TIMEOUT_MS
    } else {
        0
    }
}

fn timeout_for_event(event: &str, requested: Option<u64>) -> Result<u64> {
    let timeout_ms = requested.unwrap_or_else(|| default_timeout_ms(event));
    if is_policy_event(event) && timeout_ms == 0 {
        anyhow::bail!("policy hook {event} requires a timeout from 200 to 2000 milliseconds");
    }
    Ok(timeout_ms)
}

/// Whether a hook transport failure should be surfaced to the host as a
/// failing command. The default is deliberately fail-open so a missing or
/// temporarily unavailable runtime cannot wedge an agent session.
pub(crate) fn fail_closed_requested() -> bool {
    std::env::var(FAIL_CLOSED_ENV).is_ok_and(|value| value == "1")
}

/// Convert a hook-side failure to the host process status according to the
/// explicit fail-closed opt-in.
pub(crate) fn failure_exit_code() -> ExitCode {
    if fail_closed_requested() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn report_failure(error: impl std::fmt::Display) -> ExitCode {
    astrid_emit::write_continue_line();
    eprintln!("astrid hook: {error}");
    failure_exit_code()
}

/// Resolve the topic and publish one hook event.
pub(crate) async fn run(args: HookArgs) -> Result<ExitCode> {
    let timeout_ms = match timeout_for_event(&args.event, args.timeout_ms) {
        Ok(timeout_ms) => timeout_ms,
        Err(error) => return Ok(report_failure(error)),
    };
    let topic = match astrid_emit::hook_topic(&args.host, &args.session, &args.event) {
        Ok(topic) => topic,
        Err(error) => return Ok(report_failure(error)),
    };
    let token = match astrid_emit::hook_token_from_env() {
        Ok(token) => token,
        Err(error) => return Ok(report_failure(error)),
    };
    let principal = crate::principal::current().to_string();
    let env = HostHookEnvValues {
        principal_id: &principal,
        session_id: &args.session,
        token: &token,
        event: Some(&args.event),
        workspace_id: args.workspace.as_deref(),
    };
    let exit = astrid_emit::run_host_topic(&topic, &env, timeout_ms).await;
    if fail_closed_requested() {
        Ok(exit)
    } else {
        Ok(ExitCode::SUCCESS)
    }
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
        assert_eq!(cli.args.timeout_ms, Some(0));
    }

    #[test]
    fn omitted_timeout_defaults_by_hook_kind() {
        assert_eq!(
            default_timeout_ms("pre_tool_use"),
            DEFAULT_POLICY_TIMEOUT_MS
        );
        assert_eq!(
            default_timeout_ms("permission_request"),
            DEFAULT_POLICY_TIMEOUT_MS
        );
        assert_eq!(default_timeout_ms("session_start"), 0);
        assert_eq!(default_timeout_ms("post_tool_use"), 0);
        assert_eq!(
            timeout_for_event("pre_tool_use", None).expect("policy default"),
            1000
        );
        assert_eq!(
            timeout_for_event("session_start", None).expect("observe default"),
            0
        );
    }

    #[test]
    fn policy_hooks_reject_unbounded_zero_timeout() {
        assert!(timeout_for_event("pre_tool_use", Some(0)).is_err());
        assert_eq!(
            timeout_for_event("session_start", Some(0)).expect("observe timeout"),
            0
        );
    }

    #[test]
    fn transport_failure_respects_fail_closed_opt_in() {
        let test_exe = std::env::current_exe().expect("locate hook test binary");
        let root = tempfile::Builder::new()
            .prefix("astrid-hook-policy-")
            .tempdir()
            .expect("create throwaway hook test home");
        let home = root.path().join("home");
        let astrid_home = root.path().join("astrid");
        std::fs::create_dir_all(&home).expect("create throwaway HOME");
        std::fs::create_dir_all(&astrid_home).expect("create throwaway ASTRID_HOME");

        // The child executes the real hook command against the absent socket
        // under the throwaway ASTRID_HOME, so its transport result is a
        // failure rather than a synthetic exit code.
        let cases = [
            ("default", None),
            ("unset", None),
            ("empty", Some("")),
            ("true", Some("true")),
            ("zero", Some("0")),
            ("one", Some("1")),
        ];
        for (label, fail_closed) in cases {
            let mut command = std::process::Command::new(&test_exe);
            command
                .arg("--exact")
                .arg("commands::hook::tests::transport_failure_policy_child")
                .arg("--ignored")
                .arg("--quiet")
                .env("ASTRID_HOOK_POLICY_CHILD", "1")
                .env("ASTRID_HOOK_TOKEN", "hook-token")
                .env("HOME", &home)
                .env("ASTRID_HOME", &astrid_home)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            match fail_closed {
                Some(value) => {
                    command.env(FAIL_CLOSED_ENV, value);
                },
                None => {
                    command.env_remove(FAIL_CLOSED_ENV);
                },
            }

            let output = command
                .output()
                .unwrap_or_else(|error| panic!("run {label} hook policy child: {error}"));
            assert!(
                output.status.success(),
                "{label} hook policy child failed with status {}",
                output.status
            );
        }
    }

    #[ignore = "subprocess-only hook policy fixture"]
    #[tokio::test]
    async fn transport_failure_policy_child() {
        if std::env::var_os("ASTRID_HOOK_POLICY_CHILD").is_none() {
            return;
        }

        let actual = run(HookArgs {
            host: "codex".to_string(),
            session: "isolated".to_string(),
            event: "session_start".to_string(),
            workspace: None,
            timeout_ms: Some(0),
        })
        .await
        .expect("hook transport result");
        let expected = match std::env::var(FAIL_CLOSED_ENV) {
            Ok(value) if value == "1" => ExitCode::from(1),
            _ => ExitCode::SUCCESS,
        };
        assert_eq!(actual, expected, "unexpected hook transport policy result");
    }
}
