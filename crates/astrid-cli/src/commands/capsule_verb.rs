//! `astrid capsule <verb> [args...]` — dispatch a capsule-contributed CLI
//! verb (`[[command]]` with `kind = "cli"`) to its providing capsule over
//! IPC as a non-interactive one-shot.
//!
//! Flow:
//! 1. **Daemon** — these verbs require the daemon; auto-start it if the
//!    socket is missing (reusing [`daemon::ensure_daemon`]).
//! 2. **Resolve** — connect a [`SocketClient`], ask the kernel for the
//!    command registry (`GetCommands`), and filter to `kind == cli`.
//! 3. **Match** — resolve `(verb, providers)` to exactly one provider, or
//!    report an actionable error (zero/ambiguous).
//! 4. **Execute** — publish `cli.v1.command.run.<provider>` and await
//!    `cli.v1.command.result.<req_id>` with a bounded result budget.
//! 5. **Render** — print `output`/`error` and exit with the capsule's
//!    `exit_code`.
//!
//! The kernel does not interpret the run/result payloads — that contract
//! is capsule-space (see [`astrid_core::kernel_api::CommandKind`]).

use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use uuid::Uuid;

use astrid_core::kernel_api::{CommandInfo, CommandKind};

use crate::commands::daemon;
use crate::socket_client::SocketClient;
use crate::theme::Theme;

/// Wall-clock budget for a capsule to respond on the result topic.
const RESULT_TIMEOUT_SECS: u64 = 70;
const RESULT_TIMEOUT: Duration = Duration::from_secs(RESULT_TIMEOUT_SECS);
const CAPSULES_LOADED_TOPIC: &str = "astrid.v1.capsules_loaded";

/// Outcome of resolving a verb against the daemon's command registry.
///
/// Pure function over `(verb, &[CommandInfo])` so the zero/one/many
/// branches are unit-testable without a live daemon.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerbMatch {
    /// Exactly one capsule provides this CLI verb.
    One {
        /// The providing capsule id.
        provider: String,
        /// Resolved description (for diagnostics; unused on the happy path).
        description: String,
    },
    /// No capsule provides this CLI verb.
    None,
    /// More than one capsule provides this CLI verb — the operator must
    /// disambiguate with `astrid capsule run <provider> <verb>`.
    Ambiguous {
        /// All providers, in registry order.
        providers: Vec<String>,
    },
}

/// Resolve a CLI verb against the command registry.
///
/// Only `kind == cli` entries are considered; slash commands are ignored.
pub(crate) fn match_verb(verb: &str, commands: &[CommandInfo]) -> VerbMatch {
    let providers: Vec<&CommandInfo> = commands
        .iter()
        .filter(|c| c.kind == CommandKind::Cli && c.name == verb)
        .collect();
    match providers.as_slice() {
        [] => VerbMatch::None,
        [only] => VerbMatch::One {
            provider: only.provider_capsule.clone(),
            description: only.description.clone(),
        },
        many => VerbMatch::Ambiguous {
            providers: many.iter().map(|c| c.provider_capsule.clone()).collect(),
        },
    }
}

/// Entry point for `astrid capsule <verb> [args...]` (external subcommand).
///
/// `tokens` is the raw clap external-subcommand vector: the first token is
/// the verb, the rest are forwarded to the capsule verbatim.
pub(crate) async fn run_external(tokens: Vec<String>) -> Result<ExitCode> {
    let mut it = tokens.into_iter();
    let Some(verb) = it.next() else {
        eprintln!("{}", Theme::error("No capsule verb given."));
        return Ok(ExitCode::from(1));
    };
    let args: Vec<String> = it.collect();

    let commands = match resolve_commands().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", Theme::error(&format!("{e}")));
            return Ok(ExitCode::from(1));
        },
    };

    match match_verb(&verb, &commands) {
        VerbMatch::One { provider, .. } => execute(&provider, &verb, &args).await,
        VerbMatch::None => {
            eprintln!(
                "{}",
                Theme::error(&format!("Unknown capsule command: '{verb}'"))
            );
            print_available(&commands);
            Ok(ExitCode::from(1))
        },
        VerbMatch::Ambiguous { providers } => {
            eprintln!(
                "{}",
                Theme::error(&format!(
                    "Multiple capsules provide '{verb}': {}",
                    providers.join(", ")
                ))
            );
            eprintln!("Disambiguate with one of:");
            for p in &providers {
                eprintln!("  astrid capsule run {p} {verb}");
            }
            Ok(ExitCode::from(1))
        },
    }
}

/// Entry point for `astrid capsule run <provider> <verb> [args...]`.
///
/// Skips ambiguity resolution but still validates that the
/// `(provider, verb, kind=cli)` triple exists before dispatching.
pub(crate) async fn run_explicit(
    provider: String,
    verb: String,
    args: Vec<String>,
) -> Result<ExitCode> {
    let commands = match resolve_commands().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", Theme::error(&format!("{e}")));
            return Ok(ExitCode::from(1));
        },
    };

    let exists = commands
        .iter()
        .any(|c| c.kind == CommandKind::Cli && c.name == verb && c.provider_capsule == provider);
    if !exists {
        eprintln!(
            "{}",
            Theme::error(&format!(
                "Capsule '{provider}' does not provide CLI verb '{verb}'."
            ))
        );
        print_available(&commands);
        return Ok(ExitCode::from(1));
    }

    execute(&provider, &verb, &args).await
}

/// Ensure the daemon is up, connect, and fetch the CLI command registry.
async fn resolve_commands() -> Result<Vec<CommandInfo>> {
    // These verbs require the daemon — auto-start it if needed.
    daemon::ensure_daemon("capsule").await?;

    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let source_id = session.0;
    // Bind the connection to the active principal (and stamp it on the
    // request) so the daemon scopes this management request to the invoking
    // identity. A nil source with no principal falls back to the `default`
    // (admin) principal — letting a non-admin enumerate capsule verbs under
    // admin context, an RBAC bypass.
    let caller = crate::principal::current();
    let mut client = SocketClient::connect(session, caller.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {e}"))?;

    let req = astrid_core::kernel_api::KernelRequest::GetCommands;
    let val = serde_json::to_value(req)?;
    let msg = astrid_types::ipc::IpcMessage::new(
        astrid_types::Topic::kernel_request("get_commands"),
        astrid_types::ipc::IpcPayload::RawJson(val),
        source_id,
    )
    .with_principal(caller.to_string());
    client.send_message(msg).await?;
    let raw = client
        .read_until_topic(
            astrid_types::Topic::kernel_response("get_commands").as_str(),
            Duration::from_secs(10),
        )
        .await?;
    match SocketClient::extract_kernel_response(&raw) {
        Some(astrid_core::kernel_api::KernelResponse::Commands(cmds)) => Ok(cmds),
        // Surface the daemon's own error (e.g. a capability/permission denial)
        // instead of folding it into a generic "unexpected response".
        Some(astrid_core::kernel_api::KernelResponse::Error(err)) => {
            anyhow::bail!("Daemon error: {err}")
        },
        _ => anyhow::bail!("Daemon returned an unexpected response to GetCommands"),
    }
}

/// Publish the run request and await + render the result.
async fn execute(provider: &str, verb: &str, args: &[String]) -> Result<ExitCode> {
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let source_id = session.0;
    // Bind the connection to the active principal so the capsule verb runs
    // under the invoking identity's context (VFS/KV/secrets), not the
    // `default` (admin) principal a nil/unstamped message falls back to.
    let caller = crate::principal::current();
    let mut client = match SocketClient::connect(session, caller.clone()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}",
                Theme::error(&format!("Failed to connect to daemon: {e}"))
            );
            return Ok(ExitCode::from(1));
        },
    };

    let req_id = Uuid::new_v4().simple().to_string();
    let body = serde_json::json!({
        "req_id": req_id,
        "command": verb,
        "args": args,
    });
    let run_topic = astrid_types::Topic::cli_command_run(provider);
    let result_topic = astrid_types::Topic::cli_command_result(&req_id);

    let msg = astrid_types::ipc::IpcMessage::new(
        run_topic,
        astrid_types::ipc::IpcPayload::RawJson(body),
        source_id,
    )
    .with_principal(caller.to_string());
    if let Err(e) = client.send_message(msg).await {
        eprintln!(
            "{}",
            Theme::error(&format!("Failed to send command to '{provider}': {e}"))
        );
        return Ok(ExitCode::from(1));
    }

    match wait_for_command_result(&mut client, result_topic.as_str(), provider, RESULT_TIMEOUT)
        .await
    {
        Ok(CommandWait::Result(raw)) => Ok(render_result(provider, &raw)),
        Ok(CommandWait::ProviderUnloaded) => {
            eprintln!(
                "{}",
                Theme::error(&format!(
                    "Capsule '{provider}' unloaded before command completed; command cancelled."
                ))
            );
            Ok(ExitCode::from(1))
        },
        Err(_) => {
            eprintln!(
                "{}",
                Theme::error(&format!(
                    "Capsule '{provider}' did not respond within {RESULT_TIMEOUT_SECS}s."
                ))
            );
            Ok(ExitCode::from(1))
        },
    }
}

enum CommandWait {
    Result(serde_json::Value),
    ProviderUnloaded,
}

async fn wait_for_command_result(
    client: &mut SocketClient,
    result_topic: &str,
    provider: &str,
    timeout: Duration,
) -> Result<CommandWait> {
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(tokio::time::Instant::now);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("timed out waiting for capsule command result");
        }

        let read = tokio::time::timeout(remaining, client.read_raw_frame()).await;
        let frame = match read {
            Ok(Ok(Some(bytes))) => bytes,
            Ok(Ok(None)) => anyhow::bail!("daemon connection closed before command result"),
            Ok(Err(err)) => return Err(err),
            Err(_) => anyhow::bail!("timed out waiting for capsule command result"),
        };
        let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&frame) else {
            continue;
        };
        let topic = raw.get("topic").and_then(serde_json::Value::as_str);
        if topic == Some(result_topic) {
            return Ok(CommandWait::Result(raw));
        }
        if topic == Some(CAPSULES_LOADED_TOPIC) && capsules_loaded_missing_provider(&raw, provider)
        {
            return Ok(CommandWait::ProviderUnloaded);
        }
    }
}

fn capsules_loaded_missing_provider(raw: &serde_json::Value, provider: &str) -> bool {
    let Some(capsules) = capsules_loaded_capsules(raw) else {
        return false;
    };
    !capsules.iter().any(|capsule| {
        capsule
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name == provider)
    })
}

fn capsules_loaded_capsules(raw: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    let payload = raw.get("payload")?;
    payload
        .get("capsules")
        .and_then(serde_json::Value::as_array)
        .or_else(|| {
            payload
                .get("value")
                .and_then(|value| value.get("capsules"))
                .and_then(serde_json::Value::as_array)
        })
}

/// Parse and render a `cli.v1.command.result.*` frame.
///
/// Expected body: `{ req_id, exit_code: number, output: string,
/// error?: string }` (delivered unwrapped — `RawJson` serializes the bare
/// inner value). Malformed → error to stderr, exit 1.
fn render_result(provider: &str, raw: &serde_json::Value) -> ExitCode {
    let Some(payload) = raw.get("payload") else {
        eprintln!(
            "{}",
            Theme::error(&format!("Malformed result from '{provider}': no payload"))
        );
        return ExitCode::from(1);
    };
    let Some(exit_code) = payload.get("exit_code").and_then(serde_json::Value::as_i64) else {
        eprintln!(
            "{}",
            Theme::error(&format!(
                "Malformed result from '{provider}': missing/invalid exit_code"
            ))
        );
        return ExitCode::from(1);
    };

    if let Some(output) = payload.get("output").and_then(serde_json::Value::as_str)
        && !output.is_empty()
    {
        use std::io::Write;
        print!("{output}");
        let _ = std::io::stdout().flush();
    }
    if let Some(error) = payload.get("error").and_then(serde_json::Value::as_str)
        && !error.is_empty()
    {
        eprintln!("{error}");
    }

    // Map to the u8 process-exit range, failing secure: a negative or
    // overlong exit code is garbage from the capsule and must surface as
    // failure (1), never clamp down to 0 (success).
    let code = u8::try_from(exit_code).unwrap_or(1);
    ExitCode::from(code)
}

/// Print all available CLI verbs (name + description + provider).
fn print_available(commands: &[CommandInfo]) {
    let verbs: Vec<&CommandInfo> = commands
        .iter()
        .filter(|c| c.kind == CommandKind::Cli)
        .collect();
    if verbs.is_empty() {
        eprintln!("No capsule CLI commands are currently available.");
        return;
    }
    eprintln!("Available capsule commands:");
    for c in verbs {
        eprintln!(
            "  {} — {} (provider: {})",
            c.name, c.description, c.provider_capsule
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(name: &str, provider: &str, kind: CommandKind) -> CommandInfo {
        CommandInfo {
            name: name.to_string(),
            description: format!("{name} desc"),
            provider_capsule: provider.to_string(),
            kind,
        }
    }

    #[test]
    fn match_verb_none_when_no_cli_provider() {
        let cmds = vec![
            cmd("deploy", "ops", CommandKind::Slash),
            cmd("status", "ops", CommandKind::Cli),
        ];
        // `deploy` exists only as a slash command → no CLI match.
        assert_eq!(match_verb("deploy", &cmds), VerbMatch::None);
        // Entirely unknown verb.
        assert_eq!(match_verb("nope", &cmds), VerbMatch::None);
    }

    #[test]
    fn match_verb_one_when_single_cli_provider() {
        let cmds = vec![
            cmd("status", "ops", CommandKind::Cli),
            cmd("other", "misc", CommandKind::Cli),
        ];
        assert_eq!(
            match_verb("status", &cmds),
            VerbMatch::One {
                provider: "ops".to_string(),
                description: "status desc".to_string(),
            }
        );
    }

    #[test]
    fn match_verb_ambiguous_when_multiple_cli_providers() {
        let cmds = vec![
            cmd("deploy", "ops", CommandKind::Cli),
            cmd("deploy", "infra", CommandKind::Cli),
            // A slash command of the same name must not count.
            cmd("deploy", "ui", CommandKind::Slash),
        ];
        assert_eq!(
            match_verb("deploy", &cmds),
            VerbMatch::Ambiguous {
                providers: vec!["ops".to_string(), "infra".to_string()],
            }
        );
    }

    #[test]
    fn render_result_handles_valid_and_out_of_range_exit_codes() {
        // `ExitCode` exposes no inner-value accessor, so these assert the
        // valid and out-of-range paths execute without panicking (rendering
        // output to stdout/stderr) and return a process exit code. Out-of-
        // range codes (negative or > 255) map to failure (1), never to 0 —
        // a capsule sending garbage must not look like success.
        let frame = serde_json::json!({
            "payload": { "req_id": "x", "exit_code": 5, "output": "" }
        });
        let _ = render_result("p", &frame);

        let over = serde_json::json!({
            "payload": { "req_id": "x", "exit_code": 99999, "output": "hi" }
        });
        let _ = render_result("p", &over);

        let negative = serde_json::json!({
            "payload": { "req_id": "x", "exit_code": -1, "output": "" }
        });
        let _ = render_result("p", &negative);
    }

    #[test]
    fn render_result_handles_malformed_payloads() {
        // Missing exit_code and missing payload both take the error-exit
        // path; ensure neither panics.
        let no_code = serde_json::json!({ "payload": { "output": "hi" } });
        let _ = render_result("p", &no_code);

        let no_payload = serde_json::json!({ "topic": "x" });
        let _ = render_result("p", &no_payload);
    }

    #[test]
    fn capsules_loaded_missing_provider_detects_unload() {
        let raw = serde_json::json!({
            "topic": "astrid.v1.capsules_loaded",
            "payload": {
                "status": "ready",
                "capsules": [
                    { "name": "astrid-capsule-session", "meta": null }
                ]
            }
        });
        assert!(capsules_loaded_missing_provider(
            &raw,
            "astrid-capsule-adversarial"
        ));
        assert!(!capsules_loaded_missing_provider(
            &raw,
            "astrid-capsule-session"
        ));
    }

    #[test]
    fn capsules_loaded_missing_provider_accepts_wrapped_raw_json() {
        let raw = serde_json::json!({
            "topic": "astrid.v1.capsules_loaded",
            "payload": {
                "type": "raw_json",
                "value": {
                    "status": "ready",
                    "capsules": []
                }
            }
        });
        assert!(capsules_loaded_missing_provider(&raw, "provider"));
    }

    #[test]
    fn capsules_loaded_missing_provider_ignores_unparseable_payload() {
        let raw = serde_json::json!({
            "topic": "astrid.v1.capsules_loaded",
            "payload": { "status": "ready" }
        });
        assert!(!capsules_loaded_missing_provider(&raw, "provider"));
    }
}
