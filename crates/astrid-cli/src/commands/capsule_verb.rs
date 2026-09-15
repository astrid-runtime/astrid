//! `astrid capsule <verb> [args...]` — dispatch a capsule-contributed CLI
//! verb (`[[command]]` with `kind = "cli"`) to its providing capsule over
//! IPC as a bounded one-shot. Interactive callers may answer an approval on
//! the owning connection; redirected callers deny approval requests.
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

use std::io::{IsTerminal, Write as _};
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
const KERNEL_SOURCE_ID: &str = "00000000-0000-0000-0000-000000000000";
const MAX_GRANT_RETRIES: usize = 1;

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
    let mut client = crate::socket_client::connect_for_workspace(session, caller.clone(), None)
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
    let mut client =
        match crate::socket_client::connect_for_workspace(session, caller.clone(), None).await {
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

    for grant_attempt in 0..=MAX_GRANT_RETRIES {
        let msg = astrid_types::ipc::IpcMessage::new(
            run_topic.clone(),
            astrid_types::ipc::IpcPayload::RawJson(body.clone()),
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

        match wait_for_command_result(
            &mut client,
            result_topic.as_str(),
            provider,
            caller.as_str(),
            source_id,
            RESULT_TIMEOUT,
        )
        .await
        {
            Ok(CommandWait::Result(raw)) => return Ok(render_result(provider, &raw)),
            Ok(CommandWait::GrantApproved) if grant_attempt < MAX_GRANT_RETRIES => {},
            Ok(CommandWait::GrantApproved) => {
                eprintln!(
                    "{}",
                    Theme::error(
                        "Capsule access remained ungranted after approval; refusing to retry again."
                    )
                );
                return Ok(ExitCode::from(1));
            },
            Ok(CommandWait::GrantDenied) => {
                eprintln!("{}", Theme::error("Capsule access was not approved."));
                return Ok(ExitCode::from(1));
            },
            Ok(CommandWait::GrantFailed) => {
                eprintln!(
                    "{}",
                    Theme::error("Capsule access could not be granted; command was not retried.")
                );
                return Ok(ExitCode::from(1));
            },
            Ok(CommandWait::ProviderUnloaded) => {
                eprintln!(
                    "{}",
                    Theme::error(&format!(
                        "Capsule '{provider}' unloaded before command completed; command cancelled."
                    ))
                );
                return Ok(ExitCode::from(1));
            },
            Err(_) => {
                eprintln!(
                    "{}",
                    Theme::error(&format!(
                        "Capsule '{provider}' did not respond within {RESULT_TIMEOUT_SECS}s."
                    ))
                );
                return Ok(ExitCode::from(1));
            },
        }
    }

    unreachable!("bounded grant retry loop always returns")
}

enum CommandWait {
    Result(serde_json::Value),
    GrantApproved,
    GrantDenied,
    GrantFailed,
    ProviderUnloaded,
}

async fn wait_for_command_result(
    client: &mut SocketClient,
    result_topic: &str,
    provider: &str,
    principal: &str,
    source_id: Uuid,
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
        if let Some(prompt) = approval_request_prompt(&raw, principal) {
            if let Some(outcome) = answer_capsule_approval(
                client,
                source_id,
                prompt,
                CommandWaitContext {
                    result_topic,
                    provider,
                    principal,
                    deadline,
                },
            )
            .await?
            {
                return Ok(outcome);
            }
            continue;
        }
        if topic == Some(CAPSULES_LOADED_TOPIC)
            && capsules_loaded_missing_provider(&raw, provider, principal)
        {
            return Ok(CommandWait::ProviderUnloaded);
        }
    }
}

fn approval_request_prompt<'a>(
    raw: &'a serde_json::Value,
    expected_principal: &str,
) -> Option<ApprovalPrompt<'a>> {
    let payload = raw.get("payload")?;
    match payload.get("type")?.as_str()? {
        "approval_required" => Some(ApprovalPrompt {
            request_id: payload.get("request_id")?.as_str()?,
            request_owner: payload
                .get("request_owner")
                .and_then(serde_json::Value::as_str),
            action: payload.get("action")?.as_str()?,
            resource: payload.get("resource")?.as_str()?,
            reason: payload.get("reason")?.as_str()?,
            grant: false,
        }),
        "grant_required" if payload.get("principal")?.as_str()? == expected_principal => {
            Some(ApprovalPrompt {
                request_id: payload.get("request_id")?.as_str()?,
                request_owner: Some(payload.get("request_owner")?.as_str()?),
                action: "grant capsule access",
                resource: payload.get("capsule_id")?.as_str()?,
                reason: "the current principal has not been granted this capsule",
                grant: true,
            })
        },
        _ => None,
    }
}

struct ApprovalPrompt<'a> {
    request_id: &'a str,
    request_owner: Option<&'a str>,
    action: &'a str,
    resource: &'a str,
    reason: &'a str,
    grant: bool,
}

struct CommandWaitContext<'a> {
    result_topic: &'a str,
    provider: &'a str,
    principal: &'a str,
    deadline: tokio::time::Instant,
}

async fn answer_capsule_approval(
    client: &mut SocketClient,
    source_id: Uuid,
    prompt: ApprovalPrompt<'_>,
    wait: CommandWaitContext<'_>,
) -> Result<Option<CommandWait>> {
    let (decision, response_reason) = if std::io::stdin().is_terminal() {
        eprintln!(
            "Approval required: {} on {} ({})",
            prompt.action, prompt.resource, prompt.reason
        );
        eprint!("Approve this operation once? [y/N] ");
        std::io::stderr().flush()?;

        let (answer_tx, mut answer_rx) = tokio::sync::oneshot::channel();
        let _input_thread = std::thread::spawn(move || {
            let mut answer = String::new();
            let answer = std::io::stdin().read_line(&mut answer).map(|_| answer);
            let _ = answer_tx.send(answer);
        });
        let answer = loop {
            let remaining = wait
                .deadline
                .saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("timed out waiting for capsule approval input");
            }
            tokio::select! {
                answer = &mut answer_rx => {
                    break answer
                        .map_err(|_| anyhow::anyhow!("approval input channel closed"))??;
                }
                read = client.read_raw_frame() => {
                    let Some(frame) = read? else {
                        anyhow::bail!("daemon connection closed while awaiting approval input");
                    };
                    let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&frame) else {
                        continue;
                    };
                    let topic = raw.get("topic").and_then(serde_json::Value::as_str);
                    if topic == Some(wait.result_topic) {
                        return Ok(Some(CommandWait::Result(raw)));
                    }
                    if topic == Some(CAPSULES_LOADED_TOPIC)
                        && capsules_loaded_missing_provider(&raw, wait.provider, wait.principal)
                    {
                        return Ok(Some(CommandWait::ProviderUnloaded));
                    }
                }
                () = tokio::time::sleep(remaining) => {
                    anyhow::bail!("timed out waiting for capsule approval input");
                }
            }
        };
        if is_affirmative(&answer) {
            (
                "approve",
                Some("approved by capsule command operator".to_owned()),
            )
        } else {
            (
                "deny",
                Some("denied by capsule command operator".to_owned()),
            )
        }
    } else {
        (
            "deny",
            Some("capsule command has no interactive approval terminal".to_owned()),
        )
    };
    client
        .send_message(astrid_types::ipc::IpcMessage::new(
            astrid_types::Topic::approval_response(prompt.request_id),
            astrid_types::ipc::IpcPayload::ApprovalResponse {
                request_id: prompt.request_id.to_owned(),
                decision: decision.to_owned(),
                reason: response_reason,
            },
            source_id,
        ))
        .await?;
    if prompt.grant {
        if decision != "approve" {
            return Ok(Some(CommandWait::GrantDenied));
        }
        await_grant_result(client, &prompt, &wait).await.map(Some)
    } else {
        Ok(None)
    }
}

async fn await_grant_result(
    client: &mut SocketClient,
    prompt: &ApprovalPrompt<'_>,
    wait: &CommandWaitContext<'_>,
) -> Result<CommandWait> {
    loop {
        let remaining = wait
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("timed out waiting for capsule grant result");
        }
        let frame = match tokio::time::timeout(remaining, client.read_raw_frame()).await {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => anyhow::bail!("daemon connection closed before grant completed"),
            Ok(Err(error)) => return Err(error),
            Err(_) => anyhow::bail!("timed out waiting for capsule grant result"),
        };
        let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&frame) else {
            continue;
        };
        if raw.get("topic").and_then(serde_json::Value::as_str) == Some(wait.result_topic) {
            return Ok(CommandWait::Result(raw));
        }
        if let Some(granted) = grant_result_matches(&raw, prompt, wait.principal) {
            return Ok(if granted {
                CommandWait::GrantApproved
            } else {
                CommandWait::GrantFailed
            });
        }
        if raw.get("topic").and_then(serde_json::Value::as_str) == Some(CAPSULES_LOADED_TOPIC)
            && capsules_loaded_missing_provider(&raw, wait.provider, wait.principal)
        {
            return Ok(CommandWait::ProviderUnloaded);
        }
    }
}

fn grant_result_matches(
    raw: &serde_json::Value,
    prompt: &ApprovalPrompt<'_>,
    principal: &str,
) -> Option<bool> {
    let owner = prompt.request_owner?;
    if raw.get("topic")?.as_str()? != astrid_types::Topic::grant_result(prompt.request_id).as_str()
        || raw.get("source_id")?.as_str()? != KERNEL_SOURCE_ID
        || raw.get("principal")?.as_str()? != principal
        || raw.get("request_owner")?.as_str()? != owner
    {
        return None;
    }
    let payload = raw.get("payload")?;
    (payload.get("type")?.as_str()? == "grant_result"
        && payload.get("request_id")?.as_str()? == prompt.request_id
        && payload.get("request_owner")?.as_str()? == owner
        && payload.get("principal")?.as_str()? == principal
        && payload.get("capsule_id")?.as_str()? == prompt.resource)
        .then(|| payload.get("granted")?.as_bool())
        .flatten()
}

fn is_affirmative(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn capsules_loaded_missing_provider(
    raw: &serde_json::Value,
    provider: &str,
    principal: &str,
) -> bool {
    if raw_frame_principal(raw).is_some_and(|frame_principal| frame_principal != principal) {
        return false;
    }
    let Some(capsules) = capsules_loaded_capsules(raw) else {
        return false;
    };
    let principal_aware = capsules
        .iter()
        .any(|capsule| capsule_entry_principal(capsule).is_some());
    !capsules
        .iter()
        .filter(|capsule| !principal_aware || capsule_entry_matches_principal(capsule, principal))
        .any(|capsule| capsule_entry_name(capsule).is_some_and(|name| name == provider))
}

fn raw_frame_principal(raw: &serde_json::Value) -> Option<&str> {
    raw.get("principal").and_then(serde_json::Value::as_str)
}

fn capsule_entry_principal(capsule: &serde_json::Value) -> Option<&str> {
    capsule.get("principal").and_then(serde_json::Value::as_str)
}

fn capsule_entry_name(capsule: &serde_json::Value) -> Option<&str> {
    capsule.get("name").and_then(serde_json::Value::as_str)
}

fn capsule_entry_matches_principal(capsule: &serde_json::Value, principal: &str) -> bool {
    capsule_entry_principal(capsule).is_some_and(|entry_principal| entry_principal == principal)
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
            "astrid-capsule-adversarial",
            "alice"
        ));
        assert!(!capsules_loaded_missing_provider(
            &raw,
            "astrid-capsule-session",
            "alice"
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
        assert!(capsules_loaded_missing_provider(&raw, "provider", "alice"));
    }

    #[test]
    fn capsules_loaded_missing_provider_ignores_unparseable_payload() {
        let raw = serde_json::json!({
            "topic": "astrid.v1.capsules_loaded",
            "payload": { "status": "ready" }
        });
        assert!(!capsules_loaded_missing_provider(&raw, "provider", "alice"));
    }

    #[test]
    fn capsules_loaded_missing_provider_filters_by_principal() {
        let raw = serde_json::json!({
            "topic": "astrid.v1.capsules_loaded",
            "payload": {
                "status": "ready",
                "capsules": [
                    {
                        "principal": "bob",
                        "name": "astrid-capsule-adversarial",
                        "meta": null
                    }
                ]
            }
        });

        assert!(
            capsules_loaded_missing_provider(&raw, "astrid-capsule-adversarial", "alice"),
            "alice's command should cancel when only bob still has the provider loaded"
        );
        assert!(
            !capsules_loaded_missing_provider(&raw, "astrid-capsule-adversarial", "bob"),
            "bob's command should not cancel while bob's provider remains loaded"
        );
    }

    #[test]
    fn capsules_loaded_missing_provider_ignores_other_frame_principal() {
        let raw = serde_json::json!({
            "topic": "astrid.v1.capsules_loaded",
            "principal": "bob",
            "payload": {
                "status": "ready",
                "capsules": []
            }
        });

        assert!(
            !capsules_loaded_missing_provider(&raw, "astrid-capsule-adversarial", "alice"),
            "alice must not cancel on another principal's capsules_loaded frame"
        );
    }

    #[test]
    fn capsules_loaded_missing_provider_detects_current_principal_entry() {
        let raw = serde_json::json!({
            "topic": "astrid.v1.capsules_loaded",
            "principal": "alice",
            "payload": {
                "status": "ready",
                "capsules": [
                    {
                        "principal": "alice",
                        "name": "astrid-capsule-adversarial",
                        "meta": null
                    },
                    {
                        "principal": "bob",
                        "name": "astrid-capsule-session",
                        "meta": null
                    }
                ]
            }
        });

        assert!(!capsules_loaded_missing_provider(
            &raw,
            "astrid-capsule-adversarial",
            "alice"
        ));
    }

    #[test]
    fn approval_request_prompt_accepts_complete_approval_and_grant_prompts() {
        let raw = serde_json::json!({
            "payload": {
                "type": "approval_required",
                "request_id": "request-1",
                "action": "run",
                "resource": "command",
                "reason": "operator consent"
            }
        });
        let prompt = approval_request_prompt(&raw, "alice").expect("approval prompt");
        assert_eq!(prompt.request_id, "request-1");
        assert_eq!(prompt.action, "run");
        assert_eq!(prompt.resource, "command");
        assert_eq!(prompt.reason, "operator consent");
        assert!(!prompt.grant);

        let grant = serde_json::json!({
            "payload": {
                "type": "grant_required",
                "request_id": "grant-1",
                "request_owner": "owner-1",
                "principal": "alice",
                "capsule_id": "capsule-tools"
            }
        });
        let prompt = approval_request_prompt(&grant, "alice").expect("grant prompt");
        assert_eq!(prompt.request_id, "grant-1");
        assert_eq!(prompt.request_owner, Some("owner-1"));
        assert_eq!(prompt.action, "grant capsule access");
        assert_eq!(prompt.resource, "capsule-tools");
        assert!(prompt.grant);
        assert!(approval_request_prompt(&grant, "bob").is_none());

        let incomplete = serde_json::json!({
            "payload": { "type": "approval_required", "request_id": "request-1" }
        });
        assert!(approval_request_prompt(&incomplete, "alice").is_none());
    }

    #[test]
    fn grant_result_requires_exact_kernel_correlation() {
        let prompt = ApprovalPrompt {
            request_id: "grant-1",
            request_owner: Some("owner-1"),
            action: "grant capsule access",
            resource: "capsule-tools",
            reason: "test",
            grant: true,
        };
        let result = serde_json::json!({
            "topic": "astrid.v1.grant.result.grant-1",
            "source_id": KERNEL_SOURCE_ID,
            "principal": "alice",
            "request_owner": "owner-1",
            "payload": {
                "type": "grant_result",
                "request_id": "grant-1",
                "request_owner": "owner-1",
                "principal": "alice",
                "capsule_id": "capsule-tools",
                "granted": true
            }
        });
        assert_eq!(grant_result_matches(&result, &prompt, "alice"), Some(true));

        let mut forged = result.clone();
        forged["source_id"] = serde_json::Value::String(Uuid::new_v4().to_string());
        assert_eq!(grant_result_matches(&forged, &prompt, "alice"), None);

        let mut wrong_owner = result;
        wrong_owner["request_owner"] = serde_json::Value::String("owner-2".to_owned());
        assert_eq!(grant_result_matches(&wrong_owner, &prompt, "alice"), None);
    }

    #[test]
    fn capsule_approval_accepts_only_explicit_yes() {
        assert!(is_affirmative("y"));
        assert!(is_affirmative(" YES \n"));
        assert!(!is_affirmative(""));
        assert!(!is_affirmative("approve"));
        assert!(!is_affirmative("no"));
    }
}
