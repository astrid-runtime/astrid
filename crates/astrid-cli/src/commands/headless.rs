//! Headless and snapshot-TUI modes for non-interactive use.

use std::io::IsTerminal;

use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result};
use thiserror::Error;

use astrid_config::MAX_RUN_IDLE_TIMEOUT_SECS;

use super::daemon;
use crate::{formatter, socket_client, tui};

/// The established headless timeout exit code.
pub(crate) const TIMEOUT_EXIT_CODE: u8 = 53;
pub(crate) const AUTO_APPROVE_UNSUPPORTED_MESSAGE: &str = "headless approval automation is unsupported: approvals cannot be \
     correlated to this run; remove --yes, --yolo, or --autonomous";
const SUCCESS_EXIT_CODE: u8 = 0;
/// Best-effort budget for sends during collection cleanup and normal exit.
const MESSAGE_SEND_BUDGET: Duration = Duration::from_secs(5);

/// Why response collection stopped without a terminal response.
#[derive(Debug, Error)]
pub(crate) enum HeadlessError {
    /// No active-run message arrived within the configured idle budget.
    #[error("timed out waiting for response after {timeout_secs}s idle")]
    IdleTimeout {
        /// The configured idle budget in whole seconds.
        timeout_secs: u64,
    },
    /// The daemon connection failed while collecting the response.
    #[error(transparent)]
    Read(#[from] anyhow::Error),
}

/// Validate and convert a whole-second run idle timeout.
///
/// # Errors
/// Returns an error for zero or values above the one-day operational ceiling.
pub(crate) fn idle_timeout(timeout_secs: u64) -> Result<Duration> {
    if timeout_secs == 0 {
        anyhow::bail!("idle timeout must be greater than 0 seconds");
    }
    if timeout_secs > MAX_RUN_IDLE_TIMEOUT_SECS {
        anyhow::bail!("idle timeout must be at most {MAX_RUN_IDLE_TIMEOUT_SECS} seconds");
    }
    Ok(Duration::from_secs(timeout_secs))
}

/// Source of daemon messages consumed by headless response collection.
pub(crate) trait ResponseSource {
    /// Read the next daemon message or report timeout at the source boundary.
    fn read_message_before(
        &mut self,
        remaining: Duration,
    ) -> impl Future<Output = ReadOutcome> + Send;

    /// Send a message to the daemon.
    fn send_message(
        &mut self,
        message: astrid_types::ipc::IpcMessage,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// A deterministic read outcome used to apply the idle deadline at the source.
pub(crate) enum ReadOutcome {
    Message(Box<astrid_types::ipc::IpcMessage>),
    Closed,
    Timeout,
    Error(anyhow::Error),
}

impl ResponseSource for socket_client::SocketClient {
    async fn read_message_before(&mut self, remaining: Duration) -> ReadOutcome {
        match tokio::time::timeout(remaining, self.read_message()).await {
            Ok(Ok(Some(message))) => ReadOutcome::Message(Box::new(message)),
            Ok(Ok(None)) => ReadOutcome::Closed,
            Ok(Err(error)) => ReadOutcome::Error(error),
            Err(_) => ReadOutcome::Timeout,
        }
    }

    async fn send_message(&mut self, message: astrid_types::ipc::IpcMessage) -> Result<()> {
        socket_client::SocketClient::send_message(self, message).await
    }
}

/// Resolve the `--session` flag value into a [`uuid::Uuid`].
///
/// Auto-detects: a string that parses as a UUID is returned as-is
/// (so an operator can copy a printed session id back into the
/// next `-p` invocation and resume the exact same session). Anything
/// else is treated as a stable session name and hashed via UUID v5
/// (`NAMESPACE_URL`) so the same name always maps to the same
/// session across invocations. Matches the `cargo` / `gh` /
/// `claude` convention of accepting either form for the same flag.
/// Returns the resolved [`Uuid`] and whether the input parsed as a UUID
/// directly (`true`) or was hashed from a name (`false`). Callers
/// that need to differentiate the two cases — e.g. `--print-session`
/// — would otherwise re-run `Uuid::parse_str` on the same input to
/// recover that bit.
fn resolve_session_arg(s: &str) -> (uuid::Uuid, bool) {
    if let Ok(uuid) = uuid::Uuid::parse_str(s) {
        return (uuid, true);
    }
    let ns = uuid::Uuid::NAMESPACE_URL;
    (uuid::Uuid::new_v5(&ns, s.as_bytes()), false)
}

/// Snapshot TUI mode: render the TUI to stdout as text frames.
///
/// Uses the same daemon connection as headless mode, but renders through
/// ratatui's `TestBackend` and dumps each significant event as a text frame.
pub(crate) async fn run_snapshot_tui(
    prompt: String,
    session_name: Option<String>,
    width: u16,
    height: u16,
) -> Result<()> {
    use astrid_core::SessionId;

    daemon::ensure_daemon("snapshot-tui").await?;

    let session_id = if let Some(s) = session_name.as_deref() {
        SessionId::from_uuid(resolve_session_arg(s).0)
    } else {
        SessionId::from_uuid(uuid::Uuid::new_v4())
    };

    let mut client =
        socket_client::connect_for_workspace(session_id.clone(), crate::principal::current(), None)
            .await
            .context("Failed to connect to daemon")?;

    let workspace = std::env::current_dir().ok();
    tui::headless::run(tui::headless::HeadlessConfig {
        client: &mut client,
        session_id: &session_id,
        workspace,
        model_name: "",
        prompt: &prompt,
        width,
        height,
    })
    .await
}

/// Headless mode: send a single prompt, stream the response to stdout, exit.
///
/// Connects to the daemon (spawning if needed), sends the prompt as a
/// `UserInput` IPC message, and reads response events until the final
/// `AgentResponse` with `is_final = true`.
///
/// Output format:
/// - `Pretty`: prints the raw response text to stdout.
/// - `Json`: prints a JSON object with `response` and tool call details.
pub(crate) async fn run_headless(
    prompt: String,
    format: formatter::OutputFormat,
    session_name: Option<String>,
    print_session: bool,
) -> Result<()> {
    // Legacy bare-prompt callers retain the historical process boundary.
    let code = run_headless_with_timeout(
        prompt,
        format,
        session_name,
        print_session,
        Duration::from_mins(2),
    )
    .await?;
    if code != SUCCESS_EXIT_CODE {
        std::process::exit(code.into());
    }
    Ok(())
}

pub(crate) async fn run_headless_with_timeout(
    prompt: String,
    format: formatter::OutputFormat,
    session_name: Option<String>,
    print_session: bool,
    idle_timeout: Duration,
) -> Result<u8> {
    use astrid_core::SessionId;

    daemon::ensure_daemon("headless").await?;

    // `--session` accepts either a raw UUID (re-used as-is for resuming
    // the exact session `--print-session` reported on a prior turn) or
    // any other string (used as a stable name and hashed into a
    // deterministic UUID v5 so the same name always maps to the same
    // session). UUID-first means an operator can copy a printed
    // session id straight into the next invocation without it being
    // re-hashed; `cargo`/`gh`/`claude` use the same convention.
    let session_id = if let Some(s) = session_name.as_deref() {
        let (id, was_uuid) = resolve_session_arg(s);
        if print_session {
            if was_uuid {
                eprintln!("[headless] Session: {id}");
            } else {
                eprintln!("[headless] Session: {s} ({id})");
            }
        }
        SessionId::from_uuid(id)
    } else {
        let id = uuid::Uuid::new_v4();
        if print_session {
            eprintln!("[headless] Session: {id}");
        }
        SessionId::from_uuid(id)
    };
    let mut client =
        socket_client::connect_for_workspace(session_id.clone(), crate::principal::current(), None)
            .await
            .context("Failed to connect to daemon")?;

    // Also read stdin if there's piped content and -p was used
    let full_prompt = if std::io::stdin().is_terminal() {
        prompt
    } else {
        let mut stdin_text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut stdin_text)?;
        if stdin_text.is_empty() {
            prompt
        } else {
            format!("{stdin_text}\n\n{prompt}")
        }
    };

    // Send the prompt and collect the streaming response
    crate::socket_client::send_input_as_active_agent(&mut client, full_prompt).await?;
    let collected =
        collect_response_with_cleanup(&mut client, &session_id, format, idle_timeout).await;
    let (response_text, tool_calls) = match collected {
        Ok(collected) => collected,
        Err(HeadlessError::IdleTimeout { timeout_secs }) => {
            eprintln!("[headless] Timed out waiting for response after {timeout_secs}s idle");
            return Ok(TIMEOUT_EXIT_CODE);
        },
        Err(HeadlessError::Read(error)) => return Err(error),
    };

    // Final output
    match format {
        formatter::OutputFormat::Pretty => {
            if !response_text.ends_with('\n') {
                println!();
            }
        },
        formatter::OutputFormat::Json => {
            let output = serde_json::json!({
                "response": response_text,
                "tool_calls": tool_calls,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
    }

    send_disconnect(&mut client, &session_id).await;

    Ok(SUCCESS_EXIT_CODE)
}

async fn send_message_bounded(
    client: &mut impl ResponseSource,
    message: astrid_types::ipc::IpcMessage,
    budget: Duration,
) {
    let _ = tokio::time::timeout(budget, client.send_message(message)).await;
}

async fn send_disconnect(client: &mut impl ResponseSource, session_id: &astrid_core::SessionId) {
    send_disconnect_with_budget(client, session_id, MESSAGE_SEND_BUDGET).await;
}

async fn send_disconnect_with_budget(
    client: &mut impl ResponseSource,
    session_id: &astrid_core::SessionId,
    budget: Duration,
) {
    let disconnect = astrid_types::ipc::IpcMessage::new(
        astrid_types::Topic::client_disconnect(),
        astrid_types::ipc::IpcPayload::Disconnect {
            reason: Some("headless".to_string()),
        },
        session_id.0,
    );
    send_message_bounded(client, disconnect, budget).await;
}

/// Ensure an idle timeout performs cleanup before its typed error propagates.
async fn collect_response_with_cleanup(
    client: &mut impl ResponseSource,
    session_id: &astrid_core::SessionId,
    format: formatter::OutputFormat,
    idle_timeout: Duration,
) -> std::result::Result<(String, Vec<serde_json::Value>), HeadlessError> {
    collect_response_with_cleanup_budget(
        client,
        session_id,
        format,
        idle_timeout,
        MESSAGE_SEND_BUDGET,
    )
    .await
}

async fn collect_response_with_cleanup_budget(
    client: &mut impl ResponseSource,
    session_id: &astrid_core::SessionId,
    format: formatter::OutputFormat,
    idle_timeout: Duration,
    send_budget: Duration,
) -> std::result::Result<(String, Vec<serde_json::Value>), HeadlessError> {
    let collected = collect_response(client, session_id, format, idle_timeout).await;
    if let Err(HeadlessError::IdleTimeout { .. }) = &collected {
        send_disconnect_with_budget(client, session_id, send_budget).await;
    }
    collected
}

/// Collect the streaming response from the daemon in headless mode.
///
/// Returns `(response_text, tool_calls)`. Approval requests are unsupported
/// because production cannot prove they belong to this run; they are ignored
/// without a response and do not reset the idle deadline.
async fn collect_response(
    client: &mut impl ResponseSource,
    session_id: &astrid_core::SessionId,
    format: formatter::OutputFormat,
    idle_timeout: Duration,
) -> std::result::Result<(String, Vec<serde_json::Value>), HeadlessError> {
    let mut response_text = String::new();
    let mut tool_calls: Vec<serde_json::Value> = Vec::new();
    let timeout_secs = idle_timeout.as_secs();
    let now = tokio::time::Instant::now();
    let mut deadline = now.checked_add(idle_timeout).unwrap_or(now);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(HeadlessError::IdleTimeout { timeout_secs });
        }
        let message = match client.read_message_before(remaining).await {
            ReadOutcome::Message(message) => message,
            ReadOutcome::Closed => break,
            ReadOutcome::Error(error) => {
                return Err(HeadlessError::Read(
                    error.context("Failed to read from daemon"),
                ));
            },
            ReadOutcome::Timeout => return Err(HeadlessError::IdleTimeout { timeout_secs }),
        };

        if !is_active_run_message(&message, session_id) {
            continue;
        }
        deadline = tokio::time::Instant::now()
            .checked_add(idle_timeout)
            .unwrap_or_else(tokio::time::Instant::now);

        match &message.payload {
            astrid_types::ipc::IpcPayload::AgentResponse { text, is_final, .. } => {
                if format == formatter::OutputFormat::Pretty {
                    print!("{text}");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                response_text.push_str(text);
                if *is_final {
                    break;
                }
            },
            astrid_types::ipc::IpcPayload::RawJson(value)
                if message.topic.as_str() == astrid_types::Topic::agent_response().as_str() =>
            {
                let text = raw_json_response_text(value).unwrap_or_default();
                if format == formatter::OutputFormat::Pretty {
                    print!("{text}");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                response_text.push_str(text);
                if raw_json_response_is_final(value) {
                    break;
                }
            },
            astrid_types::ipc::IpcPayload::LlmStreamEvent {
                event: astrid_types::llm::StreamEvent::ToolCallStart { id, name },
                ..
            } => {
                tool_calls.push(serde_json::json!({
                    "type": "tool_call",
                    "id": id,
                    "name": name,
                }));
            },
            astrid_types::ipc::IpcPayload::ToolExecuteResult { call_id, result } => {
                tool_calls.push(serde_json::json!({
                    "type": "tool_result",
                    "call_id": call_id,
                    "content": result.content,
                    "is_error": result.is_error,
                }));
            },
            _ => {},
        }
    }

    Ok((response_text, tool_calls))
}

/// A nonterminal control frame must not extend the run's idle budget.
fn is_active_run_message(
    message: &astrid_types::ipc::IpcMessage,
    session_id: &astrid_core::SessionId,
) -> bool {
    // Approval requests are never active-run traffic. No run correlation is
    // currently authenticated, so answering or resetting on one would cross a
    // security boundary.
    if matches!(
        &message.payload,
        astrid_types::ipc::IpcPayload::ApprovalRequired { .. }
    ) {
        return false;
    }

    match &message.payload {
        astrid_types::ipc::IpcPayload::AgentResponse {
            session_id: target, ..
        } => {
            message.topic.as_str() == astrid_types::Topic::agent_response().as_str()
                && target == &session_id.0.to_string()
        },
        astrid_types::ipc::IpcPayload::RawJson(value) => {
            if !raw_json_session_matches(value, session_id) {
                return false;
            }
            let topic = message.topic.as_str();
            topic == astrid_types::Topic::agent_stream_delta().as_str()
                || (topic == astrid_types::Topic::agent_response().as_str()
                    && raw_json_response_is_final(value))
        },
        astrid_types::ipc::IpcPayload::LlmStreamEvent { .. }
        | astrid_types::ipc::IpcPayload::ToolExecuteResult { .. } => {
            message.source_id == session_id.0
        },
        _ => false,
    }
}

/// Cross-runtime producers may send the native chat wire shape instead of a
/// typed `AgentResponse`; the raw fields mirror the typed response fields.
fn raw_json_session_matches(
    value: &serde_json::Value,
    session_id: &astrid_core::SessionId,
) -> bool {
    value.get("session_id").and_then(serde_json::Value::as_str)
        == Some(session_id.0.to_string().as_str())
}

fn raw_json_response_text(value: &serde_json::Value) -> Option<&str> {
    value.get("text").and_then(serde_json::Value::as_str)
}

fn raw_json_response_is_final(value: &serde_json::Value) -> bool {
    value
        .get("is_final")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
#[path = "headless_tests.rs"]
mod tests;
