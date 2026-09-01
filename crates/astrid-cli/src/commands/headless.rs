//! Headless and snapshot-TUI modes for non-interactive use.

use std::io::IsTerminal;

use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result};
use thiserror::Error;

use super::daemon;
use crate::{formatter, socket_client, tui};

/// The established headless timeout exit code.
pub(crate) const TIMEOUT_EXIT_CODE: u8 = 53;
const SUCCESS_EXIT_CODE: u8 = 0;
/// A hard ceiling that permits long cold starts but rejects unbounded waits.
pub(crate) const MAX_RUN_IDLE_TIMEOUT_SECS: u64 = 86_400;

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
    /// Read the next daemon message.
    fn read_message(
        &mut self,
    ) -> impl Future<Output = Result<Option<astrid_types::ipc::IpcMessage>>> + Send;

    /// Send a message to the daemon.
    fn send_message(
        &mut self,
        message: astrid_types::ipc::IpcMessage,
    ) -> impl Future<Output = Result<()>> + Send;
}

impl ResponseSource for socket_client::SocketClient {
    fn read_message(
        &mut self,
    ) -> impl Future<Output = Result<Option<astrid_types::ipc::IpcMessage>>> + Send {
        socket_client::SocketClient::read_message(self)
    }

    fn send_message(
        &mut self,
        message: astrid_types::ipc::IpcMessage,
    ) -> impl Future<Output = Result<()>> + Send {
        socket_client::SocketClient::send_message(self, message)
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
    auto_approve: bool,
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
        auto_approve,
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
    auto_approve: bool,
    session_name: Option<String>,
    print_session: bool,
) -> Result<()> {
    // Legacy bare-prompt callers retain the historical process boundary.
    let code = run_headless_with_timeout(
        prompt,
        format,
        auto_approve,
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
    auto_approve: bool,
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
        collect_response_with_cleanup(&mut client, &session_id, format, auto_approve, idle_timeout)
            .await;
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

async fn send_disconnect(client: &mut impl ResponseSource, session_id: &astrid_core::SessionId) {
    let disconnect = astrid_types::ipc::IpcMessage::new(
        astrid_types::Topic::client_disconnect(),
        astrid_types::ipc::IpcPayload::Disconnect {
            reason: Some("headless".to_string()),
        },
        session_id.0,
    );
    let _ = client.send_message(disconnect).await;
}

/// Ensure an idle timeout performs cleanup before its typed error propagates.
async fn collect_response_with_cleanup(
    client: &mut impl ResponseSource,
    session_id: &astrid_core::SessionId,
    format: formatter::OutputFormat,
    auto_approve: bool,
    idle_timeout: Duration,
) -> std::result::Result<(String, Vec<serde_json::Value>), HeadlessError> {
    let collected = collect_response(client, session_id, format, auto_approve, idle_timeout).await;
    if let Err(HeadlessError::IdleTimeout { .. }) = &collected {
        send_disconnect(client, session_id).await;
    }
    collected
}

/// Collect the streaming response from the daemon in headless mode.
///
/// Returns `(response_text, tool_calls)`. Auto-denies any approval requests.
/// The deadline applies only to gaps between active-run messages.
async fn collect_response(
    client: &mut impl ResponseSource,
    session_id: &astrid_core::SessionId,
    format: formatter::OutputFormat,
    auto_approve: bool,
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
        let message = match tokio::time::timeout(remaining, client.read_message()).await {
            Ok(Ok(Some(msg))) => msg,
            Ok(Ok(None)) => break,
            Ok(Err(e)) => {
                return Err(HeadlessError::Read(e.context("Failed to read from daemon")));
            },
            Err(_) => return Err(HeadlessError::IdleTimeout { timeout_secs }),
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
            astrid_types::ipc::IpcPayload::ApprovalRequired {
                request_id, action, ..
            } => {
                let decision = if auto_approve { "approve" } else { "deny" };
                eprintln!(
                    "[headless] Auto-{} approval for: {action}",
                    if auto_approve { "approved" } else { "denied" }
                );
                let response = astrid_types::ipc::IpcPayload::ApprovalResponse {
                    request_id: request_id.clone(),
                    decision: decision.to_string(),
                    reason: Some(
                        if auto_approve {
                            "headless --yes mode"
                        } else {
                            "headless mode"
                        }
                        .to_string(),
                    ),
                };
                let topic = astrid_types::Topic::approval_response(request_id);
                let msg = astrid_types::ipc::IpcMessage::new(topic, response, session_id.0);
                client.send_message(msg).await?;
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
    match &message.payload {
        astrid_types::ipc::IpcPayload::AgentResponse {
            session_id: target, ..
        } => target == &session_id.0.to_string(),
        astrid_types::ipc::IpcPayload::LlmStreamEvent { .. }
        | astrid_types::ipc::IpcPayload::ToolExecuteResult { .. }
        | astrid_types::ipc::IpcPayload::ApprovalRequired { .. } => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::pending;

    use astrid_core::SessionId;
    use astrid_types::Topic;
    use astrid_types::ipc::{IpcMessage, IpcPayload};
    use uuid::Uuid;

    use super::*;

    struct QueuedSource(VecDeque<Result<Option<IpcMessage>>>);

    impl ResponseSource for QueuedSource {
        async fn read_message(&mut self) -> Result<Option<IpcMessage>> {
            match self.0.pop_front() {
                Some(next) => next,
                None => pending().await,
            }
        }

        async fn send_message(&mut self, _message: IpcMessage) -> Result<()> {
            Ok(())
        }
    }

    fn response(text: &str, is_final: bool, session_id: &SessionId) -> IpcMessage {
        IpcMessage::new(
            Topic::agent_response(),
            IpcPayload::AgentResponse {
                text: text.to_owned(),
                is_final,
                session_id: session_id.0.to_string(),
            },
            session_id.0,
        )
    }

    struct DelayedResponses {
        delay: Duration,
        remaining: u8,
        session_id: SessionId,
    }

    impl ResponseSource for DelayedResponses {
        async fn read_message(&mut self) -> Result<Option<IpcMessage>> {
            if self.remaining > 0 {
                self.remaining = self.remaining.saturating_sub(1);
                let delay = self.delay;
                let session_id = self.session_id.clone();
                tokio::time::sleep(delay).await;
                Ok(Some(response("keepalive", false, &session_id)))
            } else {
                let session_id = self.session_id.clone();
                Ok(Some(response("done", true, &session_id)))
            }
        }

        async fn send_message(&mut self, _message: IpcMessage) -> Result<()> {
            Ok(())
        }
    }

    struct ForeignThenLate {
        delay: Duration,
        session_id: SessionId,
        sent_foreign: bool,
    }

    struct SilentSource {
        sent_disconnect: bool,
    }

    impl ResponseSource for SilentSource {
        async fn read_message(&mut self) -> Result<Option<IpcMessage>> {
            pending().await
        }

        async fn send_message(&mut self, message: IpcMessage) -> Result<()> {
            self.sent_disconnect = matches!(message.payload, IpcPayload::Disconnect { .. });
            Ok(())
        }
    }

    impl ResponseSource for ForeignThenLate {
        async fn read_message(&mut self) -> Result<Option<IpcMessage>> {
            if self.sent_foreign {
                let delay = self.delay;
                let session_id = self.session_id.clone();
                tokio::time::sleep(delay).await;
                Ok(Some(response("late", true, &session_id)))
            } else {
                self.sent_foreign = true;
                let message = foreign_message(&self.session_id);
                Ok(Some(message))
            }
        }

        async fn send_message(&mut self, _message: IpcMessage) -> Result<()> {
            Ok(())
        }
    }

    fn foreign_message(session_id: &SessionId) -> IpcMessage {
        IpcMessage::new(
            Topic::from_raw("registry.v1.active_model_changed"),
            IpcPayload::RawJson(serde_json::json!({"model": "other"})),
            session_id.0,
        )
    }

    #[test]
    fn idle_timeout_preserves_default_and_fails_closed() {
        assert!(matches!(idle_timeout(120), Ok(timeout) if timeout == Duration::from_mins(2)));
        assert!(idle_timeout(0).is_err());
        assert!(idle_timeout(u64::MAX).is_err());
        assert!(idle_timeout(86_401).is_err());
    }

    #[tokio::test]
    async fn delayed_active_run_message_resets_the_idle_deadline() {
        let session_id = SessionId::from_uuid(Uuid::new_v4());
        let mut source = DelayedResponses {
            delay: Duration::from_millis(5),
            remaining: 2,
            session_id: session_id.clone(),
        };
        let (text, _) = collect_response(
            &mut source,
            &session_id,
            formatter::OutputFormat::Json,
            false,
            Duration::from_millis(7),
        )
        .await
        .unwrap();

        assert_eq!(text, "keepalivekeepalivedone");
    }

    #[tokio::test]
    async fn missing_active_run_message_returns_timeout_without_process_exit() {
        let session_id = SessionId::from_uuid(Uuid::new_v4());
        let mut source = QueuedSource(VecDeque::new());
        let error = collect_response(
            &mut source,
            &session_id,
            formatter::OutputFormat::Json,
            false,
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
    }

    #[tokio::test]
    async fn foreign_message_does_not_reset_a_short_idle_deadline() {
        let session_id = SessionId::from_uuid(Uuid::new_v4());
        let mut source = ForeignThenLate {
            delay: Duration::from_millis(10),
            session_id: session_id.clone(),
            sent_foreign: false,
        };
        let error = collect_response(
            &mut source,
            &session_id,
            formatter::OutputFormat::Json,
            false,
            Duration::from_millis(7),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
    }

    #[tokio::test]
    async fn timeout_sends_disconnect_before_returning_the_typed_error() {
        let session_id = SessionId::from_uuid(Uuid::new_v4());
        let mut source = SilentSource {
            sent_disconnect: false,
        };
        let error = collect_response_with_cleanup(
            &mut source,
            &session_id,
            formatter::OutputFormat::Json,
            false,
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
        assert!(source.sent_disconnect);
    }

    #[test]
    fn only_active_run_payloads_can_reset_the_timer() {
        let session_id = SessionId::from_uuid(Uuid::new_v4());
        assert!(is_active_run_message(
            &response("active", false, &session_id),
            &session_id
        ));
        assert!(!is_active_run_message(
            &foreign_message(&session_id),
            &session_id
        ));
    }
}
