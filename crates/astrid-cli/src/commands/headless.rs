//! Headless and snapshot-TUI modes for non-interactive use.

use std::io::IsTerminal;

use anyhow::{Context, Result};

use super::daemon;
use crate::{formatter, socket_client, tui};

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

    let mut client = socket_client::SocketClient::connect(session_id.clone())
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
    let mut client = socket_client::SocketClient::connect(session_id.clone())
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
    let (response_text, tool_calls) =
        collect_response(&mut client, &session_id, format, auto_approve).await?;

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

    // Send disconnect
    let disconnect = astrid_types::ipc::IpcMessage::new(
        "client.v1.disconnect",
        astrid_types::ipc::IpcPayload::Disconnect {
            reason: Some("headless".to_string()),
        },
        session_id.0,
    );
    let _ = client.send_message(disconnect).await;

    Ok(())
}

/// Collect the streaming response from the daemon in headless mode.
///
/// Returns `(response_text, tool_calls)`. Auto-denies any approval requests.
/// Times out after 120 seconds of no data.
async fn collect_response(
    client: &mut socket_client::SocketClient,
    session_id: &astrid_core::SessionId,
    format: formatter::OutputFormat,
    auto_approve: bool,
) -> Result<(String, Vec<serde_json::Value>)> {
    let mut response_text = String::new();
    let mut tool_calls: Vec<serde_json::Value> = Vec::new();
    let timeout_duration = std::time::Duration::from_secs(120);

    loop {
        let message = match tokio::time::timeout(timeout_duration, client.read_message()).await {
            Ok(Ok(Some(msg))) => msg,
            Ok(Ok(None)) => break,
            Ok(Err(e)) => return Err(e.context("Failed to read from daemon")),
            Err(_) => {
                eprintln!("[headless] Timed out waiting for response (120s)");
                std::process::exit(53);
            },
        };

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
                let topic = format!("astrid.v1.approval.response.{request_id}");
                let msg = astrid_types::ipc::IpcMessage::new(topic, response, session_id.0);
                client.send_message(msg).await?;
            },
            _ => {},
        }
    }

    Ok((response_text, tool_calls))
}
