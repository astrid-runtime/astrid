//! Chat command - interactive agent session via daemon.
//!
//! The CLI is a thin client: it connects to the daemon (auto-starting if needed),
//! creates or resumes a session, subscribes to events, and renders output.
//! All heavy lifting (LLM calls, MCP, security) happens in the daemon.

use astrid_core::SessionId;
use colored::Colorize;

use crate::formatter::{OutputFormat, OutputFormatter, create_formatter};
use crate::repl::ReadlineEvent;
use crate::socket_client::SocketClient;
use crate::theme::Theme;

/// Reason sent (and displayed) when the JSON REPL auto-denies an approval request.
const APPROVAL_UNSUPPORTED_REASON: &str = "approvals not supported in JSON REPL mode";

/// Reason sent when the JSON REPL auto-skips a selection prompt.
const SELECTION_UNSUPPORTED_REASON: &str = "interactive selection not supported in JSON REPL mode";

/// Reason sent when the JSON REPL auto-skips an elicit (user input) prompt.
const ELICIT_UNSUPPORTED_REASON: &str = "interactive input not supported in JSON REPL mode";

/// Run interactive chat mode via the daemon.
pub(crate) async fn run_chat(
    client: &mut SocketClient,
    session_id: &SessionId,
    model_name: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Pretty => {
            // TUI mode — replaces the rustyline REPL.
            let workspace = std::env::current_dir().ok();
            crate::tui::run(client, session_id, workspace, model_name).await?;
        },
        OutputFormat::Json => {
            // JSON/NDJSON mode — keep the existing stdin loop.
            run_json_chat(client, session_id, format).await?;
        },
    }

    Ok(())
}

async fn run_json_chat(
    client: &mut SocketClient,
    session_id: &SessionId,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let mut formatter: Box<dyn OutputFormatter> = create_formatter(format);

    println!(
        "Session: {} | Type {} to quit, {} for help
",
        Theme::session_id(&session_id.0.to_string()),
        "exit".cyan(),
        "/help".cyan()
    );

    let mut editor = crate::repl::ReplEditor::new()?;

    loop {
        let input = match editor.readline() {
            ReadlineEvent::Line(line) => line,
            ReadlineEvent::Interrupted => continue,
            ReadlineEvent::Eof => {
                println!("{}", Theme::dimmed("Goodbye!"));
                break;
            },
        };

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        if input == "exit" || input == "quit" {
            println!("{}", Theme::dimmed("Goodbye!"));
            break;
        }

        if input.starts_with('/') {
            handle_slash_command(input, client, session_id);
            continue;
        }

        crate::socket_client::send_input_as_active_agent(client, input.to_string()).await?;

        if !drain_agent_response(client, session_id, &mut *formatter).await? {
            return Ok(());
        }
    }

    Ok(())
}

/// Read events until an `AgentResponse { is_final: true }` arrives.
///
/// Interactive payloads (`ApprovalRequired`, `SelectionRequired`, `ElicitRequest`)
/// are auto-denied/cancelled because the JSON REPL has no interactive UI.
///
/// Returns `false` if the connection was lost (caller should exit the REPL).
async fn drain_agent_response(
    client: &mut SocketClient,
    session_id: &SessionId,
    formatter: &mut dyn OutputFormatter,
) -> anyhow::Result<bool> {
    loop {
        let Some(message) = client.read_message().await? else {
            eprintln!("{}", Theme::error("Connection to daemon lost"));
            return Ok(false);
        };

        match message.payload {
            astrid_types::ipc::IpcPayload::AgentResponse { text, is_final, .. } => {
                formatter.format_text(&text);
                if is_final {
                    formatter.flush_markdown();
                    return Ok(true);
                }
            },
            astrid_types::ipc::IpcPayload::LlmStreamEvent {
                event: astrid_types::llm::StreamEvent::ToolCallStart { id, name },
                ..
            } => {
                formatter.flush_markdown();
                formatter.format_tool_start(&id, &name, &serde_json::Value::Null);
            },
            astrid_types::ipc::IpcPayload::ToolExecuteResult { call_id, result } => {
                formatter.flush_markdown();
                let res_val = serde_json::to_string(&result.content).unwrap_or_default();
                formatter.format_tool_result(&call_id, &res_val, result.is_error);
            },
            astrid_types::ipc::IpcPayload::ApprovalRequired {
                request_id,
                action,
                resource,
                reason,
            } => {
                formatter.flush_markdown();
                auto_deny_approval(client, session_id, &request_id, &action, &resource, &reason)
                    .await?;
            },
            astrid_types::ipc::IpcPayload::SelectionRequired {
                request_id,
                title,
                options,
                callback_topic,
            } => {
                formatter.flush_markdown();
                auto_skip_selection(
                    client,
                    session_id,
                    &request_id,
                    &title,
                    &options,
                    &callback_topic,
                )
                .await?;
            },
            astrid_types::ipc::IpcPayload::ElicitRequest {
                request_id,
                capsule_id,
                field,
            } => {
                formatter.flush_markdown();
                auto_skip_elicit(client, session_id, request_id, &capsule_id, &field).await?;
            },
            _ => {
                // Payloads like Connect, Disconnect, OnboardingRequired,
                // LlmRequest, etc. are not actionable in JSON REPL mode.
            },
        }
    }
}

/// Auto-deny an approval request and print a diagnostic.
async fn auto_deny_approval(
    client: &mut SocketClient,
    session_id: &SessionId,
    request_id: &str,
    action: &str,
    resource: &str,
    reason: &str,
) -> anyhow::Result<()> {
    println!(
        "{}",
        Theme::warning(&format!(
            "Approval required: {action} on {resource} ({reason})"
        ))
    );
    client
        .send_message(astrid_types::ipc::IpcMessage::new(
            astrid_types::Topic::approval_response(request_id),
            astrid_types::ipc::IpcPayload::ApprovalResponse {
                request_id: request_id.to_owned(),
                decision: "deny".into(),
                reason: Some(APPROVAL_UNSUPPORTED_REASON.into()),
            },
            session_id.0,
        ))
        .await?;
    println!(
        "{}",
        Theme::dimmed(&format!("Auto-denied: {APPROVAL_UNSUPPORTED_REASON}"))
    );
    Ok(())
}

/// Auto-skip a selection prompt by publishing an empty `selected_id`.
///
/// No formal cancel protocol exists for selections yet; an empty ID is
/// handled gracefully by consumers (e.g. capsule-registry returns an error
/// for unknown model IDs without crashing).
async fn auto_skip_selection(
    client: &mut SocketClient,
    session_id: &SessionId,
    request_id: &str,
    title: &str,
    options: &[astrid_types::ipc::SelectionOption],
    callback_topic: &str,
) -> anyhow::Result<()> {
    println!(
        "{}",
        Theme::warning(&format!("Selection required: {title}"))
    );
    for opt in options {
        println!(
            "{}",
            Theme::dimmed(&format!("  - [{}] {}", opt.id, opt.label))
        );
    }
    client
        .send_message(astrid_types::ipc::IpcMessage::new(
            astrid_types::Topic::from_raw(callback_topic),
            astrid_types::ipc::IpcPayload::Custom {
                data: serde_json::json!({
                    "request_id": request_id,
                    "selected_id": "",
                }),
            },
            session_id.0,
        ))
        .await?;
    println!(
        "{}",
        Theme::dimmed(&format!("Auto-skipped: {SELECTION_UNSUPPORTED_REASON}"))
    );
    Ok(())
}

/// Auto-cancel an elicit request by publishing `ElicitResponse` with `None` values.
///
/// The host function recognises `value: None, values: None` as user cancellation
/// (`elicit.rs:189`) and returns `Err` to the WASM guest.
async fn auto_skip_elicit(
    client: &mut SocketClient,
    session_id: &SessionId,
    request_id: uuid::Uuid,
    capsule_id: &str,
    field: &astrid_types::ipc::OnboardingField,
) -> anyhow::Result<()> {
    println!(
        "{}",
        Theme::warning(&format!(
            "Input required by capsule '{capsule_id}': {} ({})",
            field.prompt, field.key
        ))
    );
    client
        .send_message(astrid_types::ipc::IpcMessage::new(
            astrid_types::Topic::elicit_response(request_id),
            astrid_types::ipc::IpcPayload::ElicitResponse {
                request_id,
                value: None,
                values: None,
            },
            session_id.0,
        ))
        .await?;
    println!(
        "{}",
        Theme::dimmed(&format!("Auto-skipped: {ELICIT_UNSUPPORTED_REASON}"))
    );
    Ok(())
}

fn handle_slash_command(cmd: &str, _client: &mut SocketClient, _session_id: &SessionId) {
    println!("Slash commands temporarily disabled in JSON Mode during microkernel refactor: {cmd}");
}
