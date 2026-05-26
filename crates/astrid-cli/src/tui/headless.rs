//! Headless TUI snapshot mode.
//!
//! Renders the TUI to an in-memory buffer using `TestBackend` and dumps
//! text-mode frame snapshots after each significant event. Designed for
//! automated smoke testing and CI — you get the real rendered output without
//! an interactive terminal.
//!
//! # Event model
//!
//! Instead of a real-time render loop, the headless TUI steps through
//! discrete events. Each event mutates `App` state via the same
//! `handle_daemon_event` used by the live TUI, then renders a snapshot:
//!
//! - `ready` — initial screen, waiting for input
//! - `input_sent` — user prompt submitted
//! - `response_complete` — full LLM response rendered
//! - `tool_call:<name>` — tool execution started
//! - `tool_result:<id>` — tool execution completed
//! - `approval_approved:<action>` — approval auto-approved
//! - `approval_denied` — approval auto-denied
//! - `state_change` — any other state transition
//! - `timeout` / `disconnected` / `error` — terminal states

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use astrid_core::SessionId;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Modifier};

use super::render;
use super::state::{App, MessageRole, UiState};
use crate::socket_client::SocketClient;

/// Convert a ratatui `Color` to an ANSI SGR foreground code.
fn fg_ansi(color: Color) -> Option<String> {
    Some(match color {
        Color::Reset => return None,
        Color::Black => "30".into(),
        Color::Red => "31".into(),
        Color::Green => "32".into(),
        Color::Yellow => "33".into(),
        Color::Blue => "34".into(),
        Color::Magenta => "35".into(),
        Color::Cyan => "36".into(),
        Color::White => "37".into(),
        Color::Gray | Color::DarkGray => "90".into(),
        Color::LightRed => "91".into(),
        Color::LightGreen => "92".into(),
        Color::LightYellow => "93".into(),
        Color::LightBlue => "94".into(),
        Color::LightMagenta => "95".into(),
        Color::LightCyan => "96".into(),
        Color::Rgb(r, g, b) => format!("38;2;{r};{g};{b}"),
        Color::Indexed(i) => format!("38;5;{i}"),
    })
}

/// Convert a ratatui `Color` to an ANSI SGR background code.
fn bg_ansi(color: Color) -> Option<String> {
    Some(match color {
        Color::Reset => return None,
        Color::Black => "40".into(),
        Color::Red => "41".into(),
        Color::Green => "42".into(),
        Color::Yellow => "43".into(),
        Color::Blue => "44".into(),
        Color::Magenta => "45".into(),
        Color::Cyan => "46".into(),
        Color::White => "47".into(),
        Color::Gray | Color::DarkGray => "100".into(),
        Color::LightRed => "101".into(),
        Color::LightGreen => "102".into(),
        Color::LightYellow => "103".into(),
        Color::LightBlue => "104".into(),
        Color::LightMagenta => "105".into(),
        Color::LightCyan => "106".into(),
        Color::Rgb(r, g, b) => format!("48;2;{r};{g};{b}"),
        Color::Indexed(i) => format!("48;5;{i}"),
    })
}

/// Build ANSI SGR codes for the given style delta.
fn build_sgr(codes: &mut Vec<String>, fg: Color, bg: Color, mods: Modifier) {
    if let Some(c) = fg_ansi(fg) {
        codes.push(c);
    }
    if let Some(c) = bg_ansi(bg) {
        codes.push(c);
    }
    if mods.contains(Modifier::BOLD) {
        codes.push("1".into());
    }
    if mods.contains(Modifier::DIM) {
        codes.push("2".into());
    }
    if mods.contains(Modifier::ITALIC) {
        codes.push("3".into());
    }
    if mods.contains(Modifier::UNDERLINED) {
        codes.push("4".into());
    }
    if mods.contains(Modifier::REVERSED) {
        codes.push("7".into());
    }
}

/// Render a snapshot with full ANSI color and print it to stdout.
fn snapshot(terminal: &mut Terminal<TestBackend>, app: &mut App, event: &str) {
    app.terminal_height = terminal.size().map_or(40, |s| s.height);
    let _ = terminal.draw(|frame| render::render_frame(frame, app));

    let backend = terminal.backend();
    let buf = backend.buffer();
    let w = buf.area.width;
    let h = buf.area.height;

    println!("--- event: {event} ---");
    for y in 0..h {
        let mut line = String::with_capacity(usize::from(w).saturating_mul(4));
        let mut old_foreground = Color::Reset;
        let mut old_background = Color::Reset;
        let mut last_mods = Modifier::empty();

        for x in 0..w {
            let cell = &buf[(x, y)];
            let style = cell.style();
            let fg = style.fg.unwrap_or(Color::Reset);
            let bg = style.bg.unwrap_or(Color::Reset);
            let mods = style.add_modifier;

            if fg != old_foreground || bg != old_background || mods != last_mods {
                let mut codes: Vec<String> = Vec::new();
                if (fg == Color::Reset && old_foreground != Color::Reset)
                    || (bg == Color::Reset && old_background != Color::Reset)
                    || (mods != last_mods)
                {
                    codes.push("0".into());
                }
                build_sgr(&mut codes, fg, bg, mods);
                if !codes.is_empty() {
                    let _ = write!(line, "\x1b[{}m", codes.join(";"));
                }
                old_foreground = fg;
                old_background = bg;
                last_mods = mods;
            }
            line.push_str(cell.symbol());
        }

        if old_foreground != Color::Reset || old_background != Color::Reset || !last_mods.is_empty()
        {
            line.push_str("\x1b[0m");
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed == "\x1b[0m" {
            println!();
        } else {
            println!("{trimmed}\x1b[0m");
        }
    }
    println!("--- end ---");
    println!();
}

/// Configuration for a headless TUI session.
pub(crate) struct HeadlessConfig<'a> {
    pub client: &'a mut SocketClient,
    pub session_id: &'a SessionId,
    pub workspace: Option<std::path::PathBuf>,
    pub model_name: &'a str,
    pub prompt: &'a str,
    pub width: u16,
    pub height: u16,
    pub auto_approve: bool,
}

/// Run a headless TUI session with frame snapshots.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run(cfg: HeadlessConfig<'_>) -> anyhow::Result<()> {
    let working_dir = cfg
        .workspace
        .as_ref()
        .map_or_else(|| "no workspace".to_string(), |p| p.display().to_string());
    let session_id_short = cfg.session_id.0.to_string()[..8].to_string();

    let mut app = App::new(working_dir, cfg.model_name.to_string(), session_id_short);
    app.terminal_height = cfg.height;

    let backend = TestBackend::new(cfg.width, cfg.height);
    let mut terminal = Terminal::new(backend)?;

    // Sync dynamic commands on startup.
    let req = astrid_core::kernel_api::KernelRequest::GetCommands;
    if let Ok(val) = serde_json::to_value(req) {
        let msg = astrid_types::ipc::IpcMessage::new(
            "astrid.v1.request.get_commands",
            astrid_types::ipc::IpcPayload::RawJson(val),
            cfg.session_id.0,
        );
        let _ = cfg.client.send_message(msg).await;
    }

    snapshot(&mut terminal, &mut app, "ready");

    app.push_message(MessageRole::User, cfg.prompt.to_string());
    app.state = UiState::Thinking {
        start_time: Instant::now(),
        dots: 0,
    };
    crate::socket_client::send_input_as_active_agent(cfg.client, cfg.prompt.to_string()).await?;
    snapshot(&mut terminal, &mut app, "input_sent");

    let timeout = Duration::from_mins(2);
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            snapshot(&mut terminal, &mut app, "timeout");
            break;
        }

        let message =
            match tokio::time::timeout(Duration::from_millis(100), cfg.client.read_message()).await
            {
                Ok(Ok(Some(msg))) => msg,
                Ok(Ok(None)) => {
                    snapshot(&mut terminal, &mut app, "disconnected");
                    break;
                },
                Ok(Err(e)) => {
                    app.state = UiState::Error {
                        message: format!("Connection error: {e}"),
                    };
                    snapshot(&mut terminal, &mut app, "error");
                    break;
                },
                Err(_) => continue,
            };

        match &message.payload {
            astrid_types::ipc::IpcPayload::AgentResponse { is_final, .. } => {
                let was_final = *is_final;
                super::handle_daemon_event(&mut app, &message);
                if was_final {
                    snapshot(&mut terminal, &mut app, "response_complete");
                    break;
                }
            },

            astrid_types::ipc::IpcPayload::LlmStreamEvent {
                event: astrid_types::llm::StreamEvent::ToolCallStart { name, .. },
                ..
            } => {
                let tag = format!("tool_call:{name}");
                super::handle_daemon_event(&mut app, &message);
                snapshot(&mut terminal, &mut app, &tag);
            },

            astrid_types::ipc::IpcPayload::ToolExecuteResult { call_id, result } => {
                let status = if result.is_error { "failed" } else { "ok" };
                let tag = format!("tool_result:{call_id}:{status}");
                super::handle_daemon_event(&mut app, &message);
                snapshot(&mut terminal, &mut app, &tag);
            },

            astrid_types::ipc::IpcPayload::ApprovalRequired {
                request_id, action, ..
            } => {
                let request_id = request_id.clone();
                let action = action.clone();

                super::handle_daemon_event(&mut app, &message);
                snapshot(&mut terminal, &mut app, &format!("approval:{action}"));

                let (decision, reason) = if cfg.auto_approve {
                    ("approve", "headless-tui auto-approve")
                } else {
                    ("deny", "headless-tui auto-deny")
                };
                cfg.client
                    .send_message(astrid_types::ipc::IpcMessage::new(
                        format!("astrid.v1.approval.response.{request_id}"),
                        astrid_types::ipc::IpcPayload::ApprovalResponse {
                            request_id: request_id.clone(),
                            decision: decision.into(),
                            reason: Some(reason.into()),
                        },
                        cfg.session_id.0,
                    ))
                    .await?;

                app.pending_approvals.retain(|a| a.id != request_id);
                if app.pending_approvals.is_empty() {
                    app.state = UiState::Thinking {
                        start_time: Instant::now(),
                        dots: 0,
                    };
                }
                let tag = if cfg.auto_approve {
                    "approval_approved"
                } else {
                    "approval_denied"
                };
                snapshot(&mut terminal, &mut app, tag);
            },

            _ => {
                let prev = std::mem::discriminant(&app.state);
                super::handle_daemon_event(&mut app, &message);
                let curr = std::mem::discriminant(&app.state);
                if curr != prev {
                    snapshot(&mut terminal, &mut app, "state_change");
                }
            },
        }
    }

    let msg = astrid_types::ipc::IpcMessage::new(
        "client.v1.disconnect",
        astrid_types::ipc::IpcPayload::Disconnect {
            reason: Some("headless-tui-done".to_string()),
        },
        cfg.session_id.0,
    );
    let _ = cfg.client.send_message(msg).await;

    Ok(())
}
