//! Rendering logic for the TUI — single-view Nexus layout.

use super::state::{
    App, InputSegment, MessageKind, MessageRole, NexusEntry, PALETTE_MAX_VISIBLE, ToolStatusKind,
    UiState,
};

use super::theme::Theme;
use astrid_core::truncate_to_boundary;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
};
use unicode_width::UnicodeWidthStr;

/// Parameters for rendering a text segment with an inline cursor.
struct CursorRenderParams<'a> {
    prompt_str: &'a str,
    raw_text: &'a str,
    display_str: &'a str,
    cursor_byte_off: usize,
    is_secret: bool,
    has_slash_prefix: bool,
    cursor_str: &'a str,
    input_style: Style,
    cursor_color: Color,
}

/// Build a `Line` with an inline cursor rendered at the correct position.
///
/// Handles slash-command prefix adjustment and secret-field byte-to-char
/// offset conversion. Used by both the segment-aware and flat render paths.
fn render_text_with_cursor(p: &CursorRenderParams<'_>) -> Line<'static> {
    let adj_off = if p.has_slash_prefix {
        p.cursor_byte_off.saturating_sub(1)
    } else {
        p.cursor_byte_off
    };
    let split_pos = if p.is_secret {
        p.raw_text[..adj_off.min(p.raw_text.len())].chars().count()
    } else {
        adj_off.min(p.display_str.len())
    };
    let (before, after) = p.display_str.split_at(split_pos.min(p.display_str.len()));
    Line::from(vec![
        Span::styled(
            p.prompt_str.to_string(),
            p.input_style.add_modifier(Modifier::BOLD),
        ),
        Span::styled(before.to_string(), p.input_style),
        Span::styled(
            p.cursor_str.to_string(),
            Style::default().fg(p.cursor_color),
        ),
        Span::styled(after.to_string(), p.input_style),
    ])
}

// ─── Public Helpers ──────────────────────────────────────────────

/// Convert a line of markdown text to styled spans.
fn markdown_to_spans<'a>(line: &str, theme: &Theme) -> Vec<Span<'a>> {
    let mut spans = Vec::new();
    let trimmed = line.trim_start();

    // # Header lines → bold + user color
    for prefix in &["### ", "## ", "# "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            spans.push(Span::styled(
                rest.to_string(),
                Style::default().fg(theme.user).add_modifier(Modifier::BOLD),
            ));
            return spans;
        }
    }

    // - list / * list → bullet prefix in tool color
    if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
        let indent = &line[..line.len().saturating_sub(trimmed.len())];
        spans.push(Span::styled(
            format!("{indent}  \u{2022} "),
            Style::default().fg(theme.tool),
        ));
        let rest = &trimmed[2..];
        spans.extend(parse_inline_markdown(rest, theme));
        return spans;
    }

    // Numbered list: 1. item
    if let Some(rest) = trimmed
        .strip_prefix(|c: char| c.is_ascii_digit())
        .and_then(|s| s.strip_prefix(". "))
    {
        let indent = &line[..line.len().saturating_sub(trimmed.len())];
        let num_char = trimmed.chars().next().expect("trimmed matched a digit");
        spans.push(Span::styled(
            format!("{indent}{num_char}. "),
            Style::default().fg(theme.tool),
        ));
        spans.extend(parse_inline_markdown(rest, theme));
        return spans;
    }

    // Regular line: parse inline formatting
    parse_inline_markdown(line, theme)
}

/// Parse inline markdown: **bold** and `code`.
fn parse_inline_markdown<'a>(text: &str, theme: &Theme) -> Vec<Span<'a>> {
    let mut spans = Vec::new();
    let mut chars = text.char_indices().peekable();
    let mut current = String::new();
    let base_style = Style::default().fg(theme.assistant);

    while let Some((i, c)) = chars.next() {
        match c {
            '*' if text[i..].starts_with("**") => {
                if !current.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut current), base_style));
                }
                chars.next();
                let mut bold_text = String::new();
                while let Some((j, bc)) = chars.next() {
                    if bc == '*' && text[j..].starts_with("**") {
                        chars.next();
                        break;
                    }
                    bold_text.push(bc);
                }
                spans.push(Span::styled(
                    bold_text,
                    base_style.add_modifier(Modifier::BOLD),
                ));
            },
            '`' => {
                if !current.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut current), base_style));
                }
                let mut code_text = String::new();
                for (_, cc) in chars.by_ref() {
                    if cc == '`' {
                        break;
                    }
                    code_text.push(cc);
                }
                spans.push(Span::styled(code_text, Style::default().fg(theme.tool)));
            },
            _ => {
                current.push(c);
            },
        }
    }

    if !current.is_empty() {
        spans.push(Span::styled(current, base_style));
    }

    if spans.is_empty() {
        spans.push(Span::styled(text.to_string(), base_style));
    }

    spans
}

/// Render a completed tool inline in the message stream.
fn render_inline_tool(lines: &mut Vec<Line<'_>>, app: &App, idx: usize, theme: &Theme) {
    let Some(tool) = app.completed_tools.get(idx) else {
        return;
    };

    let bullet_color = match &tool.status {
        ToolStatusKind::Success => theme.success,
        ToolStatusKind::Failed(_) | ToolStatusKind::Denied => theme.error,
        _ => theme.muted,
    };

    let tool_name = to_pascal_case(&tool.name);
    let tool_header = if tool.display_arg.is_empty() {
        tool_name
    } else {
        format!("{tool_name}({})", tool.display_arg)
    };

    lines.push(Line::from(vec![
        Span::styled("⏺ ", Style::default().fg(bullet_color)),
        Span::styled(
            tool_header,
            Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
        ),
    ]));

    match &tool.status {
        ToolStatusKind::Denied => {
            lines.push(Line::from(vec![
                Span::styled("  ⎿ ", Style::default().fg(theme.border)),
                Span::styled("Denied", Style::default().fg(theme.error)),
            ]));
        },
        ToolStatusKind::Failed(err) => {
            lines.push(Line::from(vec![
                Span::styled("  ⎿ ", Style::default().fg(theme.border)),
                Span::styled(err.clone(), Style::default().fg(theme.error)),
            ]));
        },
        _ => {
            if let Some(ref output) = tool.output {
                let output_lines: Vec<&str> = output.lines().collect();
                let max_lines = 20;

                if tool.expanded {
                    for line in output_lines.iter().take(max_lines) {
                        lines.push(Line::from(vec![
                            Span::styled("  ⎿ ", Style::default().fg(theme.border)),
                            Span::styled((*line).to_string(), Style::default().fg(theme.assistant)),
                        ]));
                    }
                    if output_lines.len() > max_lines {
                        lines.push(Line::from(vec![
                            Span::styled("  ⎿ ", Style::default().fg(theme.border)),
                            Span::styled(
                                format!(
                                    "... {} more lines",
                                    output_lines.len().saturating_sub(max_lines)
                                ),
                                Style::default().fg(theme.warning),
                            ),
                        ]));
                    }
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("  ⎿ ", Style::default().fg(theme.border)),
                        Span::styled(
                            format!("{} lines (ctrl+e to expand)", output_lines.len()),
                            Style::default().fg(theme.muted),
                        ),
                    ]));
                }
            }
        },
    }
}

/// Convert `snake_case` tool names to `PascalCase`.
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => format!("{}{}", c.to_uppercase(), chars.as_str()),
            }
        })
        .collect()
}

/// Format a duration as human-readable.
fn format_elapsed(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 {
        let (mins, rem) = (secs / 60, secs % 60);
        format!("{mins}m {rem:02}s")
    } else {
        format!("{:.1}s", d.as_secs_f32())
    }
}

/// Fun verbs for the thinking spinner.
const FUN_VERBS: &[(&str, &str)] = &[
    ("Thinking", "Thought"),
    ("Analyzing", "Analyzed"),
    ("Reasoning", "Reasoned"),
    ("Pondering", "Pondered"),
    ("Evaluating", "Evaluated"),
    ("Examining", "Examined"),
    ("Considering", "Considered"),
    ("Processing", "Processed"),
    ("Cogitating", "Cogitated"),
    ("Deliberating", "Deliberated"),
    ("Ruminating", "Ruminated"),
    ("Musing", "Mused"),
    ("Contemplating", "Contemplated"),
    ("Percolating", "Percolated"),
];

fn build_breadcrumb(path: &str) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let display = if !home.is_empty() && path.starts_with(&home) {
        format!("~{}", &path[home.len()..])
    } else {
        path.to_string()
    };

    let parts: Vec<&str> = display.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return vec![display];
    }

    let start = parts.len().saturating_sub(3);
    let mut result: Vec<String> = parts[start..].iter().map(|s| (*s).to_string()).collect();

    if start > 0 && result.first().is_none_or(|s| s != "~") {
        result.insert(0, "~".to_string());
    }

    result
}

// ─── Word Wrapping ───────────────────────────────────────────────

/// Word-wrap a single text line to fit within `max_width` characters.
/// Preserves leading whitespace on the first sub-line so that
/// `markdown_to_spans` can still detect indented list markers.
fn word_wrap_line(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 || text.width() <= max_width {
        return vec![text.to_string()];
    }

    let trimmed = text.trim_start();
    let leading = &text[..text.len().saturating_sub(trimmed.len())];

    let mut result = Vec::new();
    let mut line = String::from(leading);
    let mut width = leading.width();
    let mut first_word = true;

    for word in trimmed.split(' ') {
        if word.is_empty() {
            continue;
        }
        let w = word.width();
        if first_word {
            line.push_str(word);
            width = width.saturating_add(w);
            first_word = false;
        } else if width.saturating_add(1).saturating_add(w) <= max_width {
            line.push(' ');
            line.push_str(word);
            width = width.saturating_add(1).saturating_add(w);
        } else {
            result.push(std::mem::take(&mut line));
            line = word.to_string();
            width = w;
        }
    }

    if !line.is_empty() || result.is_empty() {
        result.push(line);
    }

    result
}

// ─── Dynamic Input Height ────────────────────────────────────────

fn wrapped_line_count(text: &str, width: usize) -> usize {
    if text.is_empty() || width == 0 {
        return 1;
    }
    let mut lines = 1usize;
    let mut col = 0usize;
    for word in text.split_whitespace() {
        let wlen = word.width();
        if col > 0 && col.saturating_add(1).saturating_add(wlen) > width {
            lines = lines.saturating_add(1);
            col = wlen;
        } else if col == 0 {
            col = wlen;
        } else {
            col = col.saturating_add(1).saturating_add(wlen);
        }
    }
    lines
}

/// Calculate the number of display rows needed for the onboarding menu.
/// 1 title row + N field rows + enum choices + array items + description for the current field.
fn onboarding_row_count(
    fields: &[astrid_types::ipc::OnboardingField],
    current_idx: usize,
    current_array_items: &[String],
) -> usize {
    let mut n = fields.len().saturating_add(1);
    if let Some(field) = fields.get(current_idx) {
        if let astrid_types::ipc::OnboardingFieldType::Enum(choices) = &field.field_type {
            n = n.saturating_add(PALETTE_MAX_VISIBLE.min(choices.len()));
        }
        if matches!(
            field.field_type,
            astrid_types::ipc::OnboardingFieldType::Array
        ) {
            n = n.saturating_add(current_array_items.len());
        }
        if field.description.is_some() {
            n = n.saturating_add(1);
        }
    }
    n
}

fn input_height(app: &App, frame_area: Rect) -> u16 {
    let prompt_len = 2u16;
    let avail = frame_area.width.saturating_sub(prompt_len + 1) as usize;

    // All segments render inline on a single line. Compute the total
    // character width to determine how many wrapped lines are needed.
    let mut total_chars: usize = 0;
    let mut paste_number: usize = 0;
    for (i, seg) in app.input_buf.segments.iter().enumerate() {
        match seg {
            InputSegment::Text(t) => {
                let display = if i == 0 && t.starts_with('/') {
                    &t[1..]
                } else {
                    t
                };
                total_chars = total_chars.saturating_add(display.len());
            },
            InputSegment::PasteBlock { line_count, .. } => {
                paste_number = paste_number.saturating_add(1);
                // "[Pasted text #N, M lines]" or "[Pasted text #N, 1 line]"
                let label = format!(
                    "[Pasted text #{paste_number}, {line_count} line{}]",
                    if *line_count == 1 { "" } else { "s" }
                );
                total_chars = total_chars.saturating_add(label.len());
            },
        }
    }
    #[expect(clippy::cast_possible_truncation)]
    let total_lines = if avail == 0 || total_chars == 0 {
        1u16
    } else {
        // Ceiling division: how many rows does total_chars span at `avail` width?
        total_chars.div_ceil(avail).max(1) as u16
    };

    let max = 8;
    let base = (1u16.saturating_add(total_lines)).clamp(3, max);

    if let UiState::Selection { options, .. } = &app.state {
        let n = options.len().saturating_add(1);
        let dynamic_max_visible = (frame_area.height / 3).clamp(5, 10) as usize;
        #[expect(clippy::cast_possible_truncation)]
        let menu_rows = 1u16.saturating_add(n.min(dynamic_max_visible) as u16);
        return base.saturating_add(menu_rows);
    }

    if let UiState::Onboarding {
        fields,
        current_idx,
        current_array_items,
        ..
    } = &app.state
    {
        let n = onboarding_row_count(fields, *current_idx, current_array_items);
        let dynamic_max_visible = (frame_area.height / 3).clamp(5, 15) as usize;
        #[expect(clippy::cast_possible_truncation)]
        let menu_rows = 1u16.saturating_add(n.min(dynamic_max_visible) as u16);
        return base.saturating_add(menu_rows);
    }

    if app.palette_active() {
        let n = app.palette_filtered().len();
        if n > 0 {
            // Dynamic max height for palette: 1/3 of the total screen height
            let dynamic_max_visible = (frame_area.height / 3).clamp(5, 15) as usize;

            // 1 for separator border + visible item rows
            #[expect(clippy::cast_possible_truncation)]
            let palette_rows = 1u16.saturating_add(n.min(dynamic_max_visible) as u16);
            return base.saturating_add(palette_rows);
        }
    }

    base
}

// ─── Frame Rendering ─────────────────────────────────────────────

/// Render a frame of the TUI.
pub(crate) fn render_frame(frame: &mut Frame, app: &App) {
    let theme = Theme::default();

    // Top-level layout: nexus + activity + input + status bar
    let dyn_input_h = input_height(app, frame.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),              // Nexus stream
            Constraint::Length(1),           // Activity indicator
            Constraint::Length(dyn_input_h), // Input
            Constraint::Length(1),           // Status bar
        ])
        .split(frame.area());

    render_nexus(frame, chunks[0], app, &theme);
    render_activity(frame, chunks[1], app, &theme);
    render_input(frame, chunks[2], app, &theme);
    render_status(frame, chunks[3], app, &theme);

    // Render approval overlay if needed
    if app.state == UiState::AwaitingApproval && !app.pending_approvals.is_empty() {
        render_approval_overlay(frame, app, &theme);
    }
}

// ─── Nexus Stream ────────────────────────────────────────────────

#[expect(clippy::too_many_lines)]
fn render_nexus(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let in_copy_mode = app.state == UiState::CopyMode;
    let mut lines: Vec<Line> = Vec::new();
    // Track which nexus entry index each line belongs to (None for spacing/running tools)
    let mut line_entry_idx: Vec<Option<usize>> = Vec::new();

    // Render messages from the nexus stream
    for (entry_idx, entry) in app.nexus_stream.iter().enumerate() {
        match entry {
            NexusEntry::Message(msg) => {
                let before = lines.len();
                if let Some(MessageKind::ToolResult(idx)) = &msg.kind {
                    render_inline_tool(&mut lines, app, *idx, theme);
                } else {
                    match msg.role {
                        MessageRole::User => {
                            for (i, line) in msg.content.lines().enumerate() {
                                if i == 0 {
                                    lines.push(Line::from(vec![
                                        Span::styled(
                                            "> ",
                                            Style::default()
                                                .fg(theme.tool)
                                                .add_modifier(Modifier::BOLD),
                                        ),
                                        Span::styled(line, Style::default().fg(theme.user)),
                                    ]));
                                } else {
                                    lines.push(Line::from(Span::styled(
                                        format!("  {line}"),
                                        Style::default().fg(theme.user),
                                    )));
                                }
                            }
                        },
                        MessageRole::Assistant => {
                            let content_lines: Vec<&str> = msg.content.lines().collect();
                            let mut prev_blank = false;
                            let wrap_width = (area.width as usize).saturating_sub(2);
                            let mut is_first_visual = true;

                            for line in &content_lines {
                                let is_blank = line.trim().is_empty();
                                if is_blank && prev_blank {
                                    continue;
                                }
                                prev_blank = is_blank;

                                if is_blank {
                                    // Skip leading blank lines so ⏺ lands on the
                                    // first real content line, not a stray newline.
                                    if is_first_visual {
                                        continue;
                                    }
                                    lines.push(Line::from(""));
                                    continue;
                                }

                                let wrapped = word_wrap_line(line, wrap_width);
                                for sub in &wrapped {
                                    if is_first_visual {
                                        let mut spans = vec![Span::styled(
                                            "⏺ ",
                                            Style::default().fg(theme.assistant),
                                        )];
                                        spans.extend(markdown_to_spans(sub, theme));
                                        lines.push(Line::from(spans));
                                        is_first_visual = false;
                                    } else {
                                        let mut spans = vec![Span::styled("  ", Style::default())];
                                        spans.extend(markdown_to_spans(sub, theme));
                                        lines.push(Line::from(spans));
                                    }
                                }
                            }
                        },
                        MessageRole::LocalUi => {
                            let is_diff = msg.kind.is_some();
                            if is_diff {
                                let style = match &msg.kind {
                                    Some(MessageKind::DiffHeader | MessageKind::DiffFooter) => {
                                        Style::default().fg(theme.diff_context)
                                    },
                                    Some(MessageKind::DiffRemoved) => {
                                        Style::default().fg(theme.diff_removed)
                                    },
                                    Some(MessageKind::DiffAdded) => {
                                        Style::default().fg(theme.diff_added)
                                    },
                                    Some(MessageKind::ToolResult(_)) | None => unreachable!(),
                                };
                                let prefix = "  ⎿  ";
                                for line in msg.content.lines() {
                                    lines.push(Line::from(Span::styled(
                                        format!("{prefix}{line}"),
                                        style,
                                    )));
                                }
                            } else {
                                let content_lines: Vec<&str> = msg.content.lines().collect();
                                let wrap_width = (area.width as usize).saturating_sub(2);

                                for line in &content_lines {
                                    let wrapped = word_wrap_line(line, wrap_width);
                                    for sub in &wrapped {
                                        let mut spans = vec![Span::styled("  ", Style::default())];
                                        spans.extend(markdown_to_spans(sub, theme));
                                        lines.push(Line::from(spans));
                                    }
                                }
                            }
                        },
                    }
                }
                // Tag all lines added for this entry
                let added = lines.len().saturating_sub(before);
                line_entry_idx.extend(std::iter::repeat_n(Some(entry_idx), added));

                if msg.spacing {
                    lines.push(Line::from(""));
                    line_entry_idx.push(None);
                }
            },
        }
    }

    // Running tools: primary-text bullet with spinner + ToolName(arg)
    for tool in &app.running_tools {
        let elapsed = tool.start_time.elapsed();
        let spinner = theme.spinner.frame_at(elapsed.as_millis());

        let tool_name = to_pascal_case(&tool.name);
        let tool_header = if tool.display_arg.is_empty() {
            tool_name
        } else {
            format!("{tool_name}({})", tool.display_arg)
        };

        lines.push(Line::from(vec![
            Span::styled("⏺ ", Style::default().fg(theme.assistant)),
            Span::styled(format!("{spinner} "), Style::default().fg(theme.tool)),
            Span::styled(tool_header, Style::default().fg(theme.tool)),
            Span::styled(
                format!(" ({:.1}s)", elapsed.as_secs_f32()),
                Style::default().fg(theme.muted),
            ),
        ]));
        line_entry_idx.push(None);
    }

    // Apply copy-mode background highlighting
    if in_copy_mode {
        for (i, line) in lines.iter_mut().enumerate() {
            if let Some(Some(entry_idx)) = line_entry_idx.get(i) {
                let bg = if *entry_idx == app.copy_cursor {
                    Some(Color::Indexed(17)) // dark blue
                } else if app.copy_selected.contains(entry_idx) {
                    Some(Color::DarkGray)
                } else {
                    None
                };
                if let Some(bg_color) = bg {
                    for span in &mut line.spans {
                        span.style = span.style.bg(bg_color);
                    }
                }
            }
        }
    }

    // Use Paragraph's built-in scroll so wrapped lines are accounted for.
    let visible_height = area.height as usize;
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    let total_rows = paragraph.line_count(area.width);
    let max_scroll = total_rows.saturating_sub(visible_height);
    let effective_scroll = app.scroll_offset.min(max_scroll);

    // scroll_offset 0 = bottom, so scroll_y = max_scroll - effective_scroll
    let scroll_y = max_scroll.saturating_sub(effective_scroll);

    #[expect(clippy::cast_possible_truncation)]
    let paragraph = paragraph.scroll((scroll_y as u16, 0));
    frame.render_widget(paragraph, area);
}

// ─── Activity Bar ────────────────────────────────────────────────

#[expect(clippy::cast_precision_loss, clippy::too_many_lines)]
fn render_activity(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let spans: Vec<Span> = match &app.state {
        UiState::Thinking { start_time, .. } => {
            let elapsed = start_time.elapsed();
            let spinner = theme.spinner.frame_at(elapsed.as_millis());
            #[expect(clippy::arithmetic_side_effects)]
            let verb_idx = (elapsed.as_millis() / 2500) as usize % FUN_VERBS.len();
            let verb = FUN_VERBS[verb_idx].0;
            let pulse_phase = (elapsed.as_millis() % 2000) as f32 / 2000.0;
            let spinner_color = if pulse_phase < 0.5 {
                theme.thinking
            } else {
                theme.tool
            };

            vec![
                Span::styled("  ", Style::default()),
                Span::styled(format!("{spinner} "), Style::default().fg(spinner_color)),
                Span::styled(format!("{verb}..."), Style::default().fg(theme.thinking)),
                Span::styled(
                    format!(
                        " ({} · {} tokens)",
                        format_elapsed(elapsed),
                        app.tokens_streamed
                    ),
                    Style::default().fg(theme.muted),
                ),
            ]
        },
        UiState::Streaming { start_time } => {
            let elapsed = start_time.elapsed();
            let spinner = theme.spinner.frame_at(elapsed.as_millis());
            vec![
                Span::styled("  ", Style::default()),
                Span::styled(format!("{spinner} "), Style::default().fg(theme.success)),
                Span::styled("Responding...", Style::default().fg(theme.success)),
                Span::styled(
                    format!(
                        " ({} · {} tokens)",
                        format_elapsed(elapsed),
                        app.tokens_streamed
                    ),
                    Style::default().fg(theme.muted),
                ),
            ]
        },
        UiState::ToolRunning {
            tool_name,
            start_time,
        } => {
            let elapsed = start_time.elapsed();
            let spinner = theme.spinner.frame_at(elapsed.as_millis());
            let flash_phase = (elapsed.as_millis() % 1000) as f32 / 1000.0;
            let tool_color = if flash_phase < 0.5 {
                theme.tool
            } else {
                theme.warning
            };

            vec![
                Span::styled("  ", Style::default()),
                Span::styled(format!("{spinner} "), Style::default().fg(tool_color)),
                Span::styled(
                    format!("Running {tool_name}..."),
                    Style::default().fg(theme.tool),
                ),
                Span::styled(
                    format!(" ({})", format_elapsed(elapsed)),
                    Style::default().fg(theme.muted),
                ),
            ]
        },
        UiState::Interrupted => {
            vec![
                Span::styled("  ", Style::default()),
                Span::styled("⏺ Interrupted", Style::default().fg(theme.warning)),
                Span::styled(
                    " · What should Astrid do instead?",
                    Style::default().fg(theme.muted),
                ),
            ]
        },
        UiState::CopyMode => {
            vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    "COPY ",
                    Style::default()
                        .fg(theme.warning)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "[Space]",
                    Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Select  ", Style::default().fg(theme.muted)),
                Span::styled(
                    "[Enter]",
                    Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Copy  ", Style::default().fg(theme.muted)),
                Span::styled(
                    "[Ctrl+A]",
                    Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" All  ", Style::default().fg(theme.muted)),
                Span::styled(
                    "[Esc]",
                    Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" Cancel", Style::default().fg(theme.muted)),
            ]
        },
        UiState::Selection { title, .. } => {
            vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("▸ {title}"),
                    Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " · ↑↓ Navigate  Enter Select  Esc Cancel",
                    Style::default().fg(theme.muted),
                ),
            ]
        },
        UiState::Onboarding { .. } => {
            vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    "⚙ Configuration Required",
                    Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " · Please provide the required environment variables below.",
                    Style::default().fg(theme.muted),
                ),
            ]
        },
        UiState::Idle | UiState::AwaitingApproval | UiState::Error { .. } => {
            // Show copy notice for a few seconds
            if let Some((notice, at)) = &app.copy_notice {
                let since = at.elapsed();
                if since.as_secs() < 3 {
                    let color = if since.as_secs() < 2 {
                        theme.success
                    } else {
                        theme.muted
                    };
                    return frame.render_widget(
                        Paragraph::new(Line::from(vec![
                            Span::styled("  ", Style::default()),
                            Span::styled(notice, Style::default().fg(color)),
                        ])),
                        area,
                    );
                }
            }

            if let Some((past_verb, duration)) = &app.last_completed
                && let Some(completed_at) = app.last_completed_at
            {
                let since = completed_at.elapsed();
                if since.as_secs() < 8 {
                    let color = if since.as_secs() < 4 {
                        theme.muted
                    } else {
                        theme.border
                    };
                    return frame.render_widget(
                        Paragraph::new(Line::from(vec![
                            Span::styled("  ", Style::default()),
                            Span::styled(
                                format!("{past_verb} for {}", format_elapsed(*duration)),
                                Style::default().fg(color),
                            ),
                        ])),
                        area,
                    );
                }
            }
            vec![]
        },
    };

    if spans.is_empty() {
        frame.render_widget(Paragraph::new(Line::from("")), area);
    } else {
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

// ─── Input Area ──────────────────────────────────────────────────

#[expect(clippy::too_many_lines)]
fn render_input(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let is_idle = matches!(app.state, UiState::Idle | UiState::Interrupted);

    // Dashed top border
    let border_line = "─".repeat(area.width as usize);
    let border = Paragraph::new(Line::from(Span::styled(
        border_line.clone(),
        Style::default().fg(theme.border),
    )));
    frame.render_widget(border, Rect::new(area.x, area.y, area.width, 1));

    // Calculate how much space the palette or onboarding menu needs
    let mut menu_rows = 0u16;
    let mut palette_filtered = Vec::new();

    if let UiState::Selection { options, .. } = &app.state {
        // title + options (capped at 10 visible)
        let n = options.len().saturating_add(1);
        #[expect(clippy::cast_possible_truncation)]
        {
            menu_rows = 1u16.saturating_add(n.min(10) as u16);
        }
    } else if let UiState::Onboarding {
        fields,
        current_idx,
        current_array_items,
        ..
    } = &app.state
    {
        let n = onboarding_row_count(fields, *current_idx, current_array_items);
        #[expect(clippy::cast_possible_truncation)]
        {
            menu_rows = 1u16.saturating_add(n.min(15) as u16);
        }
    } else if app.palette_active() {
        palette_filtered = app.palette_filtered();
        if !palette_filtered.is_empty() {
            #[expect(clippy::cast_possible_truncation)]
            {
                menu_rows =
                    1u16.saturating_add(palette_filtered.len().min(PALETTE_MAX_VISIBLE) as u16);
            }
        }
    }

    let input_area = Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width,
        area.height.saturating_sub(1u16.saturating_add(menu_rows)),
    );

    if app.quit_pending {
        let para = Paragraph::new(Line::from(vec![Span::styled(
            "  Press Ctrl+C again to exit...",
            Style::default().fg(theme.warning),
        )]));
        frame.render_widget(para, input_area);
        return;
    }

    let input_style = if is_idle
        || matches!(
            app.state,
            UiState::Onboarding { .. } | UiState::Selection { .. }
        ) {
        Style::default().fg(theme.user)
    } else {
        Style::default().fg(theme.muted)
    };

    let prompt = if matches!(
        app.state,
        UiState::Onboarding { .. } | UiState::Selection { .. }
    ) || !is_idle
    {
        "  "
    } else if app.input_buf.starts_with_slash() {
        "/ "
    } else {
        "> "
    };

    if app.input_buf.is_empty() && is_idle {
        // Placeholder text
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(prompt, input_style.add_modifier(Modifier::BOLD)),
                Span::styled("█", Style::default().fg(theme.cursor)),
                Span::styled(
                    " Ask a question or type / for commands...",
                    Style::default().fg(theme.border),
                ),
            ])),
            input_area,
        );
    } else {
        let mut is_secret = false;
        let mut is_enum = false;
        let mut field_placeholder: Option<&str> = None;
        if let UiState::Onboarding {
            fields,
            current_idx,
            ..
        } = &app.state
            && let Some(field) = fields.get(*current_idx)
        {
            is_secret = matches!(
                field.field_type,
                astrid_types::ipc::OnboardingFieldType::Secret
            );
            is_enum = matches!(
                field.field_type,
                astrid_types::ipc::OnboardingFieldType::Enum(_)
            );
            field_placeholder = field.placeholder.as_deref();
        }

        // Hide cursor for enum fields - the picker handles selection.
        let cursor_str = if is_enum { "" } else { "█" };
        let cursor_color = if is_idle || matches!(app.state, UiState::Onboarding { .. }) {
            theme.cursor
        } else {
            theme.border
        };

        // Build lines from segments.
        let mut lines: Vec<Line> = Vec::new();
        let has_paste_blocks = app.input_buf.has_paste_blocks();

        if has_paste_blocks {
            // Inline rendering: all segments on a single line.
            let (cursor_seg, cursor_off) = app.input_buf.cursor;
            let mut paste_number: usize = 0;
            let mut spans: Vec<Span<'static>> = Vec::new();

            // Leading prompt
            spans.push(Span::styled(
                prompt.to_string(),
                input_style.add_modifier(Modifier::BOLD),
            ));

            for (seg_idx, seg) in app.input_buf.segments.iter().enumerate() {
                match seg {
                    InputSegment::Text(t) => {
                        let display = if seg_idx == 0 && t.starts_with('/') && is_idle {
                            &t[1..]
                        } else {
                            t
                        };
                        let display_str = if is_secret {
                            "*".repeat(display.chars().count())
                        } else {
                            display.to_string()
                        };

                        let is_cursor_here = seg_idx == cursor_seg && !is_enum;

                        if is_cursor_here {
                            let has_slash = seg_idx == 0 && t.starts_with('/') && is_idle;
                            let adj_off = if has_slash {
                                cursor_off.saturating_sub(1)
                            } else {
                                cursor_off
                            };
                            let split_pos = if is_secret {
                                display[..adj_off.min(display.len())].chars().count()
                            } else {
                                adj_off.min(display_str.len())
                            };
                            let (before, after) =
                                display_str.split_at(split_pos.min(display_str.len()));
                            spans.push(Span::styled(before.to_string(), input_style));
                            spans.push(Span::styled(
                                cursor_str.to_string(),
                                Style::default().fg(cursor_color),
                            ));
                            spans.push(Span::styled(after.to_string(), input_style));
                        } else {
                            spans.push(Span::styled(display_str, input_style));
                        }
                    },
                    InputSegment::PasteBlock { line_count, .. } => {
                        paste_number = paste_number.saturating_add(1);
                        let paste_style = Style::default().fg(theme.diff_added);
                        spans.push(Span::styled(
                            format!(
                                "[Pasted text #{paste_number}, {line_count} line{}]",
                                if *line_count == 1 { "" } else { "s" }
                            ),
                            paste_style,
                        ));
                    },
                }
            }

            lines.push(Line::from(spans));
        } else {
            // Simple flat rendering (no paste blocks) - original path.
            let flat = app.input_buf.flat_text();
            let display_input = if flat.starts_with('/') && is_idle {
                &flat[1..]
            } else {
                &flat
            };

            let display_str = if is_secret {
                "*".repeat(display_input.chars().count())
            } else {
                display_input.to_string()
            };

            let show_placeholder = display_input.is_empty() && !is_secret && !is_enum;
            if show_placeholder && let Some(ph) = field_placeholder {
                lines.push(Line::from(vec![
                    Span::styled(prompt, input_style.add_modifier(Modifier::BOLD)),
                    Span::styled(ph, Style::default().fg(theme.border)),
                    Span::styled(cursor_str, Style::default().fg(cursor_color)),
                ]));
            } else {
                lines.push(render_text_with_cursor(&CursorRenderParams {
                    prompt_str: prompt,
                    raw_text: display_input,
                    display_str: &display_str,
                    cursor_byte_off: app.input_buf.cursor.1,
                    is_secret,
                    has_slash_prefix: flat.starts_with('/') && is_idle,
                    cursor_str,
                    input_style,
                    cursor_color,
                }));
            }
        }

        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        frame.render_widget(para, input_area);
    }

    // Render palette or onboarding menu below input
    if menu_rows > 0 {
        let menu_y = area.y.saturating_add(area.height).saturating_sub(menu_rows);

        // Dashed separator
        let sep = Paragraph::new(Line::from(Span::styled(
            border_line.clone(),
            Style::default().fg(theme.border),
        )));
        frame.render_widget(sep, Rect::new(area.x, menu_y, area.width, 1));

        let items_area = Rect::new(
            area.x,
            menu_y.saturating_add(1),
            area.width,
            menu_rows.saturating_sub(1),
        );

        if let UiState::Selection {
            title,
            options,
            selected,
            scroll_offset,
            ..
        } = &app.state
        {
            render_selection_picker(
                frame,
                items_area,
                title,
                options,
                *selected,
                *scroll_offset,
                theme,
            );
        } else if let UiState::Onboarding {
            capsule_id,
            fields,
            current_idx,
            answers: _,
            enum_selected,
            enum_scroll_offset,
            current_array_items,
        } = &app.state
        {
            render_onboarding_menu(
                frame,
                items_area,
                capsule_id,
                fields,
                *current_idx,
                *enum_selected,
                *enum_scroll_offset,
                current_array_items,
                theme,
            );
        } else {
            render_palette_items(frame, items_area, app, &palette_filtered, theme);
        }
    }
}

fn render_selection_picker(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    options: &[astrid_types::ipc::SelectionOption],
    selected: usize,
    scroll_offset: usize,
    theme: &Theme,
) {
    let mut lines = Vec::new();

    lines.push(Line::from(vec![Span::styled(
        format!("  {title}"),
        Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
    )]));

    let visible_count = area.height.saturating_sub(1) as usize; // -1 for title
    let end = options
        .len()
        .min(scroll_offset.saturating_add(visible_count));

    for (i, opt) in options
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(end.saturating_sub(scroll_offset))
    {
        let is_selected = i == selected;

        let prefix = if is_selected { "  ▸ " } else { "    " };
        let style = if is_selected {
            Style::default().fg(theme.user).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.assistant)
        };

        let mut spans = vec![Span::styled(prefix, style), Span::styled(&opt.label, style)];

        if let Some(desc) = &opt.description {
            spans.push(Span::styled(
                format!("  — {desc}"),
                if is_selected {
                    Style::default().fg(theme.border)
                } else {
                    Style::default().fg(theme.muted)
                },
            ));
        }

        lines.push(Line::from(spans));
    }

    frame.render_widget(Paragraph::new(lines), area);
}

/// Strip control characters and ANSI escape sequences from external strings
/// (e.g. capsule manifest prompts) before rendering in the TUI.
fn sanitize_control_chars(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect()
}

#[expect(clippy::too_many_arguments, clippy::too_many_lines)]
fn render_onboarding_menu(
    frame: &mut Frame,
    area: Rect,
    capsule_id: &str,
    fields: &[astrid_types::ipc::OnboardingField],
    current_idx: usize,
    enum_selected: usize,
    enum_scroll_offset: usize,
    current_array_items: &[String],
    theme: &Theme,
) {
    let mut lines = Vec::new();

    // Title line
    lines.push(Line::from(vec![
        Span::styled(
            "  \u{2699}  Capsule Configuration: ",
            Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
        ),
        Span::styled(capsule_id, Style::default().fg(theme.user)),
    ]));

    for (i, field) in fields.iter().enumerate() {
        let is_current = i == current_idx;
        let is_done = i < current_idx;

        let style = if is_current {
            Style::default().fg(theme.tool).add_modifier(Modifier::BOLD)
        } else if is_done {
            Style::default().fg(theme.success)
        } else {
            Style::default().fg(theme.muted)
        };

        let prefix = if is_current {
            "  \u{25b6} "
        } else if is_done {
            "  \u{2713} "
        } else {
            "    "
        };

        let clean_key = sanitize_control_chars(&field.key);
        let mut spans = vec![Span::styled(prefix, style), Span::styled(clean_key, style)];

        if is_current {
            let clean_prompt = sanitize_control_chars(&field.prompt);
            let hint = match &field.field_type {
                astrid_types::ipc::OnboardingFieldType::Enum(_) => {
                    "\u{2191}\u{2193} to select, Enter to confirm".to_string()
                },
                astrid_types::ipc::OnboardingFieldType::Array => {
                    format!("{clean_prompt} (empty to finish)")
                },
                _ => clean_prompt,
            };
            spans.push(Span::styled(
                format!("  \u{2190} {hint}"),
                Style::default()
                    .fg(theme.border)
                    .add_modifier(Modifier::ITALIC),
            ));
        } else if is_done {
            spans.push(Span::styled(
                "  (saved)",
                Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC),
            ));
        }

        lines.push(Line::from(spans));

        // Show description for the current field
        if is_current && let Some(desc) = &field.description {
            lines.push(Line::from(Span::styled(
                format!("      {desc}"),
                Style::default()
                    .fg(theme.border)
                    .add_modifier(Modifier::ITALIC),
            )));
        }

        // Render inline enum picker for the current field
        if is_current
            && let astrid_types::ipc::OnboardingFieldType::Enum(choices) = &field.field_type
        {
            let visible_count = PALETTE_MAX_VISIBLE.min(choices.len());
            let end = choices
                .len()
                .min(enum_scroll_offset.saturating_add(visible_count));

            for (ci, choice) in choices
                .iter()
                .enumerate()
                .skip(enum_scroll_offset)
                .take(end.saturating_sub(enum_scroll_offset))
            {
                let is_sel = ci == enum_selected;
                let arrow = if is_sel {
                    "      \u{25b8} "
                } else {
                    "        "
                };
                let choice_style = if is_sel {
                    Style::default().fg(theme.user).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.assistant)
                };
                lines.push(Line::from(vec![
                    Span::styled(arrow, choice_style),
                    Span::styled(choice, choice_style),
                ]));
            }
        }

        // Show accumulated array items below the current array field
        if is_current
            && matches!(
                field.field_type,
                astrid_types::ipc::OnboardingFieldType::Array
            )
            && !current_array_items.is_empty()
        {
            for (j, item) in current_array_items.iter().enumerate() {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("      {}. ", j.saturating_add(1)),
                        Style::default().fg(theme.muted),
                    ),
                    Span::styled(item, Style::default().fg(theme.user)),
                ]));
            }
        }
    }

    let p = Paragraph::new(lines);
    frame.render_widget(p, area);
}

fn render_palette_items(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    filtered: &[&super::state::SlashCommandDef],
    theme: &Theme,
) {
    let visible_count = area.height as usize;
    let scroll = app.palette_scroll_offset;

    #[expect(clippy::cast_possible_truncation)]
    for (i, cmd) in filtered.iter().skip(scroll).take(visible_count).enumerate() {
        let is_selected = scroll.saturating_add(i) == app.palette_selected;
        let y = area.y.saturating_add(i as u16);
        let row_area = Rect::new(area.x, y, area.width, 1);

        let name_style = if is_selected {
            Style::default()
                .fg(theme.tool)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.tool)
        };

        let desc_style = if is_selected {
            Style::default()
                .fg(theme.user)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.muted)
        };

        let bg_style = if is_selected {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };

        // Layout: "  /command         Description text…"
        let name_col_width = 18usize;
        let padded_name = format!("  {:<width$}", cmd.name, width = name_col_width);

        let desc_avail = (area.width as usize).saturating_sub(padded_name.len());
        let description = if cmd.description.len() > desc_avail && desc_avail > 1 {
            format!(
                "{}…",
                truncate_to_boundary(&cmd.description, desc_avail.saturating_sub(1))
            )
        } else {
            cmd.description.clone()
        };

        // Fill remaining width with background
        let total_used = padded_name.len().saturating_add(description.len());
        let trailing = (area.width as usize).saturating_sub(total_used);

        let line = Line::from(vec![
            Span::styled(padded_name, name_style),
            Span::styled(description, desc_style),
            Span::styled(" ".repeat(trailing), bg_style),
        ]);

        frame.render_widget(Paragraph::new(line), row_area);
    }
}

// ─── Status Bar ──────────────────────────────────────────────────

fn render_status(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let width = area.width as usize;
    let mut spans: Vec<Span> = Vec::new();

    // Left: breadcrumb path
    let breadcrumb = build_breadcrumb(&app.working_dir);
    for (i, segment) in breadcrumb.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" > ", Style::default().fg(theme.border)));
        }
        let style = if i == breadcrumb.len().saturating_sub(1) {
            Style::default().fg(theme.user)
        } else {
            Style::default().fg(theme.muted)
        };
        spans.push(Span::styled(segment.clone(), style));
    }

    // Session ID
    if !app.session_id_short.is_empty() {
        spans.push(Span::styled(
            "  Session: ",
            Style::default().fg(theme.muted),
        ));
        spans.push(Span::styled(
            &app.session_id_short,
            Style::default().fg(theme.tool),
        ));
    }

    // Dynamic Progress / Status Message
    if let Some((msg, _)) = &app.status_message {
        spans.push(Span::styled("  |  ", Style::default().fg(theme.border)));
        spans.push(Span::styled(
            msg.clone(),
            Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
        ));
    }

    // Right: model + context progress bar
    #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let context_pct = (app.context_usage * 100.0) as u8;
    let bar_width: usize = 8;
    let filled = (usize::from(context_pct) * bar_width) / 100;
    let empty = bar_width.saturating_sub(filled);

    let bar_color = if context_pct > 80 {
        theme.error
    } else if context_pct > 60 {
        theme.warning
    } else {
        theme.success
    };

    let bar_filled = "█".repeat(filled);
    let bar_empty = "░".repeat(empty);
    let right_label = format!("{} ", app.model_name);
    let right_pct = format!(" {context_pct}%");
    let right_len = right_label
        .len()
        .saturating_add(bar_width)
        .saturating_add(right_pct.len());

    let left_len: usize = spans.iter().map(|s| s.content.len()).sum();
    let pad = width.saturating_sub(left_len.saturating_add(right_len));

    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(right_label, Style::default().fg(theme.tool)));
    spans.push(Span::styled(bar_filled, Style::default().fg(bar_color)));
    spans.push(Span::styled(bar_empty, Style::default().fg(theme.border)));
    spans.push(Span::styled(right_pct, Style::default().fg(bar_color)));

    let status = Paragraph::new(Line::from(spans));
    frame.render_widget(status, area);
}

// ─── Approval Overlay ────────────────────────────────────────────

fn render_approval_overlay(frame: &mut Frame, app: &App, theme: &Theme) {
    if app.pending_approvals.is_empty() {
        return;
    }

    let approval = &app.pending_approvals[app
        .selected_approval
        .min(app.pending_approvals.len().saturating_sub(1))];
    let area = frame.area();
    #[expect(clippy::cast_possible_truncation)]
    // u32 intermediate prevents u16 overflow; result <= area.width so truncation is safe
    let width = (u32::from(area.width) * 60 / 100) as u16;
    let width = width.clamp(40, 60);
    // Inner width after borders (left + right = 2 chars)
    let inner_width = width.saturating_sub(2) as usize;

    let approval_color = theme.warning;

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Tool: ", Style::default().fg(theme.muted)),
            Span::styled(
                &approval.tool_name,
                Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            &approval.description,
            Style::default().fg(theme.assistant),
        )),
        Line::from(""),
    ];

    for (key, value) in &approval.details {
        lines.push(Line::from(vec![
            Span::styled(format!("{key}: "), Style::default().fg(theme.muted)),
            Span::styled(value, Style::default().fg(theme.assistant)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "[y]",
            Style::default()
                .fg(theme.success)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Allow  "),
        Span::styled(
            "[s]",
            Style::default().fg(theme.tool).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Session  "),
        Span::styled(
            "[a]",
            Style::default()
                .fg(theme.success)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Always  "),
        Span::styled(
            "[n]",
            Style::default()
                .fg(theme.error)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Deny"),
    ]));

    // Calculate dynamic height based on content, accounting for word wrapping
    let mut content_height: u16 = 0;
    for line in &lines {
        let line_len: usize = line.spans.iter().map(|s| s.content.len()).sum();
        if inner_width > 0 && line_len > inner_width {
            #[expect(clippy::cast_possible_truncation)]
            {
                content_height =
                    content_height.saturating_add(line_len.div_ceil(inner_width) as u16);
            }
        } else {
            content_height = content_height.saturating_add(1);
        }
    }
    // Total height = content lines + 2 (top + bottom border)
    let height = content_height
        .saturating_add(2)
        .clamp(8, area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let overlay_area = Rect::new(x, y, width, height);

    let block = Block::default()
        .title(" Approval Required ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(approval_color))
        .style(Style::default().bg(Color::Black));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });

    frame.render_widget(Clear, overlay_area);
    frame.render_widget(paragraph, overlay_area);
}
