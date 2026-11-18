//! Markdown span parsing for the terminal renderer.

use super::super::theme::Theme;
use ratatui::{
    style::{Modifier, Style},
    text::Span,
};

/// Convert a line of markdown text to styled spans.
pub(super) fn markdown_to_spans<'a>(line: &str, theme: &Theme) -> Vec<Span<'a>> {
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
    let digit_end = trimmed
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map_or(trimmed.len(), |(index, _)| index);
    let (number, suffix) = trimmed.split_at(digit_end);
    if !number.is_empty()
        && let Some(rest) = suffix.strip_prefix(". ")
    {
        let indent = &line[..line.len().saturating_sub(trimmed.len())];
        spans.push(Span::styled(
            format!("{indent}{number}. "),
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

#[cfg(test)]
mod tests;
