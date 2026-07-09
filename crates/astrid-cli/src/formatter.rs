//! Output formatters for rendering daemon events in the terminal.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use serde_json::Value;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::as_24_bit_terminal_escaped;

/// Output format mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Pretty,
    Json,
}

/// Trait for formatting daemon events to the terminal.
pub(crate) trait OutputFormatter {
    /// Format a text chunk (may be buffered for later rendering).
    fn format_text(&mut self, text: &str);

    /// Format the start of a tool call.
    fn format_tool_start(&mut self, id: &str, name: &str, args: &Value);

    /// Format the result of a tool call.
    fn format_tool_result(&mut self, id: &str, result: &str, is_error: bool);

    /// Format an error message.
    fn format_error(&mut self, msg: &str);

    /// Format a turn completion event.
    fn format_turn_complete(&mut self);

    /// Flush any buffered markdown at end of text stream.
    fn flush_markdown(&mut self);
}

// ---------------------------------------------------------------------------
// PrettyFormatter
// ---------------------------------------------------------------------------

/// Renders daemon events as styled terminal output with markdown formatting.
pub(crate) struct PrettyFormatter {
    text_buffer: String,
    active_spinners: HashMap<String, ProgressBar>,
    syntax_set: SyntaxSet,
    theme: Theme,
}

impl PrettyFormatter {
    /// Create a new `PrettyFormatter` with default syntax and theme sets.
    pub(crate) fn new() -> Self {
        let syntax_set = SyntaxSet::load_defaults_newlines();
        let theme_set = ThemeSet::load_defaults();
        let theme = theme_set.themes["base16-ocean.dark"].clone();
        Self {
            text_buffer: String::new(),
            active_spinners: HashMap::new(),
            syntax_set,
            theme,
        }
    }

    /// Render the buffered text as terminal markdown and clear the buffer.
    fn render_markdown(&mut self) {
        if self.text_buffer.is_empty() {
            return;
        }

        let text = std::mem::take(&mut self.text_buffer);
        let mut in_code_block = false;
        let mut code_block_lang = String::new();
        let mut code_block_lines: Vec<String> = Vec::new();

        for line in text.lines() {
            if line.starts_with("```") {
                if in_code_block {
                    // End of code block — render collected lines.
                    self.render_code_block(&code_block_lang, &code_block_lines);
                    code_block_lines.clear();
                    code_block_lang.clear();
                    in_code_block = false;
                } else {
                    // Start of code block — extract language.
                    in_code_block = true;
                    code_block_lang = line.trim_start_matches('`').trim().to_string();
                }
                continue;
            }

            if in_code_block {
                code_block_lines.push(line.to_string());
                continue;
            }

            // Regular line — render inline markdown.
            Self::render_markdown_line(line);
        }

        // If we ended mid-code-block (unclosed), flush whatever we have.
        if in_code_block && !code_block_lines.is_empty() {
            self.render_code_block(&code_block_lang, &code_block_lines);
        }
    }

    /// Render a single markdown line with inline formatting.
    fn render_markdown_line(line: &str) {
        let stdout = io::stdout();
        let mut out = stdout.lock();

        // Headers
        if let Some(rest) = line.strip_prefix("### ") {
            let _ = writeln!(out, "{}", rest.bold().cyan());
            return;
        }
        if let Some(rest) = line.strip_prefix("## ") {
            let _ = writeln!(out, "{}", rest.bold().cyan());
            return;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            let _ = writeln!(out, "{}", rest.bold().cyan());
            return;
        }

        // Blockquotes
        if let Some(rest) = line.strip_prefix("> ") {
            let _ = writeln!(out, "{}", rest.dimmed().italic());
            return;
        }

        // List items
        if let Some(rest) = line.strip_prefix("- ") {
            let formatted = Self::format_inline(rest);
            let _ = writeln!(out, "  \u{2022} {formatted}");
            return;
        }
        if let Some(rest) = line.strip_prefix("* ") {
            let formatted = Self::format_inline(rest);
            let _ = writeln!(out, "  \u{2022} {formatted}");
            return;
        }

        // Plain text with inline formatting.
        let formatted = Self::format_inline(line);
        let _ = writeln!(out, "{formatted}");
    }

    /// Apply inline markdown formatting: **bold** and `code`.
    fn format_inline(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            // Bold: **...**
            if i.saturating_add(1) < len
                && chars[i] == '*'
                && chars[i.saturating_add(1)] == '*'
                && let Some(end) = Self::find_closing_double_star(&chars, i.saturating_add(2))
            {
                let inner: String = chars[i.saturating_add(2)..end].iter().collect();
                let _ = write!(result, "{}", inner.bold());
                i = end.saturating_add(2);
                continue;
            }

            // Inline code: `...`
            if chars[i] == '`'
                && let Some(end) = Self::find_closing_backtick(&chars, i.saturating_add(1))
            {
                let inner: String = chars[i.saturating_add(1)..end].iter().collect();
                let _ = write!(result, "{}", inner.yellow());
                i = end.saturating_add(1);
                continue;
            }

            result.push(chars[i]);
            i = i.saturating_add(1);
        }

        result
    }

    /// Find closing `**` starting from position `start`.
    fn find_closing_double_star(chars: &[char], start: usize) -> Option<usize> {
        let len = chars.len();
        let mut i = start;
        while i.saturating_add(1) < len {
            if chars[i] == '*' && chars[i.saturating_add(1)] == '*' {
                return Some(i);
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Find closing `` ` `` starting from position `start`.
    fn find_closing_backtick(chars: &[char], start: usize) -> Option<usize> {
        chars[start..]
            .iter()
            .position(|&c| c == '`')
            .map(|p| p.saturating_add(start))
    }

    /// Render a fenced code block using syntect highlighting.
    fn render_code_block(&self, lang: &str, lines: &[String]) {
        let stdout = io::stdout();
        let mut out = stdout.lock();

        let syntax = if lang.is_empty() {
            None
        } else {
            self.syntax_set.find_syntax_by_token(lang)
        };

        match syntax {
            Some(syn) => {
                let mut highlighter = HighlightLines::new(syn, &self.theme);
                for line in lines {
                    match highlighter.highlight_line(line, &self.syntax_set) {
                        Ok(regions) => {
                            let escaped = as_24_bit_terminal_escaped(&regions, false);
                            let _ = writeln!(out, "{escaped}\x1b[0m");
                        },
                        Err(_) => {
                            // Fallback on highlight error.
                            let _ = writeln!(out, "{}", line.dimmed());
                        },
                    }
                }
            },
            None => {
                // Unknown language — plain dimmed text.
                for line in lines {
                    let _ = writeln!(out, "{}", line.dimmed());
                }
            },
        }
    }
}

impl OutputFormatter for PrettyFormatter {
    fn format_text(&mut self, text: &str) {
        self.text_buffer.push_str(text);
    }

    fn format_tool_start(&mut self, id: &str, name: &str, _args: &Value) {
        // Flush any pending text first.
        self.render_markdown();

        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.blue} {msg}")
                .expect("valid spinner template"),
        );
        spinner.set_message(format!("{}", format!("\u{2699} {name}").bold().blue()));
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));

        self.active_spinners.insert(id.to_string(), spinner);
    }

    fn format_tool_result(&mut self, id: &str, result: &str, is_error: bool) {
        if let Some(spinner) = self.active_spinners.remove(id) {
            spinner.finish_and_clear();
        }

        let stdout = io::stdout();
        let mut out = stdout.lock();
        if is_error {
            let _ = writeln!(out, "{}", result.red());
        } else {
            let _ = writeln!(out, "{}", result.dimmed());
        }
    }

    fn format_error(&mut self, msg: &str) {
        self.render_markdown();
        let stderr = io::stderr();
        let mut err = stderr.lock();
        let _ = writeln!(err, "{}{}", "error: ".red().bold(), msg.red());
    }

    fn format_turn_complete(&mut self) {
        self.render_markdown();
    }

    fn flush_markdown(&mut self) {
        self.render_markdown();
    }
}

// ---------------------------------------------------------------------------
// JsonFormatter
// ---------------------------------------------------------------------------

/// Renders daemon events as newline-delimited JSON.
pub(crate) struct JsonFormatter;

/// Wrapper enum for serialising each event type with a `type` discriminator.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum JsonEvent<'a> {
    Text {
        text: &'a str,
    },
    ToolStart {
        id: &'a str,
        name: &'a str,
        args: &'a Value,
    },
    ToolResult {
        id: &'a str,
        result: &'a str,
        is_error: bool,
    },
    Error {
        message: &'a str,
    },
    TurnComplete,
}

impl JsonFormatter {
    /// Create a new `JsonFormatter`.
    pub(crate) fn new() -> Self {
        Self
    }

    /// Serialise an event and write it to stdout as a single line.
    fn emit(event: &JsonEvent<'_>) {
        if let Ok(json) = serde_json::to_string(event) {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            let _ = writeln!(out, "{json}");
        }
    }
}

impl OutputFormatter for JsonFormatter {
    fn format_text(&mut self, text: &str) {
        Self::emit(&JsonEvent::Text { text });
    }

    fn format_tool_start(&mut self, id: &str, name: &str, args: &Value) {
        Self::emit(&JsonEvent::ToolStart { id, name, args });
    }

    fn format_tool_result(&mut self, id: &str, result: &str, is_error: bool) {
        Self::emit(&JsonEvent::ToolResult {
            id,
            result,
            is_error,
        });
    }

    fn format_error(&mut self, msg: &str) {
        Self::emit(&JsonEvent::Error { message: msg });
    }

    fn format_turn_complete(&mut self) {
        Self::emit(&JsonEvent::TurnComplete);
    }

    fn flush_markdown(&mut self) {
        // JSON formatter does not buffer, nothing to flush.
    }
}

/// Create an `OutputFormatter` for the given format mode.
pub(crate) fn create_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Pretty => Box::new(PrettyFormatter::new()),
        OutputFormat::Json => Box::new(JsonFormatter::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::PrettyFormatter;

    #[test]
    fn pretty_formatter_loads_embedded_syntaxes_and_themes() {
        let formatter = PrettyFormatter::new();

        assert!(formatter.syntax_set.find_syntax_by_token("rust").is_some());
        assert_eq!(formatter.theme.name.as_deref(), Some("Base16 Ocean Dark"));
    }
}
