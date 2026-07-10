//! Rustyline-based REPL editor with history and completion.

use std::path::PathBuf;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::history::DefaultHistory;
use rustyline::{
    CompletionType, Config, Context, EditMode, Editor, Helper, Highlighter, Validator,
};

/// Slash commands available in the REPL.
const SLASH_COMMANDS: &[&str] = &[
    "/help",
    "/clear",
    "/info",
    "/context",
    "/servers",
    "/tools",
    "/allowances",
    "/budget",
    "/audit",
    "/compact",
    "/save",
    "/sessions",
];

/// Events returned by the REPL editor.
pub(crate) enum ReadlineEvent {
    /// A complete line of input (possibly multi-line, joined).
    Line(String),
    /// The user pressed Ctrl+C, cancelling current input.
    Interrupted,
    /// The user pressed Ctrl+D, signalling end-of-input.
    Eof,
}

/// Helper that provides slash-command completion and history hints.
#[derive(Helper, Validator, Highlighter)]
struct ReplHelper {
    hinter: HistoryHinter,
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // Only complete if the cursor is at a word that starts with '/'
        // and that word begins at the start of the line or after whitespace.
        let prefix = &line[..pos];
        let word_start = prefix
            .rfind(char::is_whitespace)
            .map_or(0, |i| i.saturating_add(1));
        let word = &prefix[word_start..];

        if !word.starts_with('/') {
            return Ok((pos, Vec::new()));
        }

        let matches: Vec<Pair> = SLASH_COMMANDS
            .iter()
            .filter(|cmd| cmd.starts_with(word))
            .map(|cmd| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();

        Ok((word_start, matches))
    }
}

impl Hinter for ReplHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

/// Rustyline-based REPL editor with command history and tab completion.
pub(crate) struct ReplEditor {
    editor: Editor<ReplHelper, DefaultHistory>,
    history_path: PathBuf,
}

impl ReplEditor {
    /// Create a new REPL editor.
    ///
    /// Loads command history from `~/.astrid/history` (creating the file if
    /// it does not yet exist) and configures tab completion for slash commands.
    pub(crate) fn new() -> anyhow::Result<Self> {
        let home = astrid_core::dirs::AstridHome::resolve()?;
        home.ensure()?;
        let history_path = home.root().join("history");

        // Ensure the history file exists so rustyline doesn't error on first load.
        if !history_path.exists() {
            std::fs::write(&history_path, "")?;
        }

        let config = Config::builder()
            .history_ignore_dups(true)?
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Emacs)
            .auto_add_history(true)
            .build();

        let helper = ReplHelper {
            hinter: HistoryHinter::new(),
        };

        let mut editor = Editor::with_config(config)?;
        editor.set_helper(Some(helper));
        let _ = editor.load_history(&history_path);

        Ok(Self {
            editor,
            history_path,
        })
    }

    /// Read a line of input from the user.
    ///
    /// Supports multi-line input: when a line ends with `\`, the backslash is
    /// stripped and the next line is appended (separated by a newline). The
    /// continuation prompt is `  ` (two spaces).
    ///
    /// Returns [`ReadlineEvent::Interrupted`] on Ctrl+C and
    /// [`ReadlineEvent::Eof`] on Ctrl+D.
    pub(crate) fn readline(&mut self) -> ReadlineEvent {
        let continuation = "  ";

        let mut accumulated = String::new();
        let mut is_continuation = false;

        loop {
            let line = if is_continuation {
                self.editor.readline(continuation)
            } else {
                self.editor.readline(&("> ", "\x1b[1;32m> \x1b[0m"))
            };

            match line {
                Ok(line) => {
                    if line.ends_with('\\') {
                        // Strip trailing backslash and continue to next line.
                        accumulated.push_str(&line[..line.len().saturating_sub(1)]);
                        accumulated.push('\n');
                        is_continuation = true;
                        continue;
                    }

                    accumulated.push_str(&line);

                    // Save history after each complete input.
                    let _ = self.editor.save_history(&self.history_path);

                    return ReadlineEvent::Line(accumulated);
                },
                Err(ReadlineError::Interrupted) => {
                    // Ctrl+C: discard any accumulated continuation and signal interrupt.
                    return ReadlineEvent::Interrupted;
                },
                Err(ReadlineError::Eof | _) => {
                    // Ctrl+D or any I/O error → EOF.
                    return ReadlineEvent::Eof;
                },
            }
        }
    }
}
