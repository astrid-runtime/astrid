//! Rustyline-based REPL editor with history and completion.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

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
const MAX_HISTORY_BYTES: u64 = 8 * 1024 * 1024;

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
    /// Loads command history from the operator-only `log/cli/history` path
    /// (creating the private file if it does not yet exist) and configures tab
    /// completion for slash commands. History is never stored in a principal
    /// home or capsule-visible namespace.
    pub(crate) fn new() -> anyhow::Result<Self> {
        let home = astrid_core::dirs::AstridHome::resolve()?;
        home.ensure()?;
        let history_dir = home.log_dir().join("cli");
        astrid_core::platform_fs::ensure_private_directory(&history_dir)?;
        let history_path = history_dir.join("history");
        migrate_legacy_history(&history_path, &home.root().join("history"))?;

        // Ensure the history file exists and is a regular, private, no-follow
        // file so rustyline cannot be redirected through a user-controlled
        // symlink or special entry.
        match std::fs::symlink_metadata(&history_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                anyhow::bail!(
                    "REPL history path is not a regular file: {}",
                    history_path.display()
                );
            },
            Ok(_) => {
                astrid_core::platform_fs::verify_no_redirects(&history_path)?;
                astrid_core::platform_fs::restrict_private_file(&history_path)?;
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                astrid_core::platform_fs::atomic_write_private_file(&history_path, b"")?;
            },
            Err(error) => return Err(error.into()),
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
                    let _ = astrid_core::platform_fs::restrict_private_file(&self.history_path);

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

/// Move the legacy operator history out of the retired top-level Astrid root.
///
/// The old file is accepted only as a regular, no-follow file and is bounded
/// before being copied. If both locations exist, differing bytes fail closed;
/// an operator must resolve the ambiguity rather than silently lose commands.
fn migrate_legacy_history(new_path: &Path, legacy_path: &Path) -> io::Result<()> {
    let legacy_exists = match std::fs::symlink_metadata(legacy_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "legacy REPL history is not a regular file: {}",
                        legacy_path.display()
                    ),
                ));
            }
            astrid_core::platform_fs::verify_no_redirects(legacy_path)?;
            true
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if !legacy_exists {
        return Ok(());
    }
    let legacy = read_history_bounded(legacy_path)?;
    match std::fs::symlink_metadata(new_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "REPL history path is not a regular file: {}",
                    new_path.display()
                ),
            ));
        },
        Ok(_) => {
            astrid_core::platform_fs::verify_no_redirects(new_path)?;
            let current = read_history_bounded(new_path)?;
            if current != legacy {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "legacy and operator REPL histories differ; refusing to merge",
                ));
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            astrid_core::platform_fs::atomic_write_private_file(new_path, &legacy)?;
        },
        Err(error) => return Err(error),
    }
    std::fs::remove_file(legacy_path)?;
    Ok(())
}

fn read_history_bounded(path: &Path) -> io::Result<Vec<u8>> {
    astrid_core::platform_fs::verify_no_redirects(path)?;
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_HISTORY_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_HISTORY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("REPL history exceeds {MAX_HISTORY_BYTES} bytes"),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::migrate_legacy_history;

    #[test]
    fn legacy_history_moves_to_operator_log() {
        let root = tempfile::tempdir().expect("tempdir");
        let legacy = root.path().join("history");
        let current = root.path().join("log/cli/history");
        std::fs::create_dir_all(current.parent().unwrap()).unwrap();
        std::fs::write(&legacy, b"/help\nhello\n").unwrap();

        migrate_legacy_history(&current, &legacy).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"/help\nhello\n");
        assert!(!legacy.exists());
    }

    #[cfg(unix)]
    #[test]
    fn redirected_legacy_history_is_rejected() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("tempdir");
        let outside = root.path().join("outside");
        let legacy = root.path().join("history");
        let current = root.path().join("log/cli/history");
        std::fs::write(&outside, b"secret").unwrap();
        symlink(&outside, &legacy).unwrap();

        assert!(migrate_legacy_history(&current, &legacy).is_err());
        assert!(!current.exists());
    }
}
