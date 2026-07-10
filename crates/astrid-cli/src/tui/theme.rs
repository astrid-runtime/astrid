//! Color theme and spinner animation for the TUI.

use ratatui::style::Color;

/// Spinner animation style.
#[derive(Debug, Clone, Copy, Default)]
#[expect(dead_code)]
pub(crate) enum SpinnerStyle {
    #[default]
    Stellar,
    Braille,
    Dots,
}

impl SpinnerStyle {
    pub(crate) fn frames(self) -> &'static [&'static str] {
        match self {
            Self::Stellar => &["✧", "✦", "✶", "✴", "✸", "✴", "✶", "✦"],
            Self::Braille => &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            Self::Dots => &["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"],
        }
    }

    /// Get the current frame for a given elapsed time.
    pub(crate) fn frame_at(self, elapsed_ms: u128) -> &'static str {
        let frames = self.frames();
        let interval = 120u128;
        #[expect(clippy::arithmetic_side_effects)]
        // constant divisor, modulo by non-empty frames array
        let idx = (elapsed_ms / interval % frames.len() as u128) as usize;
        frames[idx]
    }
}

/// Color theme — primary text inherits the terminal foreground.
#[derive(Debug, Clone)]
pub(crate) struct Theme {
    /// User input text
    pub user: Color,
    /// Assistant response text
    pub assistant: Color,
    /// Muted/metadata text
    pub muted: Color,
    /// Tool names
    pub tool: Color,
    /// Success indicators
    pub success: Color,
    /// Warning indicators
    pub warning: Color,
    /// Error indicators
    pub error: Color,
    /// Thinking indicator
    pub thinking: Color,
    /// Border color
    pub border: Color,
    /// Cursor color
    pub cursor: Color,
    /// Diff added lines
    pub diff_added: Color,
    /// Diff removed lines
    pub diff_removed: Color,
    /// Diff context lines
    pub diff_context: Color,
    /// Spinner animation style
    pub spinner: SpinnerStyle,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            user: Color::Reset,
            assistant: Color::Reset,
            muted: Color::DarkGray,
            tool: Color::Cyan,
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            thinking: Color::Magenta,
            border: Color::DarkGray,
            cursor: Color::Reset,
            diff_added: Color::Green,
            diff_removed: Color::Red,
            diff_context: Color::DarkGray,
            spinner: SpinnerStyle::Stellar,
        }
    }
}

#[cfg(test)]
mod tests {
    use ratatui::style::Color;

    use super::Theme;

    #[test]
    fn primary_text_inherits_the_terminal_foreground() {
        let theme = Theme::default();

        assert_eq!(theme.user, Color::Reset);
        assert_eq!(theme.assistant, Color::Reset);
        assert_eq!(theme.cursor, Color::Reset);
    }
}
