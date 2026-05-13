//! `astrid completions <shell>` — emit shell completion scripts.

use std::io;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::Shell;

use crate::cli::Cli;

#[derive(Args, Debug, Clone)]
pub(crate) struct CompletionsArgs {
    /// Target shell.
    #[arg(value_enum)]
    pub shell: ShellArg,
}

/// Wrapper enum so we can derive `clap::ValueEnum` and accept the
/// canonical shell names (`bash`, `zsh`, `fish`, `powershell`, `elvish`).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ShellArg {
    /// Bash.
    Bash,
    /// Zsh.
    Zsh,
    /// Fish.
    Fish,
    /// Elvish.
    Elvish,
    /// `PowerShell`.
    Powershell,
}

impl From<ShellArg> for Shell {
    fn from(s: ShellArg) -> Self {
        match s {
            ShellArg::Bash => Self::Bash,
            ShellArg::Zsh => Self::Zsh,
            ShellArg::Fish => Self::Fish,
            ShellArg::Elvish => Self::Elvish,
            ShellArg::Powershell => Self::PowerShell,
        }
    }
}

/// Entry point for `astrid completions`.
#[expect(clippy::unnecessary_wraps, reason = "uniform dispatcher signature")]
pub(crate) fn run(args: &CompletionsArgs) -> Result<ExitCode> {
    let mut cmd = Cli::command();
    let bin = cmd.get_name().to_string();
    clap_complete::generate(Shell::from(args.shell), &mut cmd, bin, &mut io::stdout());
    Ok(ExitCode::SUCCESS)
}
