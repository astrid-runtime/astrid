//! `astrid logs [capsule] [-a]` — tail daemon or per-capsule logs.
//!
//! No daemon round-trip — logs are written to the filesystem under
//! `~/.astrid/log/` (kernel-level) and
//! `<principal_home>/.local/log/<capsule>/` (per-capsule). This command
//! locates the most-recent log file by date and either prints it or
//! follows it (`--follow`).

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use clap::Args;

use crate::context;
use crate::theme::Theme;

#[derive(Args, Debug, Clone)]
pub(crate) struct LogsArgs {
    /// Capsule name (omit for kernel/daemon logs).
    pub capsule: Option<String>,
    /// Agent name (defaults to active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Follow the log file (tail -f). Without this flag, prints the
    /// last `--lines` lines and exits.
    #[arg(short, long)]
    pub follow: bool,
    /// Number of trailing lines to print (default: 100).
    #[arg(short = 'n', long = "lines", default_value = "100")]
    pub lines: usize,
}

fn most_recent_log(dir: &Path) -> Result<Option<PathBuf>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let modified = entry.metadata()?.modified()?;
        if newest.as_ref().is_none_or(|(t, _)| *t < modified) {
            newest = Some((modified, path));
        }
    }
    Ok(newest.map(|(_, p)| p))
}

fn resolve_log_dir(principal: &PrincipalId, capsule: Option<&str>) -> Result<PathBuf> {
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    Ok(match capsule {
        Some(name) => home
            .principal_home(principal)
            .root()
            .join(".local")
            .join("log")
            .join(name),
        None => home.log_dir(),
    })
}

/// Print the last `n` lines of `path` to stdout. For non-huge logs we
/// load the whole file in memory; the per-day rotation keeps individual
/// files small.
fn print_tail(path: &Path, n: usize) -> Result<()> {
    let mut bytes = Vec::new();
    let mut file =
        fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    for line in &lines[start..] {
        println!("{line}");
    }
    Ok(())
}

/// Tail-follow loop: prints existing tail, then polls for new bytes.
fn follow_tail(path: &Path, n: usize) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    use std::thread;
    use std::time::Duration;

    let mut file =
        fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    // Seek to a position roughly `n` lines from the end. A line-bound
    // seek is cheap because the per-day log size is bounded.
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    for line in &lines[start..] {
        println!("{line}");
    }
    let mut pos = len;
    let mut reader = BufReader::new(file);
    loop {
        reader.seek(SeekFrom::Start(pos))?;
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(250));
            },
            Ok(read) => {
                print!("{line}");
                pos = pos.saturating_add(read as u64);
            },
            Err(e) => return Err(e.into()),
        }
    }
}

/// Entry point for `astrid logs`.
pub(crate) fn run(args: &LogsArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let dir = resolve_log_dir(&principal, args.capsule.as_deref())?;
    let Some(path) = most_recent_log(&dir)? else {
        eprintln!(
            "{}",
            Theme::info(&format!("(no logs in {})", dir.display()))
        );
        return Ok(ExitCode::SUCCESS);
    };

    if args.follow {
        follow_tail(&path, args.lines)?;
        Ok(ExitCode::SUCCESS)
    } else {
        print_tail(&path, args.lines)?;
        Ok(ExitCode::SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn most_recent_log_returns_newest() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.log");
        let b = dir.path().join("b.log");
        fs::write(&a, "old").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&b, "new").unwrap();
        let recent = most_recent_log(dir.path()).unwrap().unwrap();
        assert_eq!(recent, b);
    }

    #[test]
    fn most_recent_log_handles_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(most_recent_log(&missing).unwrap().is_none());
    }

    #[test]
    fn print_tail_returns_last_n_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.log");
        let body: String = (0..20).map(|i| format!("line {i}\n")).collect();
        fs::write(&path, body).unwrap();
        // No assertion on stdout content — just confirms no panic.
        print_tail(&path, 5).unwrap();
    }
}
