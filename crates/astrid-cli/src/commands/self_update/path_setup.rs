//! Private PATH setup for Astrid's account-level install.
//!
//! Startup-file edits and the default binary directory are shared account
//! state. An explicit `ASTRID_HOME` is an isolation boundary, so it must be
//! resolved before either side effect can happen; failure to classify it as
//! the default is a reason to do nothing, never a reason to guess.

use std::io;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::theme::Theme;

/// Return the account-level Astrid home used when `ASTRID_HOME` is absent.
pub(super) fn default_astrid_home_path() -> io::Result<PathBuf> {
    #[cfg(windows)]
    return astrid_core::platform_fs::default_astrid_home_root();

    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "HOME environment variable is not set",
            )
        })?;
        Ok(PathBuf::from(home).join(".astrid"))
    }
}

/// Decide whether this run may touch account-level PATH state.
///
/// An absent `ASTRID_HOME` means the runtime chose the account home. An
/// explicit path is allowed only when it equals that home exactly. Any other
/// explicit selection -- including an invalid or non-UTF-8 value -- stays a
/// private runtime home: return before creating `bin` or reading or writing a
/// shell profile.
pub(super) fn shell_profile_setup_wanted(
    astrid_home: Option<&Path>,
    default_home: Option<&Path>,
) -> bool {
    let Some(home) = astrid_home else {
        return true;
    };

    default_home.is_some_and(|default| home == default)
}

/// The binary directory belonging to the resolved Astrid home.
pub(super) fn astrid_bin_dir() -> anyhow::Result<PathBuf> {
    let home = astrid_core::dirs::AstridHome::resolve()?;
    Ok(home.root().join("bin"))
}

/// Check if a directory is already in the current PATH.
pub(super) fn is_in_path(dir: &Path) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|entry| entry == dir))
}

/// Detect the user's shell RC file.
pub(super) fn detect_shell_rc() -> Option<PathBuf> {
    let home = directories::BaseDirs::new()?.home_dir().to_path_buf();
    let shell = std::env::var("SHELL").unwrap_or_default();

    if shell.ends_with("zsh") {
        Some(home.join(".zshrc"))
    } else if shell.ends_with("bash") {
        // Prefer .bashrc on Linux, .bash_profile on macOS
        let bashrc = home.join(".bashrc");
        let profile = home.join(".bash_profile");
        if cfg!(target_os = "macos") && profile.exists() {
            Some(profile)
        } else if bashrc.exists() {
            Some(bashrc)
        } else {
            Some(home.join(".bashrc"))
        }
    } else if shell.ends_with("fish") {
        Some(home.join(".config/fish/config.fish"))
    } else {
        // Fallback: try zshrc (macOS default), then bashrc
        let zshrc = home.join(".zshrc");
        if zshrc.exists() {
            Some(zshrc)
        } else {
            Some(home.join(".bashrc"))
        }
    }
}

/// True if the match starting at byte `start` sits on a `#`-commented
/// (inert) rc line -- a `#` appears between the line start and the match.
///
/// A commented line is a no-op in the shell, so treating a match inside one
/// as "already configured" would silently skip the real PATH setup. Both
/// match paths in [`rc_configures_path`] consult this so a commented block or
/// token never counts.
pub(super) fn match_is_commented(rc: &str, start: usize) -> bool {
    let line_start = rc[..start].rfind('\n').map_or(0, |nl| nl.saturating_add(1));
    rc[line_start..start].contains('#')
}

/// Whether `rc_contents` already puts the bin dir on PATH, so a second run
/// must not append a duplicate block.
///
/// Returns "already configured" (skip the append) only when EITHER the exact
/// block we emit (`export_line`) is present -- the reliable idempotency
/// signal, since we always write it verbatim -- OR `bin_str` appears as a
/// WHOLE path component: bounded on both sides by a shell PATH-list
/// separator. A bare substring match must NOT count: an rc containing
/// `.astrid/bin_backup` or `.astrid/bin/sub` would otherwise make the guard
/// skip the real `.astrid/bin` setup and silently leave astrid off PATH. A
/// match on a `#`-commented (inert) line is likewise NOT a match, on both
/// paths. When unsure we err toward ADDING the block -- a duplicate PATH
/// entry is harmless; a silent skip is not. Pure over its inputs so the
/// guarantee is unit-testable without a real shell rc.
pub(super) fn rc_configures_path(rc_contents: &str, bin_str: &str, export_line: &str) -> bool {
    // Our exact block is the authoritative "already done" marker -- unless it
    // is commented out, in which case it is inert and we must add a live one.
    if let Some(start) = rc_contents.find(export_line)
        && !match_is_commented(rc_contents, start)
    {
        return true;
    }
    if bin_str.is_empty() {
        return false;
    }

    // A PATH entry is bounded by these separators in a shell rc line. The
    // leading set admits assignment/grouping openers (`=`, `(`); the trailing
    // set admits a grouping close (`)`). A following `/`, alphanumeric, `_`,
    // or `-` means `bin_str` is only a prefix of a longer path -- NOT a match.
    let is_lead = |c: char| matches!(c, ':' | '"' | '\'' | '=' | '(' | ' ' | '\t' | '\n' | '\r');
    let is_trail = |c: char| matches!(c, ':' | '"' | '\'' | ')' | ' ' | '\t' | '\n' | '\r');

    let mut from = 0;
    while let Some(rel) = rc_contents[from..].find(bin_str) {
        let start = from.saturating_add(rel);
        let end = start.saturating_add(bin_str.len());

        // Skip a match inside a commented-out line, e.g.
        // `# export PATH=".../.astrid/bin:$PATH"`, and keep scanning.
        if match_is_commented(rc_contents, start) {
            from = end;
            continue;
        }

        let lead_ok = start == 0
            || rc_contents[..start]
                .chars()
                .next_back()
                .is_some_and(is_lead);
        let trail_ok =
            end == rc_contents.len() || rc_contents[end..].chars().next().is_some_and(is_trail);
        if lead_ok && trail_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Ensure the account-level binary directory is on PATH after `astrid init`.
///
/// This is the only safe order for the home boundary: classify
/// `ASTRID_HOME` first, then create `bin`, then inspect or update the shell
/// startup file. An explicit non-default, invalid, or non-UTF-8 home leaves
/// both `bin` and the profile untouched.
pub(crate) fn ensure_path_setup() -> anyhow::Result<()> {
    let explicit_home = std::env::var_os("ASTRID_HOME").map(PathBuf::from);
    let default_home = default_astrid_home_path().ok();
    if !shell_profile_setup_wanted(explicit_home.as_deref(), default_home.as_deref()) {
        return Ok(());
    }

    let bin_dir = astrid_bin_dir()?;
    std::fs::create_dir_all(&bin_dir)?;

    if is_in_path(&bin_dir) {
        return Ok(());
    }

    let bin_str = bin_dir.to_string_lossy();
    let Some(rc_file) = detect_shell_rc() else {
        println!(
            "{}",
            Theme::warning(&format!("Add {bin_str} to your PATH manually."))
        );
        return Ok(());
    };

    let export_line = if rc_file.to_string_lossy().contains("fish") {
        format!("fish_add_path {bin_str}")
    } else {
        format!("export PATH=\"{bin_str}:$PATH\"")
    };

    // Idempotency: if the rc file already wires the bin dir onto PATH, do
    // NOT append a second block. `astrid init` (and the first-run auto-init)
    // calls this on every run, so an unguarded append would accumulate a
    // duplicate `# Astrid OS` block per invocation.
    if let Ok(contents) = std::fs::read_to_string(&rc_file)
        && rc_configures_path(&contents, &bin_str, &export_line)
    {
        return Ok(()); // Already configured, just not sourced yet
    }

    // Prompt if interactive.
    if std::io::stdin().is_terminal() {
        eprint!(
            "\n{bin_str} is not in your PATH. Add it to {}? [Y/n] ",
            rc_file.display()
        );
        std::io::Write::flush(&mut std::io::stderr())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() && !input.eq_ignore_ascii_case("y") {
            println!(
                "{}",
                Theme::dimmed(&format!("Skipped. Add manually: {export_line}"))
            );
            return Ok(());
        }
    }

    // Append to RC file.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_file)?;
    std::io::Write::write_all(
        &mut file,
        format!("\n# Astrid OS\n{export_line}\n").as_bytes(),
    )?;

    println!(
        "{}",
        Theme::success(&format!("Added to {}", rc_file.display()))
    );
    println!(
        "  Run: {} (or restart your terminal)",
        Theme::dimmed(&format!("source {}", rc_file.display()))
    );

    Ok(())
}
