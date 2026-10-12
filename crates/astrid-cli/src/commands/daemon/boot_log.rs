//! Detached boot diagnostics without creating an unadmitted runtime layout.

use std::process::Stdio;

use anyhow::{Context, Result};

pub(super) struct BootLog {
    temporary: Option<tempfile::TempPath>,
}

pub(super) fn prepare_boot_stderr() -> Result<(Stdio, BootLog)> {
    let home = astrid_core::dirs::AstridHome::resolve().ok();
    prepare_for_home(home.as_ref())
}

fn prepare_for_home(home: Option<&astrid_core::dirs::AstridHome>) -> Result<(Stdio, BootLog)> {
    if let Some(stderr) = home.and_then(initialized_home_stderr) {
        return Ok((stderr, BootLog { temporary: None }));
    }

    // Inheriting stderr here keeps pipe-based callers waiting for EOF for the
    // daemon's entire lifetime. tempfile creates an owner-only file outside
    // the runtime; its path disappears after readiness, while the daemon keeps
    // its open descriptor. Retain it only when startup needs operator recovery.
    let temporary = tempfile::Builder::new()
        .prefix("astrid-daemon-boot-")
        .tempfile()
        .context("failed to create detached daemon boot log")?;
    let (file, path) = temporary.into_parts();
    Ok((
        Stdio::from(file),
        BootLog {
            temporary: Some(path),
        },
    ))
}

/// Capture early lock failures/panics before the tracing subscriber is live.
/// Fresh roots must not acquire `log/` before the kernel admits their layout.
pub(super) fn initialized_home_stderr(home: &astrid_core::dirs::AstridHome) -> Option<Stdio> {
    if !matches!(home.layout_version(), Ok(Some(_))) {
        return None;
    }
    let log_dir = home.log_dir();
    std::fs::create_dir_all(&log_dir).ok()?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    // Boot diagnostics can carry sensitive paths and panic backtraces.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(log_dir.join("daemon-boot.log"))
        .ok()
        .map(Stdio::from)
}

impl BootLog {
    pub(super) fn failure_hint(&mut self) -> Result<String> {
        match self.temporary.take() {
            Some(path) => {
                let path = path
                    .keep()
                    .context("failed to retain daemon boot diagnostics")?;
                Ok(format!(" Check boot log: {}", path.display()))
            },
            None => Ok(super::log_hint()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_home_capture_stays_outside_layout_and_cleans_up() {
        let root = tempfile::tempdir().expect("test root");
        let home = astrid_core::dirs::AstridHome::from_path(root.path().join("home"));
        let (stderr, log) = prepare_for_home(Some(&home)).expect("detached stderr");
        let path = log
            .temporary
            .as_ref()
            .expect("temporary fallback")
            .to_path_buf();
        assert!(path.exists());
        assert!(!path.starts_with(home.root()));
        assert!(!home.root().exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).expect("log").permissions().mode() & 0o777,
                0o600
            );
        }
        drop(stderr);
        drop(log);
        assert!(!path.exists());
    }

    #[test]
    fn failed_boot_retains_capture_file() {
        let (stderr, mut log) = prepare_for_home(None).expect("detached stderr");
        let path = log
            .temporary
            .as_ref()
            .expect("temporary fallback")
            .to_path_buf();
        std::fs::write(&path, "boot failure").expect("captured diagnostics");
        drop(stderr);
        let hint = log.failure_hint().expect("retain log");
        drop(log);
        assert!(hint.contains(&path.display().to_string()));
        assert_eq!(
            std::fs::read_to_string(&path).expect("boot diagnostics"),
            "boot failure"
        );
        std::fs::remove_file(path).expect("remove owned test log");
    }
}
