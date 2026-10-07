//! Invocation-level daemon selection, independent of local file arguments and
//! the project context carried by a client session.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};

static SELECTION: OnceLock<Option<DaemonWorkspace>> = OnceLock::new();

/// An explicit daemon root cannot change meaning when MCP enters its project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaemonWorkspace(PathBuf);

impl DaemonWorkspace {
    pub(crate) fn new(path: PathBuf) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("daemon workspace must be an absolute path".to_owned());
        }
        // Fresh workspaces need not exist yet. The existing checked workspace
        // fingerprint validates the state path before daemon attachment.
        Ok(Self(path))
    }
}

pub(crate) fn initialize(
    selection: Option<DaemonWorkspace>,
) -> Result<(), Option<DaemonWorkspace>> {
    SELECTION.set(selection)
}

pub(crate) fn selected(requested: Option<&Path>) -> Result<PathBuf> {
    resolve(SELECTION.get().and_then(Option::as_ref), requested)
}

fn resolve(configured: Option<&DaemonWorkspace>, requested: Option<&Path>) -> Result<PathBuf> {
    if let Some(root) = configured {
        return Ok(root.0.clone());
    }
    if let Some(root) = requested {
        return Ok(root.to_path_buf());
    }
    std::env::current_dir().context("failed to resolve daemon workspace from current directory")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn explicit_root_wins_without_changing_caller_directory() {
        let caller = std::env::current_dir().expect("caller directory");
        let fixture = tempfile::tempdir().expect("daemon root");
        let root = DaemonWorkspace::new(fixture.path().to_path_buf()).expect("absolute root");
        assert_eq!(resolve(Some(&root), Some(&caller)).unwrap(), fixture.path());
        assert_eq!(std::env::current_dir().unwrap(), caller);
        assert_eq!(resolve(None, Some(&caller)).unwrap(), caller);
        assert_eq!(resolve(None, None).unwrap(), caller);
    }

    #[test]
    fn relative_root_is_rejected_before_a_client_can_change_directory() {
        assert!(DaemonWorkspace::new(PathBuf::from("relative/runtime")).is_err());
    }

    #[test]
    fn cli_keeps_daemon_selection_separate_from_mcp_project_context() {
        let fixture = tempfile::tempdir().expect("daemon root");
        let parsed = crate::cli::Cli::try_parse_from([
            std::ffi::OsStr::new("astrid"),
            std::ffi::OsStr::new("--daemon-workspace"),
            fixture.path().as_os_str(),
            std::ffi::OsStr::new("mcp"),
            std::ffi::OsStr::new("serve"),
            std::ffi::OsStr::new("--workspace"),
            std::ffi::OsStr::new("./host-project"),
        ])
        .expect("separate workspace selectors");
        assert_eq!(parsed.daemon_workspace.unwrap().0, fixture.path());
        assert!(matches!(
            parsed.command,
            Some(crate::cli::Commands::Mcp {
                command: crate::cli::McpCommands::Serve { workspace: Some(workspace), .. }
            }) if workspace == Path::new("./host-project")
        ));
    }
}
