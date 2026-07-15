//! Hook discovery - find hooks from standard locations.

use astrid_core::dirs::WorkspaceLayout;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::hook::Hook;

/// Errors that can occur during hook discovery.
#[derive(Debug, Error)]
pub(crate) enum DiscoveryError {
    /// Failed to read directory.
    #[error("failed to read directory {path}: {message}")]
    DirectoryRead {
        /// The path that failed.
        path: PathBuf,
        /// Error message.
        message: String,
    },

    /// Failed to read hook file.
    #[error("failed to read hook file {path}: {message}")]
    FileRead {
        /// The path that failed.
        path: PathBuf,
        /// Error message.
        message: String,
    },

    /// Failed to parse hook file.
    #[error("failed to parse hook file {path}: {message}")]
    Parse {
        /// The path that failed.
        path: PathBuf,
        /// Error message.
        message: String,
    },
}

/// Result type for discovery operations.
pub(crate) type DiscoveryResult<T> = Result<T, DiscoveryError>;

/// Standard hook file names.
pub(crate) const HOOK_FILE_NAMES: &[&str] = &["HOOK.toml", "hook.toml", "hooks.toml"];

/// Discover hooks from standard locations.
///
/// This function looks for hooks in:
/// 1. Hooks under the selected project state directory
/// 2. Any additional paths provided in `extra_paths`
///
/// Callers should pass the user-level hooks directory (e.g.
/// `AstridHome::hooks_dir()`) via `extra_paths` rather than relying
/// on hard-coded platform paths.
pub(crate) fn discover_hooks(extra_paths: Option<&[PathBuf]>) -> Vec<Hook> {
    discover_hooks_with_layout(extra_paths, &WorkspaceLayout::default())
}

pub(crate) fn discover_hooks_with_layout(
    extra_paths: Option<&[PathBuf]>,
    workspace_layout: &WorkspaceLayout,
) -> Vec<Hook> {
    let workspace_root = std::env::current_dir().ok();
    discover_hooks_in_workspace(extra_paths, workspace_root.as_deref(), workspace_layout)
}

pub(crate) fn discover_hooks_in_workspace(
    extra_paths: Option<&[PathBuf]>,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> Vec<Hook> {
    let mut hooks = Vec::new();

    if let Some(workspace_root) = workspace_root {
        let checked = workspace_layout
            .resolve(workspace_root)
            .and_then(|selection| selection.verify_tree("hooks").map(|dir| (selection, dir)));
        if let Ok((selection, local_hooks_dir)) = checked {
            if local_hooks_dir.exists() {
                info!(path = %local_hooks_dir.display(), "Discovering hooks from local directory");
                match load_hooks_from_dir(&local_hooks_dir) {
                    Ok(found) => hooks.extend(found),
                    Err(e) => warn!(error = %e, "Failed to load hooks from local directory"),
                }
            }
            if let Err(error) = selection.verify_tree("hooks") {
                warn!(%error, "Workspace changed during hook discovery; discarding workspace hooks");
                hooks.clear();
            }
        } else if let Err(error) = checked {
            warn!(%error, "Unsafe workspace hook path; skipping workspace hooks");
        }
    }

    // Look in extra paths
    if let Some(paths) = extra_paths {
        for path in paths {
            if path.exists() {
                info!(path = %path.display(), "Discovering hooks from custom path");
                match load_hooks_from_dir(path) {
                    Ok(found) => hooks.extend(found),
                    Err(e) => warn!(error = %e, "Failed to load hooks from custom path"),
                }
            }
        }
    }

    info!(count = hooks.len(), "Discovered hooks");
    hooks
}

/// Load hooks from a directory.
///
/// This function looks for:
/// - Direct hook files (HOOK.toml, hook.toml)
/// - Subdirectories containing hook files
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub(crate) fn load_hooks_from_dir(dir: &Path) -> DiscoveryResult<Vec<Hook>> {
    let mut hooks = Vec::new();

    let entries = std::fs::read_dir(dir).map_err(|e| DiscoveryError::DirectoryRead {
        path: dir.to_path_buf(),
        message: e.to_string(),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| DiscoveryError::DirectoryRead {
            path: dir.to_path_buf(),
            message: e.to_string(),
        })?;

        let path = entry.path();

        if path.is_dir() {
            // Look for hook file in subdirectory
            for hook_file in HOOK_FILE_NAMES {
                let hook_path = path.join(hook_file);
                if hook_path.exists() {
                    match load_hook(&hook_path) {
                        Ok(hook) => {
                            debug!(path = %hook_path.display(), "Loaded hook");
                            hooks.push(hook);
                        },
                        Err(e) => {
                            warn!(
                                path = %hook_path.display(),
                                error = %e,
                                "Failed to load hook"
                            );
                        },
                    }
                    break; // Only load first matching file
                }
            }
        } else if path.is_file()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
            && HOOK_FILE_NAMES.contains(&name)
        {
            match load_hook(&path) {
                Ok(hook) => {
                    debug!(path = %path.display(), "Loaded hook");
                    hooks.push(hook);
                },
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to load hook");
                },
            }
        }
    }

    Ok(hooks)
}

/// Load a single hook from a TOML file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub(crate) fn load_hook(path: &Path) -> DiscoveryResult<Hook> {
    let content = std::fs::read_to_string(path).map_err(|e| DiscoveryError::FileRead {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let hook: Hook = toml::from_str(&content).map_err(|e| DiscoveryError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    Ok(hook)
}

/// Save a hook to a TOML file.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub(crate) fn save_hook(hook: &Hook, path: &Path) -> DiscoveryResult<()> {
    let content = toml::to_string_pretty(hook).map_err(|e| DiscoveryError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    std::fs::write(path, content).map_err(|e| DiscoveryError::FileRead {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    Ok(())
}

/// Hooks directory in a workspace.
#[must_use]
pub(crate) fn workspace_hooks_dir(workspace_root: &Path) -> PathBuf {
    workspace_hooks_dir_with_layout(workspace_root, &WorkspaceLayout::default())
}

#[must_use]
pub(crate) fn workspace_hooks_dir_with_layout(
    workspace_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> PathBuf {
    workspace_layout.hooks_dir(workspace_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::{HookEvent, HookHandler};
    use tempfile::TempDir;

    #[test]
    fn test_load_hook_from_toml() {
        let temp_dir = TempDir::new().unwrap();
        let hook_path = temp_dir.path().join("HOOK.toml");

        let hook = Hook::new(HookEvent::SessionStart)
            .with_name("test-hook")
            .with_handler(HookHandler::command("echo"));

        // Save the hook
        save_hook(&hook, &hook_path).unwrap();

        // Load it back
        let loaded = load_hook(&hook_path).unwrap();

        assert_eq!(loaded.name, Some("test-hook".to_string()));
        assert_eq!(loaded.event, HookEvent::SessionStart);
    }

    #[test]
    fn test_load_hooks_from_dir() {
        let temp_dir = TempDir::new().unwrap();

        // Create a subdirectory with a hook
        let subdir = temp_dir.path().join("my-hook");
        std::fs::create_dir(&subdir).unwrap();

        let hook = Hook::new(HookEvent::PreToolCall)
            .with_name("sub-hook")
            .with_handler(HookHandler::command("echo"));

        save_hook(&hook, &subdir.join("HOOK.toml")).unwrap();

        // Load hooks from the directory
        let hooks = load_hooks_from_dir(temp_dir.path()).unwrap();

        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].name, Some("sub-hook".to_string()));
    }

    #[test]
    fn test_discover_hooks_empty() {
        // Should not panic even with no hooks
        let hooks = discover_hooks(None);
        // May find system hooks, so just check it doesn't panic
        let _ = hooks;
    }

    #[test]
    fn workspace_hooks_use_injected_layout() {
        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        assert_eq!(
            workspace_hooks_dir_with_layout(Path::new("/workspace"), &layout),
            PathBuf::from("/workspace/.alternate-runtime/hooks")
        );
    }

    #[test]
    fn discovery_uses_explicit_workspace_root() {
        let workspace = TempDir::new().unwrap();
        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        let hooks_dir = layout.hooks_dir(workspace.path());
        std::fs::create_dir_all(&hooks_dir).unwrap();
        save_hook(
            &Hook::new(HookEvent::SessionStart).with_name("selected"),
            &hooks_dir.join("HOOK.toml"),
        )
        .unwrap();

        let hooks = discover_hooks_in_workspace(None, Some(workspace.path()), &layout);

        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].name.as_deref(), Some("selected"));
    }

    #[cfg(unix)]
    #[test]
    fn discovery_skips_workspace_with_symlinked_hook_file() {
        use std::os::unix::fs::symlink;

        let workspace = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let hooks = workspace.path().join(".astrid/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        let target = outside.path().join("HOOK.toml");
        std::fs::write(&target, "event = 'session-start'\n").unwrap();
        symlink(target, hooks.join("HOOK.toml")).unwrap();

        assert!(
            discover_hooks_in_workspace(None, Some(workspace.path()), &WorkspaceLayout::default())
                .is_empty()
        );
    }
}
