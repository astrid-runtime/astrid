//! Runtime-media checks shared by capsule native processes and native MCP.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use astrid_core::dirs::AstridHome;

use super::{ProcessSandboxConfig, SandboxCommand, SandboxPrefix, resolve_sandbox_path};

pub(super) fn sensitive_astrid_paths() -> io::Result<Vec<PathBuf>> {
    let home = AstridHome::resolve()?;
    require_private_volume_links(&home)?;
    Ok(SandboxCommand::sensitive_astrid_paths_in(&home))
}

impl SandboxPrefix {
    /// Build a standard command while retaining verified Linux bind sources
    /// until Bubblewrap consumes them. Callers can convert it to Tokio.
    #[must_use]
    pub fn into_command(self) -> std::process::Command {
        let mut command = std::process::Command::new(&self.program);
        command.args(&self.args);
        #[cfg(target_os = "linux")]
        super::bwrap::inherit_bind_sources(&mut command, self.bind_sources);
        command
    }
}

impl ProcessSandboxConfig {
    /// Hide Astrid's runtime home and reject grants that reopen its state.
    #[must_use]
    pub fn with_protected_runtime_home(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.hidden_paths.push(path.clone());
        self.protected_runtime_home = Some(path);
        self
    }

    pub(super) fn validate_protected_runtime_grants(&self) -> io::Result<()> {
        let Some(root) = &self.protected_runtime_home else {
            return Ok(());
        };
        let home = AstridHome::from_path(root);
        require_private_volume_links(&home)?;
        validate_mcp_grants(
            &home,
            std::iter::once(self.writable_root.as_path())
                .chain(self.extra_read_paths.iter().map(PathBuf::as_path))
                .chain(self.extra_write_paths.iter().map(PathBuf::as_path))
                .chain(
                    self.ro_injections
                        .iter()
                        .map(|injection| injection.target.as_path()),
                ),
        )
    }
}

/// A second name for a backing volume defeats pathname-only sandbox masks.
/// Refuse native spawn until the extra link is removed.
pub(super) fn require_private_volume_links(home: &AstridHome) -> io::Result<()> {
    for path in [
        home.storage_volume_path(),
        home.retired_root_storage_volume_path(),
    ] {
        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "runtime backing volume {} must be a regular file with one link before native process spawn",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Only a scoped capsule subtree may be granted through the otherwise hidden
/// runtime home. Check both the name and its resolved target for aliases.
pub(super) fn validate_mcp_grants<'a>(
    home: &AstridHome,
    grants: impl IntoIterator<Item = &'a Path>,
) -> io::Result<()> {
    let root = home.root();
    let resolved_root = resolve_sandbox_path(root)?;
    let capsule_root = root.join("capsules");
    let resolved_capsule_root = resolved_root.join("capsules");
    for path in grants {
        let resolved = resolve_sandbox_path(path)?;
        if disallowed(path, root, &capsule_root)
            || disallowed(&resolved, &resolved_root, &resolved_capsule_root)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "native process grant {} overlaps protected runtime state",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn disallowed(path: &Path, root: &Path, capsule_root: &PathBuf) -> bool {
    (path.starts_with(root) || root.starts_with(path)) && !path.starts_with(capsule_root)
}
