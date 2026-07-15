//! Checked workspace filesystem boundaries.

use std::io;
use std::path::{Component, Path, PathBuf};

use blake3::Hasher;

use super::WorkspaceLayout;

/// A checked project workspace selection.
///
/// The project root is canonical and the selected state directory is either
/// absent or a real directory directly beneath that root. Symlinks, junctions,
/// and other redirects are rejected by requiring an existing directory to
/// canonicalize to the exact direct-child path selected here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSelection {
    project_root: PathBuf,
    state_dir: PathBuf,
    layout: WorkspaceLayout,
}

impl WorkspaceSelection {
    pub(super) fn resolve(project_root: &Path, layout: WorkspaceLayout) -> io::Result<Self> {
        let project_root = std::fs::canonicalize(project_root).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to resolve workspace root {}: {error}",
                    project_root.display()
                ),
            )
        })?;
        if !std::fs::metadata(&project_root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "workspace root is not a directory: {}",
                    project_root.display()
                ),
            ));
        }

        let state_dir = project_root.join(layout.state_dir_name());
        verify_state_dir_path(&project_root, &state_dir)?;
        Ok(Self {
            project_root,
            state_dir,
            layout,
        })
    }

    /// Canonical project root used by every workspace filesystem consumer.
    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Checked selected state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Selected workspace layout.
    #[must_use]
    pub fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }

    /// Checked capsule directory under selected project state.
    ///
    /// # Errors
    ///
    /// Returns an error if an existing path component is redirected or is not
    /// a directory.
    pub fn capsules_dir(&self) -> io::Result<PathBuf> {
        self.resolve_directory("capsules")
    }

    /// Checked configuration path under selected project state.
    ///
    /// # Errors
    ///
    /// Returns an error if the existing file or one of its parents is
    /// redirected or has the wrong type.
    pub fn config_path(&self) -> io::Result<PathBuf> {
        self.resolve_file("config.toml")
    }

    /// Checked hooks directory under selected project state.
    ///
    /// # Errors
    ///
    /// Returns an error if an existing path component is redirected or is not
    /// a directory.
    pub fn hooks_dir(&self) -> io::Result<PathBuf> {
        self.resolve_directory("hooks")
    }

    /// Resolve a relative directory beneath selected project state without
    /// following an existing redirect.
    ///
    /// Missing components are allowed so callers can validate before creation.
    ///
    /// # Errors
    ///
    /// Returns an error for non-normal relative components, redirects, or an
    /// existing non-directory component.
    pub fn resolve_directory(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        self.resolve_descendant(relative.as_ref(), DescendantKind::Directory)
    }

    /// Resolve a relative file beneath selected project state without following
    /// an existing redirect.
    ///
    /// Missing components are allowed so callers can validate before creation.
    ///
    /// # Errors
    ///
    /// Returns an error for non-normal relative components, redirects, a
    /// non-directory parent, or an existing non-file target.
    pub fn resolve_file(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        self.resolve_descendant(relative.as_ref(), DescendantKind::File)
    }

    /// Verify every existing entry in a workspace-relative tree without
    /// following redirects.
    ///
    /// # Errors
    ///
    /// Returns an error if the root is unsafe, any descendant is a symlink,
    /// reparse redirect, or special file, or the tree changes while walking.
    pub fn verify_tree(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        let relative = relative.as_ref();
        let root = self.resolve_directory(relative)?;
        if !root.exists() {
            return Ok(root);
        }
        let mut pending = vec![root.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink()
                    || (!metadata.is_dir() && !metadata.is_file())
                    || std::fs::canonicalize(&path)? != path
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "workspace tree contains a redirected or special entry: {}",
                            path.display()
                        ),
                    ));
                }
                if metadata.is_dir() {
                    pending.push(path);
                }
            }
        }
        self.resolve_directory(relative)?;
        Ok(root)
    }

    fn resolve_descendant(&self, relative: &Path, kind: DescendantKind) -> io::Result<PathBuf> {
        self.verify()?;
        let components = relative.components().collect::<Vec<_>>();
        if components.is_empty()
            || components
                .iter()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workspace descendant must be a non-empty relative path without traversal",
            ));
        }

        let mut current = self.state_dir.clone();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(component) = component else {
                unreachable!("components validated above")
            };
            current.push(component);
            let metadata = match std::fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let final_component = index == components.len().saturating_sub(1);
            let expected_file = final_component && kind == DescendantKind::File;
            if metadata.file_type().is_symlink()
                || (expected_file && !metadata.is_file())
                || (!expected_file && !metadata.is_dir())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "workspace path must not contain redirects or unexpected file types: {}",
                        current.display()
                    ),
                ));
            }
            if std::fs::canonicalize(&current)? != current {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "workspace path redirects from its selected target: {}",
                        current.display()
                    ),
                ));
            }
        }
        Ok(self.state_dir.join(relative))
    }

    /// Re-check that the selected state path has not been redirected.
    ///
    /// A missing state directory remains valid. This permits a checked
    /// selection to be created before initialization while still rejecting a
    /// later symlink or non-directory replacement.
    ///
    /// # Errors
    ///
    /// Returns an error if the project root or state path no longer satisfies
    /// the original selection.
    pub fn verify(&self) -> io::Result<()> {
        let current = Self::resolve(&self.project_root, self.layout.clone())?;
        if current.project_root != self.project_root || current.state_dir != self.state_dir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "workspace selection changed after validation",
            ));
        }
        Ok(())
    }

    /// Create the selected state directory and verify it again afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if creation fails or the path is redirected before or
    /// after creation.
    pub fn ensure_state_dir(&self) -> io::Result<()> {
        self.verify()?;
        match std::fs::create_dir(&self.state_dir) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error),
        }
        self.verify()
    }

    /// Create a checked relative directory and verify the full path afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if a component is unsafe, creation fails, or a redirect
    /// appears during creation.
    pub fn ensure_directory(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        let relative = relative.as_ref();
        let path = self.resolve_directory(relative)?;
        self.ensure_state_dir()?;
        std::fs::create_dir_all(&path)?;
        let checked = self.resolve_directory(relative)?;
        self.verify()?;
        Ok(checked)
    }

    /// Stable opaque identity for the checked root and state-directory target.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(b"astrid-workspace-selection-v2\0");
        hash_path(&mut hasher, &self.project_root);
        hasher.update(b"\0");
        hash_path(&mut hasher, &self.state_dir);
        hasher.update(b"\0");
        hasher.update(self.layout.state_dir_name().as_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescendantKind {
    Directory,
    File,
}

fn verify_state_dir_path(project_root: &Path, state_dir: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(state_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "workspace state path must be a real directory, not a redirect or file: {}",
                state_dir.display()
            ),
        ));
    }

    let canonical = std::fs::canonicalize(state_dir)?;
    if canonical != state_dir || canonical.parent() != Some(project_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "workspace state directory escapes or redirects outside its selected path: {}",
                state_dir.display()
            ),
        ));
    }
    Ok(())
}

/// Stable identity for one project root and workspace layout selection.
///
/// The identity is suitable for detecting whether a CLI and an already-running
/// daemon selected the same project. It does not expose the project path.
#[must_use]
pub fn workspace_selection_fingerprint(
    project_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> String {
    if let Ok(selection) = workspace_layout.resolve(project_root) {
        return selection.fingerprint();
    }
    let root = std::fs::canonicalize(project_root).unwrap_or_else(|_| {
        if project_root.is_absolute() {
            project_root.to_path_buf()
        } else {
            std::env::current_dir()
                .map_or_else(|_| project_root.to_path_buf(), |cwd| cwd.join(project_root))
        }
    });
    let mut hasher = Hasher::new();
    hasher.update(b"astrid-workspace-selection-v1\0");
    hash_path(&mut hasher, &root);
    hasher.update(b"\0");
    hasher.update(workspace_layout.state_dir_name().as_bytes());
    hex::encode(hasher.finalize().as_bytes())
}

/// Resolve a workspace safely and derive its opaque selection identity.
///
/// Security-sensitive callers must use this fallible form rather than relying
/// on a lexical path fingerprint.
///
/// # Errors
///
/// Returns an error if the workspace root or selected state path is unsafe.
pub fn checked_workspace_selection_fingerprint(
    project_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> io::Result<String> {
    Ok(workspace_layout.resolve(project_root)?.fingerprint())
}

fn hash_path(hasher: &mut Hasher, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        hasher.update(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        for unit in path.as_os_str().encode_wide() {
            hasher.update(&unit.to_le_bytes());
        }
    }
    #[cfg(not(any(unix, windows)))]
    hasher.update(path.as_os_str().to_string_lossy().as_bytes());
}
