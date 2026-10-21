//! Selected per-project workspace state.

use std::io;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::WorkspaceLayout;
use super::workspace_security::WorkspaceSelection;

/// Selected per-project workspace state directory.
///
/// Contains project-local runtime state. A `workspace-id` UUID links the
/// project to its global state in `~/.astrid/`.
#[derive(Debug, Clone)]
pub struct WorkspaceDir {
    project_root: PathBuf,
    layout: WorkspaceLayout,
}

impl WorkspaceDir {
    /// Detect the workspace directory by walking up from `start_dir`.
    ///
    /// Detection order:
    /// 1. Directory containing the selected state directory
    /// 2. Directory containing `.git`
    /// 3. Directory containing `ASTRID.md`
    /// 4. Fallback to `start_dir` itself
    #[must_use]
    pub fn detect(start_dir: &Path) -> Self {
        Self::detect_with_layout(start_dir, WorkspaceLayout::default())
    }

    /// Detect the workspace directory using `layout`.
    #[must_use]
    pub fn detect_with_layout(start_dir: &Path, layout: WorkspaceLayout) -> Self {
        let start = if start_dir.is_absolute() {
            start_dir.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(start_dir)
        };

        let mut current = start.as_path();

        loop {
            if layout.state_dir(current).is_dir() {
                return Self {
                    project_root: current.to_path_buf(),
                    layout,
                };
            }
            if current.join(".git").exists() {
                return Self {
                    project_root: current.to_path_buf(),
                    layout,
                };
            }
            if current.join("ASTRID.md").exists() {
                return Self {
                    project_root: current.to_path_buf(),
                    layout,
                };
            }
            match current.parent() {
                Some(parent) if parent != current => current = parent,
                _ => break,
            }
        }

        Self {
            project_root: start,
            layout,
        }
    }

    /// Create from an explicit project root (useful for testing).
    #[must_use]
    pub fn from_path(project_root: impl Into<PathBuf>) -> Self {
        Self::from_path_with_layout(project_root, WorkspaceLayout::default())
    }

    /// Create from an explicit project root and layout.
    #[must_use]
    pub fn from_path_with_layout(
        project_root: impl Into<PathBuf>,
        layout: WorkspaceLayout,
    ) -> Self {
        Self {
            project_root: project_root.into(),
            layout,
        }
    }

    /// Ensure the selected state directory exists and generate a workspace ID
    /// if one does not already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or workspace ID generation fails.
    pub fn ensure(&self) -> io::Result<()> {
        let selection = self.layout.resolve(&self.project_root)?;
        selection.ensure_state_dir()?;
        let _ = self.workspace_id()?;
        selection.verify()?;
        Ok(())
    }

    /// Resolve this workspace through the checked filesystem boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if the project root or selected state path is unsafe.
    pub fn selection(&self) -> io::Result<WorkspaceSelection> {
        self.layout.resolve(&self.project_root)
    }

    /// Project root directory containing the selected state directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.project_root
    }

    /// The selected project state directory.
    #[must_use]
    pub fn dot_astrid(&self) -> PathBuf {
        self.layout.state_dir(&self.project_root)
    }

    /// The active per-project runtime state directory.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.layout.state_dir(&self.project_root)
    }

    /// The active workspace layout.
    #[must_use]
    pub fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }

    /// Capsules under the selected project state directory.
    #[must_use]
    pub fn capsules_dir(&self) -> PathBuf {
        self.dot_astrid().join("capsules")
    }

    /// Path to the workspace-id file under selected project state.
    #[must_use]
    pub fn workspace_id_path(&self) -> PathBuf {
        self.dot_astrid().join("workspace-id")
    }

    /// Read or generate the workspace ID.
    ///
    /// If the file exists (e.g. cloned from a repo), its UUID is adopted.
    /// Otherwise a new UUID is generated and written.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or written.
    pub fn workspace_id(&self) -> io::Result<Uuid> {
        let selection = self.selection()?;
        selection.ensure_state_dir()?;
        let path = selection.resolve_file("workspace-id")?;
        if let Ok(content) = std::fs::read_to_string(&path) {
            let trimmed = content.trim();
            if let Ok(id) = Uuid::parse_str(trimmed) {
                selection.verify()?;
                return Ok(id);
            }
        }
        let id = Uuid::new_v4();
        selection.verify()?;
        std::fs::write(&path, id.to_string())?;
        selection.resolve_file("workspace-id")?;
        selection.verify()?;
        Ok(id)
    }

    /// Path to project instructions under selected project state.
    #[must_use]
    pub fn instructions_path(&self) -> PathBuf {
        self.dot_astrid().join("ASTRID.md")
    }
}
