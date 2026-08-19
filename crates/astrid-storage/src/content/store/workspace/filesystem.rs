use std::{collections::BTreeMap, fmt};

use super::{
    ContentName, FilesystemEntry, FilesystemEntryKind, FilesystemError, FilesystemPath,
    PrincipalProjectionEngine, WorkspaceBranchDescriptor, WorkspaceBranchError,
    WorkspaceBranchStore, WorkspaceUid,
};

/// A branch-bound filesystem view using the same path semantics as the main
/// Astrid filesystem projection.
#[derive(Clone)]
pub struct WorkspaceFilesystem<P: Ord, E> {
    pub(super) branches: WorkspaceBranchStore<P, E>,
    pub(super) owner: P,
    pub(super) branch: WorkspaceUid,
}

impl<P: Ord + fmt::Debug, E> fmt::Debug for WorkspaceFilesystem<P, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceFilesystem")
            .field("owner", &self.owner)
            .field("branch", &self.branch)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::missing_errors_doc)]
impl<P, E> WorkspaceFilesystem<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Return the accountable owner.
    #[must_use]
    pub const fn owner(&self) -> &P {
        &self.owner
    }

    /// Return the opaque branch identifier.
    #[must_use]
    pub const fn branch(&self) -> WorkspaceUid {
        self.branch
    }

    /// Inspect one branch path.
    pub fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, WorkspaceBranchError> {
        if path.as_str().is_empty() {
            return Ok(FilesystemEntry::new(
                String::new(),
                FilesystemEntryKind::Directory,
                0,
            ));
        }
        let file = path.file_name()?;
        let entries = self.branches.list(&self.owner, self.branch)?;
        let file_entry = entries
            .iter()
            .find(|entry| entry.name().as_str() == file.as_str());
        let prefix = path.directory_prefix();
        let directory = entries
            .iter()
            .any(|entry| entry.name().as_str().starts_with(&prefix));
        match (file_entry, directory) {
            (Some(_), true) => Err(FilesystemError::NamespaceConflict(path.clone()).into()),
            (Some(entry), false) => Ok(FilesystemEntry::new(
                basename(path),
                FilesystemEntryKind::File,
                entry.logical_bytes(),
            )),
            (None, true) => Ok(FilesystemEntry::new(
                basename(path),
                FilesystemEntryKind::Directory,
                0,
            )),
            (None, false) => Err(FilesystemError::NotFound(path.clone()).into()),
        }
    }

    /// Enumerate direct children in canonical byte order.
    pub fn read_dir(
        &self,
        path: &FilesystemPath,
    ) -> Result<Vec<FilesystemEntry>, WorkspaceBranchError> {
        if !path.as_str().is_empty() && self.stat(path)?.kind() != FilesystemEntryKind::Directory {
            return Err(FilesystemError::NotDirectory(path.clone()).into());
        }
        let prefix = path.directory_prefix();
        let mut children = BTreeMap::<String, FilesystemEntry>::new();
        for entry in self.branches.list(&self.owner, self.branch)? {
            let name = entry.name().as_str();
            let Some(rest) = name.strip_prefix(&prefix) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            let (child, kind, bytes) = match rest.split_once('/') {
                Some((child, _)) if !child.is_empty() => (child, FilesystemEntryKind::Directory, 0),
                Some(_) => return Err(FilesystemError::NamespaceConflict(path.clone()).into()),
                None => (rest, FilesystemEntryKind::File, entry.logical_bytes()),
            };
            match children.get(child) {
                Some(existing) if existing.kind() != kind => {
                    return Err(FilesystemError::NamespaceConflict(path.clone()).into());
                },
                Some(_) => {},
                None => {
                    children.insert(
                        child.to_owned(),
                        FilesystemEntry::new(child.to_owned(), kind, bytes),
                    );
                },
            }
        }
        Ok(children.into_values().collect())
    }

    /// Read an exact file range.
    pub fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, WorkspaceBranchError> {
        if self.stat(path)?.kind() != FilesystemEntryKind::File {
            return Err(FilesystemError::IsDirectory(path.clone()).into());
        }
        self.branches
            .read_range(&self.owner, self.branch, &path.file_name()?, offset, length)?
            .ok_or_else(|| FilesystemError::NotFound(path.clone()).into())
    }

    /// Publish complete file bytes.
    pub fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), WorkspaceBranchError> {
        self.require_parent(path)?;
        if self.directory_exists(path)? {
            return Err(FilesystemError::IsDirectory(path.clone()).into());
        }
        self.branches
            .write(&self.owner, self.branch, &path.file_name()?, bytes)
    }

    /// Create an explicit empty directory marker.
    pub fn create_dir(&self, path: &FilesystemPath) -> Result<(), WorkspaceBranchError> {
        if path.as_str().is_empty() {
            return Err(FilesystemError::AlreadyExists(path.clone()).into());
        }
        self.require_parent(path)?;
        if self.entry_exists(path)? {
            return Err(FilesystemError::AlreadyExists(path.clone()).into());
        }
        self.branches
            .write(&self.owner, self.branch, &path.directory_marker()?, &[])
    }

    /// Remove one file or empty directory marker.
    pub fn remove(&self, path: &FilesystemPath) -> Result<(), WorkspaceBranchError> {
        match self.stat(path)?.kind() {
            FilesystemEntryKind::File => {
                let removed =
                    self.branches
                        .remove_name(&self.owner, self.branch, &path.file_name()?)?;
                if !removed {
                    return Err(FilesystemError::NotFound(path.clone()).into());
                }
            },
            FilesystemEntryKind::Directory => {
                if !self.read_dir(path)?.is_empty() {
                    return Err(FilesystemError::DirectoryNotEmpty(path.clone()).into());
                }
                let removed = self.branches.remove_name(
                    &self.owner,
                    self.branch,
                    &path.directory_marker()?,
                )?;
                if !removed {
                    return Err(FilesystemError::NotFound(path.clone()).into());
                }
            },
        }
        Ok(())
    }

    /// Atomically rename a branch file or complete directory subtree.
    pub fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
    ) -> Result<(), WorkspaceBranchError> {
        self.rename_inner(from, to, false)
    }

    /// Atomically rename a branch entry, replacing a compatible destination.
    pub fn rename_replacing(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
    ) -> Result<(), WorkspaceBranchError> {
        self.rename_inner(from, to, true)
    }

    /// Promote this branch's current content view into the owner.
    pub fn promote(&self) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        self.branches.promote(&self.owner, self.branch)
    }

    /// Roll back this branch without changing owner content.
    pub fn rollback(&self) -> Result<(), WorkspaceBranchError> {
        self.branches.rollback(&self.owner, self.branch)
    }

    /// Flush immutable objects and the owner root carrying this branch.
    pub fn sync(&self) -> Result<(), WorkspaceBranchError> {
        self.branches.content.flush().map_err(Into::into)
    }

    fn require_parent(&self, path: &FilesystemPath) -> Result<(), WorkspaceBranchError> {
        if path.as_str().is_empty() {
            return Err(FilesystemError::IsDirectory(path.clone()).into());
        }
        let parent = path.parent();
        if parent.as_str().is_empty() {
            return Ok(());
        }
        if self.stat(&parent)?.kind() != FilesystemEntryKind::Directory {
            return Err(FilesystemError::NotDirectory(parent).into());
        }
        Ok(())
    }

    fn rename_inner(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
        replace: bool,
    ) -> Result<(), WorkspaceBranchError> {
        if from.as_str().is_empty() || to.as_str().is_empty() {
            return Err(FilesystemError::InvalidPath(to.as_str().to_owned()).into());
        }
        if from == to {
            return Ok(());
        }
        self.require_parent(to)?;
        let source = self.stat(from)?;
        let destination = match self.stat(to) {
            Ok(_) if !replace => return Err(FilesystemError::AlreadyExists(to.clone()).into()),
            Ok(destination) => Some(destination),
            Err(WorkspaceBranchError::Filesystem(FilesystemError::NotFound(_))) => None,
            Err(error) => return Err(error),
        };
        let replacements = match (source.kind(), destination.map(|entry| entry.kind())) {
            (_, None) => Vec::new(),
            (FilesystemEntryKind::File, Some(FilesystemEntryKind::File)) => {
                vec![to.file_name()?]
            },
            (FilesystemEntryKind::Directory, Some(FilesystemEntryKind::Directory)) => {
                if !self.read_dir(to)?.is_empty() {
                    return Err(FilesystemError::DirectoryNotEmpty(to.clone()).into());
                }
                vec![to.directory_marker()?]
            },
            (FilesystemEntryKind::File, Some(FilesystemEntryKind::Directory)) => {
                return Err(FilesystemError::IsDirectory(to.clone()).into());
            },
            (FilesystemEntryKind::Directory, Some(FilesystemEntryKind::File)) => {
                return Err(FilesystemError::NotDirectory(to.clone()).into());
            },
        };
        let moves = match source.kind() {
            FilesystemEntryKind::File => vec![(from.file_name()?, to.file_name()?)],
            FilesystemEntryKind::Directory => {
                let from_prefix = from.directory_prefix();
                let to_prefix = to.directory_prefix();
                if to_prefix.starts_with(&from_prefix) {
                    return Err(FilesystemError::InvalidPath(to.as_str().to_owned()).into());
                }
                self.branches
                    .list(&self.owner, self.branch)?
                    .into_iter()
                    .filter_map(|entry| {
                        let source = entry.name().clone();
                        let suffix = source.as_str().strip_prefix(&from_prefix)?;
                        let destination = ContentName::new(format!("{to_prefix}{suffix}")).ok()?;
                        Some((source, destination))
                    })
                    .collect::<Vec<_>>()
            },
        };
        if !self
            .branches
            .rename_batch(&self.owner, self.branch, &moves, &replacements)?
        {
            return Err(FilesystemError::AlreadyExists(to.clone()).into());
        }
        Ok(())
    }

    fn entry_exists(&self, path: &FilesystemPath) -> Result<bool, WorkspaceBranchError> {
        match self.stat(path) {
            Ok(_) => Ok(true),
            Err(WorkspaceBranchError::Filesystem(FilesystemError::NotFound(_))) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn directory_exists(&self, path: &FilesystemPath) -> Result<bool, WorkspaceBranchError> {
        if path.as_str().is_empty() {
            return Ok(true);
        }
        let prefix = path.directory_prefix();
        Ok(self
            .branches
            .list(&self.owner, self.branch)?
            .iter()
            .any(|entry| entry.name().as_str().starts_with(&prefix)))
    }
}

fn basename(path: &FilesystemPath) -> String {
    path.as_str()
        .rsplit_once('/')
        .map_or(path.as_str(), |(_, name)| name)
        .to_owned()
}
