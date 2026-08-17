//! Filesystem semantics over Astrid's authoritative named-content projection.
//!
//! Regular files remain immutable chunk DAGs. Directories are namespace
//! entries represented by canonical trailing-slash names, so the mounted view
//! does not require (or trust) a parallel host directory tree. The root is
//! implicit. Mutations publish through the same owner-root compare-and-swap as
//! content and KV state.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use crate::content::{ContentName, PrincipalContentError, PrincipalContentStore};
use crate::engine::PrincipalProjectionEngine;

/// One validated relative path inside an Astrid filesystem view.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilesystemPath(String);

impl FilesystemPath {
    /// Construct the implicit filesystem root.
    #[must_use]
    pub const fn root() -> Self {
        Self(String::new())
    }

    /// Validate a slash-separated relative path.
    ///
    /// # Errors
    ///
    /// Rejects absolute paths, empty segments, `.`/`..`, trailing separators,
    /// and null bytes. Native providers pass names as data and must never rely
    /// on host path normalization for authority.
    pub fn new(value: impl Into<String>) -> Result<Self, FilesystemError> {
        let value = value.into();
        if value.is_empty() {
            return Ok(Self::root());
        }
        if value.starts_with('/') || value.ends_with('/') || value.as_bytes().contains(&0) {
            return Err(FilesystemError::InvalidPath(value));
        }
        if value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(FilesystemError::InvalidPath(value));
        }
        Ok(Self(value))
    }

    /// Borrow the canonical relative spelling. The root is the empty string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn file_name(&self) -> Result<ContentName, FilesystemError> {
        if self.0.is_empty() {
            return Err(FilesystemError::IsDirectory(self.clone()));
        }
        ContentName::new(self.0.clone()).map_err(|_| FilesystemError::InvalidPath(self.0.clone()))
    }

    pub(crate) fn directory_marker(&self) -> Result<ContentName, FilesystemError> {
        if self.0.is_empty() {
            return Err(FilesystemError::IsDirectory(self.clone()));
        }
        ContentName::new(format!("{}/", self.0))
            .map_err(|_| FilesystemError::InvalidPath(self.0.clone()))
    }

    pub(crate) fn directory_prefix(&self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            format!("{}/", self.0)
        }
    }

    pub(crate) fn parent(&self) -> Self {
        self.0
            .rsplit_once('/')
            .map_or_else(Self::root, |(parent, _)| Self(parent.to_owned()))
    }
}

/// Stable kind surfaced by every native filesystem provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemEntryKind {
    /// Immutable content bytes addressed by one namespace entry.
    File,
    /// An explicit or implied namespace directory.
    Directory,
}

/// Metadata common to directory enumeration and lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemEntry {
    name: String,
    kind: FilesystemEntryKind,
    logical_bytes: u64,
}

impl FilesystemEntry {
    pub(crate) const fn new(name: String, kind: FilesystemEntryKind, logical_bytes: u64) -> Self {
        Self {
            name,
            kind,
            logical_bytes,
        }
    }

    /// Borrow the final path segment.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the entry kind.
    #[must_use]
    pub const fn kind(&self) -> FilesystemEntryKind {
        self.kind
    }

    /// Return file length. Directories report zero.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
}

/// Filesystem semantic failure independent of an OS errno mapping.
#[derive(Debug, thiserror::Error)]
pub enum FilesystemError {
    /// The supplied path is not a canonical relative Astrid path.
    #[error("invalid Astrid filesystem path: {0:?}")]
    InvalidPath(String),
    /// No file or directory exists at the supplied path.
    #[error("filesystem entry not found: {0:?}")]
    NotFound(FilesystemPath),
    /// The path resolves to a directory where a file was required.
    #[error("filesystem entry is a directory: {0:?}")]
    IsDirectory(FilesystemPath),
    /// The path resolves to a file where a directory was required.
    #[error("filesystem entry is not a directory: {0:?}")]
    NotDirectory(FilesystemPath),
    /// A create or rename destination already exists.
    #[error("filesystem entry already exists: {0:?}")]
    AlreadyExists(FilesystemPath),
    /// A non-empty directory cannot be removed without an explicit recursive operation.
    #[error("filesystem directory is not empty: {0:?}")]
    DirectoryNotEmpty(FilesystemPath),
    /// Persisted content names cannot form an unambiguous filesystem.
    #[error("filesystem namespace conflict at {0:?}")]
    NamespaceConflict(FilesystemPath),
    /// A provider-private staging operation failed before publication.
    #[error("filesystem private staging failed: {0}")]
    Staging(String),
    /// The authoritative content projection rejected an operation.
    #[error("authoritative content operation failed: {0}")]
    Content(#[from] PrincipalContentError),
}

/// A typed-owner filesystem view over one Astrid content store.
#[derive(Clone)]
pub struct AstridFilesystem<P: Ord, E> {
    content: Arc<PrincipalContentStore<P, E>>,
    owner: P,
}

impl<P: Ord, E> AstridFilesystem<P, E> {
    /// Bind a filesystem view to one already-authorized owner.
    #[must_use]
    pub const fn new(content: Arc<PrincipalContentStore<P, E>>, owner: P) -> Self {
        Self { content, owner }
    }

    /// Bind the kernel-fixed Fleet shared subtree (`shared/`).
    ///
    /// The returned view exposes paths relative to `shared/`; callers cannot
    /// choose another prefix or reach unrelated owner content. Authorization
    /// that the owner is a Fleet belongs to the kernel lease resolver.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed canonical `shared` prefix is rejected by the
    /// validated [`FilesystemPath`] parser.
    #[must_use]
    pub fn new_fleet_shared(
        content: Arc<PrincipalContentStore<P, E>>,
        owner: P,
    ) -> OwnerSubtreeFilesystem<P, E> {
        OwnerSubtreeFilesystem {
            inner: Self::new(content, owner),
            prefix: FilesystemPath::new("shared").expect("canonical Fleet shared prefix"),
        }
    }

    /// Bind the kernel-fixed principal home subtree (`home/`).
    ///
    /// This is deliberately separate from [`Self::new`], which remains an
    /// owner-root diagnostic primitive. Principal capsule mounts must use this
    /// constructor so registry, system-control, and other owner components are
    /// not exposed as ordinary home paths.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed canonical `home` prefix is rejected by the
    /// validated [`FilesystemPath`] parser.
    #[must_use]
    pub fn new_principal_home(
        content: Arc<PrincipalContentStore<P, E>>,
        owner: P,
    ) -> OwnerSubtreeFilesystem<P, E> {
        OwnerSubtreeFilesystem {
            inner: Self::new(content, owner),
            prefix: FilesystemPath::new("home").expect("canonical principal home prefix"),
        }
    }
}

/// Filesystem view rooted at one kernel-admitted owner-local directory.
///
/// The prefix is private to the constructor so a provider callback cannot
/// retarget an existing mount. `new_fleet_shared` is the public constructor;
/// other fixed-prefix constructors may be added by the kernel as lease types
/// are admitted.
#[derive(Clone)]
pub struct OwnerSubtreeFilesystem<P: Ord, E> {
    inner: AstridFilesystem<P, E>,
    prefix: FilesystemPath,
}

impl<P: Ord, E> OwnerSubtreeFilesystem<P, E> {
    fn path(&self, path: &FilesystemPath) -> Result<FilesystemPath, FilesystemError> {
        if path.as_str().is_empty() {
            return Ok(self.prefix.clone());
        }
        FilesystemPath::new(format!("{}/{}", self.prefix.as_str(), path.as_str()))
    }
}

impl<P, E> OwnerSubtreeFilesystem<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Inspect one path relative to the fixed subtree root.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when the path cannot
    /// be resolved.
    pub fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, FilesystemError> {
        let mut entry = self.inner.stat(&self.path(path)?)?;
        if path.as_str().is_empty() {
            entry.name = String::new();
        }
        Ok(entry)
    }

    /// Enumerate direct children relative to the fixed subtree root.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when the directory
    /// cannot be enumerated.
    pub fn read_dir(&self, path: &FilesystemPath) -> Result<Vec<FilesystemEntry>, FilesystemError> {
        self.inner.read_dir(&self.path(path)?)
    }

    /// Read a verified file range relative to the fixed subtree root.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when the path or
    /// requested range is invalid.
    pub fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        self.inner.read(&self.path(path)?, offset, length)
    }

    /// Publish complete file bytes relative to the fixed subtree root.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when publication is
    /// rejected.
    pub fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        self.inner.write(&self.path(path)?, bytes)
    }

    /// Publish streamed file bytes relative to the fixed subtree root.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when streaming or
    /// publication is rejected.
    pub fn write_streaming<R: Read>(
        &self,
        path: &FilesystemPath,
        source: R,
    ) -> Result<(), FilesystemError> {
        self.inner.write_streaming(&self.path(path)?, source)
    }

    /// Create a directory relative to the fixed subtree root.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when creation is
    /// rejected.
    pub fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.inner.create_dir(&self.path(path)?)
    }

    /// Remove a file or empty directory relative to the fixed subtree root.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when removal is
    /// rejected.
    pub fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        if path.as_str().is_empty() {
            return Err(FilesystemError::AlreadyExists(path.clone()));
        }
        self.inner.remove(&self.path(path)?)
    }

    /// Rename within the fixed subtree root without replacement.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when either path is
    /// invalid or the rename cannot be applied.
    pub fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
    ) -> Result<(), FilesystemError> {
        self.inner.rename(&self.path(from)?, &self.path(to)?)
    }

    /// Rename within the fixed subtree root, replacing a compatible target.
    ///
    /// # Errors
    ///
    /// Returns a namespace or authoritative content error when either path is
    /// invalid or replacement cannot be applied.
    pub fn rename_replacing(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
    ) -> Result<(), FilesystemError> {
        self.inner
            .rename_replacing(&self.path(from)?, &self.path(to)?)
    }

    /// Flush authoritative objects and roots.
    ///
    /// # Errors
    ///
    /// Returns the underlying content-store error when the flush cannot be
    /// completed.
    pub fn sync(&self) -> Result<(), FilesystemError> {
        self.inner.sync()
    }
}

impl<P, E> AstridFilesystem<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Inspect one path without reading file bytes.
    ///
    /// # Errors
    ///
    /// Returns a namespace or storage error when the entry cannot be resolved.
    pub fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, FilesystemError> {
        if path.as_str().is_empty() {
            return Ok(FilesystemEntry {
                name: String::new(),
                kind: FilesystemEntryKind::Directory,
                logical_bytes: 0,
            });
        }
        let file = self.content.describe(&self.owner, &path.file_name()?)?;
        let directory = self.directory_exists(path)?;
        match (file, directory) {
            (Some(_), true) => Err(FilesystemError::NamespaceConflict(path.clone())),
            (Some(descriptor), false) => Ok(FilesystemEntry {
                name: basename(path),
                kind: FilesystemEntryKind::File,
                logical_bytes: descriptor.logical_bytes(),
            }),
            (None, true) => Ok(FilesystemEntry {
                name: basename(path),
                kind: FilesystemEntryKind::Directory,
                logical_bytes: 0,
            }),
            (None, false) => Err(FilesystemError::NotFound(path.clone())),
        }
    }

    /// Enumerate direct children in exact UTF-8 byte order.
    ///
    /// # Errors
    ///
    /// Returns an error when `path` is not a directory or persisted names are
    /// ambiguous under filesystem semantics.
    pub fn read_dir(&self, path: &FilesystemPath) -> Result<Vec<FilesystemEntry>, FilesystemError> {
        if !path.as_str().is_empty() {
            match self.stat(path)? {
                FilesystemEntry {
                    kind: FilesystemEntryKind::Directory,
                    ..
                } => {},
                _ => return Err(FilesystemError::NotDirectory(path.clone())),
            }
        }
        let prefix = path.directory_prefix();
        let mut children = BTreeMap::<String, FilesystemEntry>::new();
        for entry in self.content.list(&self.owner)? {
            let name = entry.name().as_str();
            let Some(rest) = name.strip_prefix(&prefix) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            let (child, kind, logical_bytes) = match rest.split_once('/') {
                Some((child, _)) if !child.is_empty() => (child, FilesystemEntryKind::Directory, 0),
                Some(_) => return Err(FilesystemError::NamespaceConflict(path.clone())),
                None => (rest, FilesystemEntryKind::File, entry.logical_bytes()),
            };
            match children.get(child) {
                Some(existing) if existing.kind != kind => {
                    let conflict = joined(path, child)?;
                    return Err(FilesystemError::NamespaceConflict(conflict));
                },
                Some(_) => {},
                None => {
                    children.insert(
                        child.to_owned(),
                        FilesystemEntry {
                            name: child.to_owned(),
                            kind,
                            logical_bytes,
                        },
                    );
                },
            }
        }
        Ok(children.into_values().collect())
    }

    /// Read a verified file range.
    ///
    /// # Errors
    ///
    /// Returns a path, type, range, integrity, or storage error.
    pub fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        match self.stat(path)? {
            FilesystemEntry {
                kind: FilesystemEntryKind::File,
                ..
            } => {},
            _ => return Err(FilesystemError::IsDirectory(path.clone())),
        }
        self.content
            .read_range(&self.owner, &path.file_name()?, offset, length)?
            .ok_or_else(|| FilesystemError::NotFound(path.clone()))
    }

    /// Atomically publish complete file bytes.
    ///
    /// # Errors
    ///
    /// Returns a path, parent, conflict, quota, or storage error.
    pub fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        self.require_parent(path)?;
        if self.directory_exists(path)? {
            return Err(FilesystemError::IsDirectory(path.clone()));
        }
        self.content.put(&self.owner, &path.file_name()?, bytes)?;
        Ok(())
    }

    /// Atomically publish complete file bytes from a blocking reader.
    ///
    /// Immutable objects are staged incrementally, so native random-write
    /// adapters can rebuild large files without holding the complete value in
    /// memory. The namespace root changes only after the stream is complete.
    ///
    /// # Errors
    ///
    /// Returns a path, parent, conflict, quota, source, or storage error.
    pub fn write_streaming<R: Read>(
        &self,
        path: &FilesystemPath,
        source: R,
    ) -> Result<(), FilesystemError> {
        self.require_parent(path)?;
        if self.directory_exists(path)? {
            return Err(FilesystemError::IsDirectory(path.clone()));
        }
        self.content
            .put_streaming(&self.owner, &path.file_name()?, source)?;
        Ok(())
    }

    /// Create an explicit empty directory.
    ///
    /// # Errors
    ///
    /// Returns a path, parent, conflict, quota, or storage error.
    pub fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        if path.as_str().is_empty() {
            return Err(FilesystemError::AlreadyExists(path.clone()));
        }
        self.require_parent(path)?;
        if self.entry_exists(path)? {
            return Err(FilesystemError::AlreadyExists(path.clone()));
        }
        self.content
            .put(&self.owner, &path.directory_marker()?, &[])?;
        Ok(())
    }

    /// Remove one file or an empty directory.
    ///
    /// # Errors
    ///
    /// Returns a path, non-empty-directory, or storage error.
    pub fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        match self.stat(path)? {
            FilesystemEntry {
                kind: FilesystemEntryKind::File,
                ..
            } => {
                let removed = self.content.delete(&self.owner, &path.file_name()?)?;
                if !removed {
                    return Err(FilesystemError::NotFound(path.clone()));
                }
            },
            FilesystemEntry {
                kind: FilesystemEntryKind::Directory,
                ..
            } => {
                if !self.read_dir(path)?.is_empty() {
                    return Err(FilesystemError::DirectoryNotEmpty(path.clone()));
                }
                let removed = self
                    .content
                    .delete(&self.owner, &path.directory_marker()?)?;
                if !removed {
                    return Err(FilesystemError::NotFound(path.clone()));
                }
            },
        }
        Ok(())
    }

    /// Atomically rename a file or complete directory subtree.
    ///
    /// # Errors
    ///
    /// Returns a source, destination, parent, conflict, quota, or storage error.
    pub fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
    ) -> Result<(), FilesystemError> {
        self.rename_inner(from, to, false)
    }

    /// Atomically rename an entry, replacing a compatible destination.
    ///
    /// Files replace files. Directories replace only empty directories.
    /// Cross-kind replacement and non-empty directory replacement fail.
    ///
    /// # Errors
    ///
    /// Returns a source, destination, parent, type, quota, or storage error.
    pub fn rename_replacing(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
    ) -> Result<(), FilesystemError> {
        self.rename_inner(from, to, true)
    }

    fn rename_inner(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
        replace: bool,
    ) -> Result<(), FilesystemError> {
        if from.as_str().is_empty() || to.as_str().is_empty() {
            return Err(FilesystemError::InvalidPath(to.as_str().to_owned()));
        }
        if from == to {
            return Ok(());
        }
        self.require_parent(to)?;
        let source = self.stat(from)?;
        let destination = match self.stat(to) {
            Ok(_) if !replace => {
                return Err(FilesystemError::AlreadyExists(to.clone()));
            },
            Ok(destination) => Some(destination),
            Err(FilesystemError::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        let replacements = match (source.kind, destination.map(|entry| entry.kind)) {
            (_, None) => Vec::new(),
            (FilesystemEntryKind::File, Some(FilesystemEntryKind::File)) => vec![to.file_name()?],
            (FilesystemEntryKind::Directory, Some(FilesystemEntryKind::Directory)) => {
                if !self.read_dir(to)?.is_empty() {
                    return Err(FilesystemError::DirectoryNotEmpty(to.clone()));
                }
                vec![to.directory_marker()?]
            },
            (FilesystemEntryKind::File, Some(FilesystemEntryKind::Directory)) => {
                return Err(FilesystemError::IsDirectory(to.clone()));
            },
            (FilesystemEntryKind::Directory, Some(FilesystemEntryKind::File)) => {
                return Err(FilesystemError::NotDirectory(to.clone()));
            },
        };
        let moves = match source.kind {
            FilesystemEntryKind::File => vec![(from.file_name()?, to.file_name()?)],
            FilesystemEntryKind::Directory => {
                let from_prefix = from.directory_prefix();
                let to_prefix = to.directory_prefix();
                if to_prefix.starts_with(&from_prefix) {
                    return Err(FilesystemError::InvalidPath(to.as_str().to_owned()));
                }
                self.content
                    .list(&self.owner)?
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
            .content
            .rename_batch_replacing(&self.owner, &moves, &replacements)?
        {
            return Err(FilesystemError::AlreadyExists(to.clone()));
        }
        Ok(())
    }

    /// Flush authoritative objects and roots.
    ///
    /// # Errors
    ///
    /// Returns a storage error if durable synchronization fails.
    pub fn sync(&self) -> Result<(), FilesystemError> {
        self.content.flush().map_err(Into::into)
    }

    fn require_parent(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        if path.as_str().is_empty() {
            return Err(FilesystemError::IsDirectory(path.clone()));
        }
        let parent = path.parent();
        if parent.as_str().is_empty() {
            return Ok(());
        }
        match self.stat(&parent)? {
            FilesystemEntry {
                kind: FilesystemEntryKind::Directory,
                ..
            } => Ok(()),
            _ => Err(FilesystemError::NotDirectory(parent)),
        }
    }

    fn entry_exists(&self, path: &FilesystemPath) -> Result<bool, FilesystemError> {
        match self.stat(path) {
            Ok(_) => Ok(true),
            Err(FilesystemError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn directory_exists(&self, path: &FilesystemPath) -> Result<bool, FilesystemError> {
        if path.as_str().is_empty() {
            return Ok(true);
        }
        let prefix = path.directory_prefix();
        Ok(self
            .content
            .list(&self.owner)?
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

fn joined(parent: &FilesystemPath, name: &str) -> Result<FilesystemPath, FilesystemError> {
    FilesystemPath::new(if parent.as_str().is_empty() {
        name.to_owned()
    } else {
        format!("{}/{name}", parent.as_str())
    })
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use std::sync::Arc;

    use astrid_core::PrincipalUid;

    use super::*;
    use crate::{KvQuotaResolver, StateOwner, open_runtime_principal_store};

    async fn filesystem() -> (
        tempfile::TempDir,
        AstridFilesystem<
            StateOwner,
            crate::engine::DurableEngine<
                StateOwner,
                crate::Blake3ObjectIdentityV1,
                crate::StateOwnerCodecV2,
            >,
        >,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(directory.path());
        home.ensure().unwrap();
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        });
        let store = open_runtime_principal_store(&home, quota).await.unwrap();
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([7; 32]));
        (directory, AstridFilesystem::new(store.content(), owner))
    }

    #[tokio::test]
    async fn directories_are_namespace_entries_not_host_directories() {
        let (directory, filesystem) = filesystem().await;
        let projects = FilesystemPath::new("projects").unwrap();
        let note = FilesystemPath::new("projects/note.txt").unwrap();

        filesystem.create_dir(&projects).unwrap();
        filesystem.write(&note, b"astrid").unwrap();

        assert_eq!(
            filesystem.read_dir(&FilesystemPath::root()).unwrap(),
            vec![FilesystemEntry {
                name: "projects".to_owned(),
                kind: FilesystemEntryKind::Directory,
                logical_bytes: 0,
            }]
        );
        assert_eq!(filesystem.read(&note, 1, 4).unwrap(), b"stri");
        assert!(!directory.path().join("projects").exists());
    }

    #[tokio::test]
    async fn owner_views_are_isolated_over_one_physical_store() {
        let (directory, first) = filesystem().await;
        let home = astrid_core::dirs::AstridHome::from_path(directory.path());
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        });
        drop(first);
        let store = open_runtime_principal_store(&home, quota).await.unwrap();
        let first = AstridFilesystem::new(
            store.content(),
            StateOwner::Principal(PrincipalUid::from_bytes([7; 32])),
        );
        let second = AstridFilesystem::new(
            store.content(),
            StateOwner::Principal(PrincipalUid::from_bytes([8; 32])),
        );
        let path = FilesystemPath::new("shared-name.txt").unwrap();

        first.write(&path, b"first").unwrap();
        second.write(&path, b"second").unwrap();

        assert_eq!(first.read(&path, 0, 5).unwrap(), b"first");
        assert_eq!(second.read(&path, 0, 6).unwrap(), b"second");
    }

    #[tokio::test]
    async fn fleet_shared_view_cannot_escape_fixed_prefix() {
        let (_directory, filesystem) = filesystem().await;
        let shared = FilesystemPath::new("shared").unwrap();
        let inside = FilesystemPath::new("shared/inside.txt").unwrap();
        let outside = FilesystemPath::new("private.txt").unwrap();
        filesystem.create_dir(&shared).unwrap();
        filesystem.write(&inside, b"shared bytes").unwrap();
        filesystem.write(&outside, b"private bytes").unwrap();

        let scoped =
            AstridFilesystem::new_fleet_shared(Arc::clone(&filesystem.content), filesystem.owner);
        assert_eq!(
            scoped.read_dir(&FilesystemPath::root()).unwrap()[0].name(),
            "inside.txt"
        );
        assert_eq!(
            scoped
                .read(&FilesystemPath::new("inside.txt").unwrap(), 0, 12)
                .unwrap(),
            b"shared bytes"
        );
        assert!(matches!(
            scoped.stat(&FilesystemPath::new("private.txt").unwrap()),
            Err(FilesystemError::NotFound(_))
        ));
        assert!(matches!(
            scoped.remove(&FilesystemPath::root()),
            Err(FilesystemError::AlreadyExists(_))
        ));
    }

    #[tokio::test]
    async fn empty_directory_removal_is_explicit_and_non_recursive() {
        let (_directory, filesystem) = filesystem().await;
        let directory = FilesystemPath::new("dir").unwrap();
        let child = FilesystemPath::new("dir/child").unwrap();
        filesystem.create_dir(&directory).unwrap();
        filesystem.write(&child, b"x").unwrap();

        assert!(matches!(
            filesystem.remove(&directory),
            Err(FilesystemError::DirectoryNotEmpty(_))
        ));
        filesystem.remove(&child).unwrap();
        filesystem.remove(&directory).unwrap();
        assert!(matches!(
            filesystem.stat(&directory),
            Err(FilesystemError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn directory_rename_publishes_the_subtree_as_one_owner_transition() {
        let (_directory, filesystem) = filesystem().await;
        let from = FilesystemPath::new("from").unwrap();
        let nested = FilesystemPath::new("from/nested").unwrap();
        let file = FilesystemPath::new("from/nested/file").unwrap();
        let to = FilesystemPath::new("to").unwrap();
        filesystem.create_dir(&from).unwrap();
        filesystem.create_dir(&nested).unwrap();
        filesystem.write(&file, b"value").unwrap();

        filesystem.rename(&from, &to).unwrap();

        assert!(matches!(
            filesystem.stat(&from),
            Err(FilesystemError::NotFound(_))
        ));
        assert_eq!(
            filesystem
                .read(&FilesystemPath::new("to/nested/file").unwrap(), 0, 5)
                .unwrap(),
            b"value"
        );
    }

    #[tokio::test]
    async fn replace_rename_supports_atomic_editor_saves() {
        let (_directory, filesystem) = filesystem().await;
        let temporary = FilesystemPath::new("note.txt.tmp").unwrap();
        let target = FilesystemPath::new("note.txt").unwrap();
        filesystem.write(&target, b"old").unwrap();
        filesystem.write(&temporary, b"new contents").unwrap();

        filesystem.rename_replacing(&temporary, &target).unwrap();

        assert_eq!(filesystem.read(&target, 0, 12).unwrap(), b"new contents");
        assert!(matches!(
            filesystem.stat(&temporary),
            Err(FilesystemError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn directory_replace_requires_an_empty_compatible_destination() {
        let (_directory, filesystem) = filesystem().await;
        let source = FilesystemPath::new("source").unwrap();
        let destination = FilesystemPath::new("destination").unwrap();
        filesystem.create_dir(&source).unwrap();
        filesystem.create_dir(&destination).unwrap();
        filesystem
            .write(&FilesystemPath::new("destination/occupied").unwrap(), b"x")
            .unwrap();

        assert!(matches!(
            filesystem.rename_replacing(&source, &destination),
            Err(FilesystemError::DirectoryNotEmpty(_))
        ));
    }
}
