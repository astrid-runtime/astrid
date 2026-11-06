//! Original-source owner retained across digest, copy, and retirement.

use super::super::migrations::copy_legacy_tree;
use super::super::native_io::PrivateDirectory;
use super::intent::{LegacyCapturedIdentity, LegacyRetirementIntent};
use super::store::SnapshotStore;
use super::{LegacySourceKind, SnapshotReader, SnapshotWorkspace, snapshot_error};
use crate::{StorageResult, SurrealKvStore};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Captured original source retained while a private snapshot is read.
///
/// The owner is not `Clone`. Its shared LOCK fence is also held by the copied
/// snapshot engine so dropping one handle cannot release writer exclusion.
pub struct LegacySource {
    intent: LegacyRetirementIntent,
    fence: Option<Arc<std::fs::File>>,
    captured: CapturedSource,
}

pub(super) enum CapturedSource {
    #[cfg(windows)]
    Handle {
        directory: astrid_core::platform_fs::CapturedDirectory,
    },
    #[cfg(not(windows))]
    ParentRelative {
        parent: PrivateDirectory,
        name: std::ffi::OsString,
        identity: LegacyCapturedIdentity,
        path: PathBuf,
    },
}

impl LegacySource {
    /// Move this captured database into its generation stage without deleting bytes.
    ///
    /// Persist the staged receipt after this returns and before calling the
    /// returned owner's `retire`. Empty sources cannot be staged by this API.
    ///
    /// # Errors
    /// Returns an error on an empty/mismatched intent, replacement, or failed MOVE.
    pub async fn stage_retirement(
        self,
        intent: &LegacyRetirementIntent,
        staging_root: &Path,
    ) -> StorageResult<super::retire::LegacyRetirementStage> {
        if !self.matches_retirement_intent(intent) {
            return Err(snapshot_error(
                "legacy retirement intent does not match the captured source",
            ));
        }
        let intent = intent.clone();
        let staging_root = staging_root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            super::retire::stage_blocking(self, &intent, &staging_root)
        })
        .await
        .map_err(snapshot_error)?
    }

    /// Classification captured with the original source.
    #[must_use]
    pub fn kind(&self) -> LegacySourceKind {
        self.intent.kind()
    }

    /// Typed identities that authorize later retirement of this source.
    #[must_use]
    pub fn retirement_intent(&self) -> LegacyRetirementIntent {
        self.intent.clone()
    }

    /// Whether `intent` names this live source, ignoring stage generation.
    #[must_use]
    pub fn matches_retirement_intent(&self, intent: &LegacyRetirementIntent) -> bool {
        intent.matches_source(
            self.kind(),
            self.intent.captured_root(),
            self.intent.captured_lock(),
        )
    }

    /// Retire this captured original under a previously persisted intent.
    ///
    /// The whole owner is moved into a blocking worker so cancelling the
    /// caller cannot drop the fence or captured root while deletion runs.
    /// Empty sources are removed at their original name. Databases move to a
    /// generation-derived stage name first.
    ///
    /// # Errors
    ///
    /// Returns an error if the intent does not match, a replacement is found,
    /// or identity-conditioned removal fails. Failures preserve unmatched trees.
    pub async fn retire(
        self,
        intent: &LegacyRetirementIntent,
        staging_root: &Path,
    ) -> StorageResult<()> {
        if !self.matches_retirement_intent(intent) {
            return Err(snapshot_error(
                "legacy retirement intent does not match the captured source",
            ));
        }
        let staging_root = staging_root.to_path_buf();
        let intent = intent.clone();
        tokio::task::spawn_blocking(move || {
            super::retire::retire_blocking(self, &intent, &staging_root)
        })
        .await
        .map_err(snapshot_error)?
    }

    pub(super) fn into_parts(self) -> (Option<Arc<std::fs::File>>, CapturedSource) {
        (self.fence, self.captured)
    }
}

pub(super) fn prepare_snapshot(
    source: &Path,
) -> StorageResult<(SnapshotReader, Arc<SnapshotStore>, LegacySource)> {
    let (captured, directory) = capture_source(source)?;
    let lock = lock_source(&directory)?;
    let workspace = SnapshotWorkspace::create()?;
    let copied = copy_snapshot(&directory, &workspace);
    drop(directory);
    let path = match copied {
        Ok(path) => path,
        Err(error) => {
            workspace.remove()?;
            return Err(error);
        },
    };
    let (fence, lock_identity) = match lock {
        Some((file, identity)) => (Some(Arc::new(file)), Some(identity)),
        None => (None, None),
    };
    let kind = if fence.is_some() {
        LegacySourceKind::LockedDatabase
    } else {
        LegacySourceKind::EmptyDirectory
    };
    let root = captured.root_identity();
    let intent = match (&kind, lock_identity) {
        (LegacySourceKind::EmptyDirectory, None) => LegacyRetirementIntent::empty(root),
        (LegacySourceKind::LockedDatabase, Some(lock_identity)) => {
            LegacyRetirementIntent::database(root, lock_identity, Uuid::new_v4())
        },
        _ => {
            return Err(snapshot_error(
                "legacy source kind does not match captured LOCK identity",
            ));
        },
    };
    let owner = LegacySource {
        intent,
        fence: fence.clone(),
        captured,
    };
    let store = Arc::new(SnapshotStore::new(SurrealKvStore::open(&path)?, fence));
    let reader = SnapshotReader {
        store: Some(Arc::clone(&store)),
        workspace: Some(workspace),
    };
    Ok((reader, store, owner))
}

fn copy_snapshot(
    source: &PrivateDirectory,
    workspace: &SnapshotWorkspace,
) -> StorageResult<PathBuf> {
    let path = workspace.directory_path()?.join("database");
    let destination = PrivateDirectory::open(&path)?;
    copy_legacy_tree(source, &destination)?;
    drop(destination);
    Ok(path)
}

fn lock_source(
    source: &PrivateDirectory,
) -> StorageResult<Option<(std::fs::File, LegacyCapturedIdentity)>> {
    if source.entries()?.is_empty() {
        return Ok(None);
    }
    let lock = source.open_file(Path::new("LOCK"))?;
    lock.try_lock_shared().map_err(snapshot_error)?;
    #[cfg(windows)]
    let lock = super::source_lock::handoff(lock).map_err(snapshot_error)?;
    let identity = lock_identity(&lock)?;
    Ok(Some((lock, identity)))
}

pub(super) fn lock_identity(lock: &std::fs::File) -> StorageResult<LegacyCapturedIdentity> {
    #[cfg(windows)]
    {
        let (volume, file_id) =
            super::source_lock::extended_identity(lock).map_err(snapshot_error)?;
        Ok(LegacyCapturedIdentity::from_windows_file_id(
            volume, file_id,
        ))
    }
    #[cfg(unix)]
    {
        let (volume, inode) = super::super::native_io::private_file_identity(lock)?.raw_parts();
        Ok(LegacyCapturedIdentity::from_unix(volume, inode))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = lock;
        Err(snapshot_error(
            "legacy LOCK identity is unsupported on this platform",
        ))
    }
}

#[cfg(windows)]
fn capture_source(path: &Path) -> StorageResult<(CapturedSource, PrivateDirectory)> {
    let directory =
        astrid_core::platform_fs::CapturedDirectory::open(path).map_err(snapshot_error)?;
    let clone = directory
        .try_clone_directory_file()
        .map_err(snapshot_error)?;
    let capability = PrivateDirectory::from_std_directory_file(clone, path.to_path_buf())?;
    Ok((CapturedSource::Handle { directory }, capability))
}

#[cfg(not(windows))]
fn capture_source(path: &Path) -> StorageResult<(CapturedSource, PrivateDirectory)> {
    let parent_path = path
        .parent()
        .ok_or_else(|| snapshot_error(format!("legacy source {} has no parent", path.display())))?;
    let name = path
        .file_name()
        .ok_or_else(|| snapshot_error(format!("legacy source {} has no name", path.display())))?;
    let parent = PrivateDirectory::open(parent_path)?;
    let child = parent.open_child(Path::new(name))?;
    let identity = {
        let (volume, inode) = child.raw_identity();
        LegacyCapturedIdentity::from_unix(volume, inode)
    };
    Ok((
        CapturedSource::ParentRelative {
            parent,
            name: name.to_os_string(),
            identity,
            path: path.to_path_buf(),
        },
        child,
    ))
}

impl CapturedSource {
    fn root_identity(&self) -> LegacyCapturedIdentity {
        match self {
            #[cfg(windows)]
            Self::Handle { directory, .. } => {
                LegacyCapturedIdentity::from_windows_directory(directory.identity())
            },
            #[cfg(not(windows))]
            Self::ParentRelative { identity, .. } => identity.clone(),
        }
    }
}

impl SnapshotWorkspace {
    fn directory_path(&self) -> StorageResult<&Path> {
        self.0
            .as_ref()
            .map(super::super::native_io::CapturedDirectory::path)
            .ok_or_else(|| snapshot_error("missing workspace"))
    }
}
