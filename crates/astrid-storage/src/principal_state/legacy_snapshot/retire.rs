//! Identity-conditioned original-source retirement and crash resume.

#[cfg(not(windows))]
use super::super::native_io::validate_retirement_tree;
use super::super::native_io::{PrivateDirectory, remove_retirement_contents};
use super::intent::{LegacyCapturedIdentity, LegacyRetirementIntent};
use super::owner::{CapturedSource, LegacySource};
use super::snapshot_error;
use crate::StorageResult;
use std::path::Path;
use std::sync::Arc;

/// Captured database already moved to its generation stage, not yet emptied.
///
/// The caller must durably record the staged transition before `retire`.
/// Dropping this owner releases handles but never deletes the staged source.
pub struct LegacyRetirementStage {
    captured: CapturedSource,
    fence: Option<Arc<std::fs::File>>,
    #[cfg(windows)]
    path: std::path::PathBuf,
}

impl LegacyRetirementStage {
    /// Empty and remove only the captured staged database.
    ///
    /// # Errors
    /// Returns an error on validation, replacement, or incomplete removal.
    pub async fn retire(self) -> StorageResult<()> {
        tokio::task::spawn_blocking(move || self.finish_blocking())
            .await
            .map_err(snapshot_error)?
    }

    fn finish_blocking(self) -> StorageResult<()> {
        let Self {
            captured,
            fence,
            #[cfg(windows)]
            path,
        } = self;
        let _fence = fence;
        match captured {
            #[cfg(windows)]
            CapturedSource::Handle { directory } => empty_moved_tree(directory, &path),
            #[cfg(not(windows))]
            CapturedSource::ParentRelative {
                parent,
                name,
                identity,
                path,
            } => empty_staged_unix(&parent, &name, &identity, &path),
        }
    }
}

pub(super) fn retire_blocking(
    source: LegacySource,
    intent: &LegacyRetirementIntent,
    staging_root: &Path,
) -> StorageResult<()> {
    if intent.stage_name().is_some() {
        return stage_blocking(source, intent, staging_root)?.finish_blocking();
    }
    let (fence, captured) = source.into_parts();
    let _fence = fence;
    retire_empty(captured)
}

pub(super) fn stage_blocking(
    source: LegacySource,
    intent: &LegacyRetirementIntent,
    staging_root: &Path,
) -> StorageResult<LegacyRetirementStage> {
    let name = intent
        .stage_name()
        .ok_or_else(|| snapshot_error("empty source has no database retirement stage"))?;
    let (fence, captured) = source.into_parts();
    // Require an existing containing directory. Creating an arbitrary ancestor
    // chain here would need separate durability fences for every new name
    // before the source's old name can safely be removed.
    let parent = staging_root
        .parent()
        .ok_or_else(|| snapshot_error("retirement staging root has no parent"))?;
    drop(PrivateDirectory::open(parent)?);
    astrid_core::platform_fs::ensure_private_directory(staging_root).map_err(snapshot_error)?;
    #[cfg(unix)]
    staging_parent(staging_root)?.sync()?;
    let stage_path = staging_root.join(&name);
    let captured = match captured {
        #[cfg(windows)]
        CapturedSource::Handle { mut directory } => {
            directory.rename_to(&stage_path).map_err(snapshot_error)?;
            CapturedSource::Handle { directory }
        },
        #[cfg(not(windows))]
        CapturedSource::ParentRelative {
            parent,
            name,
            identity,
            path,
        } => {
            move_unix(&parent, &name, &identity, &path, &stage_path)?;
            CapturedSource::ParentRelative {
                parent: staging_parent(&stage_path)?,
                name: stage_file_name(&stage_path)?,
                identity,
                path: stage_path.clone(),
            }
        },
    };
    Ok(LegacyRetirementStage {
        captured,
        fence,
        #[cfg(windows)]
        path: stage_path,
    })
}

/// Capture a moved database stage that is still complete, before durable Staged.
///
/// The generation directory must exist, match the captured root, and still hold
/// the captured LOCK under a shared fence. Dropping the returned owner does not
/// delete. Callers persist Staged, then `retire`.
///
/// # Errors
/// Returns an error for an empty intent, absent or replaced stage, missing or
/// replaced LOCK, or a lock that cannot be held. An absent stage is not success.
pub async fn capture_authorized_legacy_retirement_stage(
    staging_root: &Path,
    intent: &LegacyRetirementIntent,
) -> StorageResult<LegacyRetirementStage> {
    let name = intent
        .stage_name()
        .ok_or_else(|| snapshot_error("empty source has no database retirement stage"))?;
    let path = staging_root.join(name);
    let intent = intent.clone();
    tokio::task::spawn_blocking(move || capture_authorized_blocking(&path, &intent))
        .await
        .map_err(snapshot_error)?
}

/// Finish only the receipt's staged database, regardless of the original name.
///
/// Callers must prove that the staged transition is durable before using this
/// entry point. An original-name occupant never becomes deletion authority.
/// An absent whole stage, or a partial stage whose LOCK is already gone, is
/// success for this Staged-only resume.
///
/// # Errors
/// Returns an error for an empty intent, replaced stage/LOCK, or failed removal.
pub async fn resume_staged_legacy_retirement(
    staging_root: &Path,
    intent: &LegacyRetirementIntent,
) -> StorageResult<()> {
    let name = intent
        .stage_name()
        .ok_or_else(|| snapshot_error("empty source has no database retirement stage"))?;
    let path = staging_root.join(name);
    let intent = intent.clone();
    tokio::task::spawn_blocking(move || {
        if directory_present(&path)? {
            resume_stage(&path, &intent)?;
        }
        Ok(())
    })
    .await
    .map_err(snapshot_error)?
}

/// Resume deletion of a previously authorized stage, never a live original.
///
/// # Errors
///
/// Returns an error if the original name is still occupied, both original and
/// stage exist, the staged identity does not match, or removal fails. A live
/// original is preserved so the caller can digest it as a new source.
pub async fn resume_legacy_retirement(
    original: &Path,
    staging_root: &Path,
    intent: &LegacyRetirementIntent,
) -> StorageResult<()> {
    let original = original.to_path_buf();
    let staging_root = staging_root.to_path_buf();
    let intent = intent.clone();
    tokio::task::spawn_blocking(move || resume_blocking(&original, &staging_root, &intent))
        .await
        .map_err(snapshot_error)?
}

fn resume_blocking(
    original: &Path,
    staging_root: &Path,
    intent: &LegacyRetirementIntent,
) -> StorageResult<()> {
    let original_present = directory_present(original)?;
    let stage_path = intent.stage_name().map(|name| staging_root.join(name));
    let stage_present = match &stage_path {
        Some(path) => directory_present(path)?,
        None => false,
    };
    if original_present && stage_present {
        return Err(snapshot_error(
            "legacy retirement is ambiguous because original and stage both exist",
        ));
    }
    if original_present {
        return Err(snapshot_error(
            "legacy retirement original is still present; caller must digest the current source",
        ));
    }
    if !stage_present {
        return Ok(());
    }
    let Some(stage_path) = stage_path else {
        return Ok(());
    };
    resume_stage(&stage_path, intent)
}

fn retire_empty(captured: CapturedSource) -> StorageResult<()> {
    match captured {
        #[cfg(windows)]
        CapturedSource::Handle { directory, .. } => {
            directory.remove_empty().map_err(snapshot_error)
        },
        #[cfg(not(windows))]
        CapturedSource::ParentRelative {
            parent,
            name,
            identity,
            path,
        } => remove_empty_unix(&parent, &name, &identity, &path),
    }
}

#[cfg(windows)]
fn empty_moved_tree(
    directory: astrid_core::platform_fs::CapturedDirectory,
    stage_path: &Path,
) -> StorageResult<()> {
    // Mutation-only: obtain relative paired flush from retained parent+name
    // before cloning the readonly traversal handle. No ambient path reopen.
    let flush = directory.open_paired_flush().map_err(snapshot_error)?;
    let clone = directory
        .try_clone_directory_file()
        .map_err(snapshot_error)?;
    let capability = PrivateDirectory::from_std_directory_file_with_flush(
        clone,
        stage_path.to_path_buf(),
        Some(flush),
    )?;
    directory
        .validate_legacy_source_tree(stage_path)
        .map_err(snapshot_error)?;
    remove_retirement_contents(&capability)?;
    drop(capability);
    directory.remove_empty().map_err(snapshot_error)
}

#[cfg(not(windows))]
fn remove_empty_unix(
    parent: &PrivateDirectory,
    name: &std::ffi::OsStr,
    identity: &LegacyCapturedIdentity,
    path: &Path,
) -> StorageResult<()> {
    let child = parent.open_child(Path::new(name))?;
    let actual = unix_directory_identity(&child);
    if &actual != identity {
        return Err(snapshot_error(format!(
            "legacy empty source {} was replaced",
            path.display()
        )));
    }
    if !child.entries()?.is_empty() {
        return Err(snapshot_error(format!(
            "legacy empty source {} is no longer empty",
            path.display()
        )));
    }
    drop(child);
    parent.remove_directory(Path::new(name))?;
    parent.sync()
}

#[cfg(not(windows))]
fn move_unix(
    parent: &PrivateDirectory,
    name: &std::ffi::OsStr,
    identity: &LegacyCapturedIdentity,
    path: &Path,
    stage_path: &Path,
) -> StorageResult<()> {
    let current = parent.open_child(Path::new(name))?;
    if &unix_directory_identity(&current) != identity {
        return Err(snapshot_error(format!(
            "legacy source {} was replaced before retirement",
            path.display()
        )));
    }
    drop(current);
    let staging_parent = staging_parent(stage_path)?;
    let stage_name = stage_file_name(stage_path)?;
    let installed =
        parent.rename_child_to(Path::new(name), &staging_parent, Path::new(&stage_name))?;
    if &unix_directory_identity(&installed) != identity {
        return Err(snapshot_error(format!(
            "legacy retirement moved a replacement of {}",
            path.display()
        )));
    }
    // Publish the MOVE in both directories before deleting any source bytes.
    // Recovery must find the authorized stage after a crash during emptying.
    parent.sync()?;
    staging_parent.sync()?;
    drop(installed);
    Ok(())
}

#[cfg(not(windows))]
fn empty_staged_unix(
    parent: &PrivateDirectory,
    name: &std::ffi::OsStr,
    identity: &LegacyCapturedIdentity,
    path: &Path,
) -> StorageResult<()> {
    let installed = parent.open_child(Path::new(name))?;
    if &unix_directory_identity(&installed) != identity {
        return Err(snapshot_error(format!(
            "legacy retirement stage {} was replaced",
            path.display()
        )));
    }
    validate_retirement_tree(&installed)?;
    remove_retirement_contents(&installed)?;
    drop(installed);
    let confirmation = parent.open_child(Path::new(name))?;
    if &unix_directory_identity(&confirmation) != identity || !confirmation.entries()?.is_empty() {
        return Err(snapshot_error(
            "legacy retirement stage changed before empty removal",
        ));
    }
    drop(confirmation);
    parent.remove_directory(Path::new(name))?;
    parent.sync()
}

fn capture_authorized_blocking(
    stage_path: &Path,
    intent: &LegacyRetirementIntent,
) -> StorageResult<LegacyRetirementStage> {
    if !directory_present(stage_path)? {
        return Err(snapshot_error(
            "legacy retirement stage is absent; Authorized resume cannot publish Staged",
        ));
    }
    let stage = capture_present_stage(stage_path, intent)?;
    if stage.fence.is_none() {
        return Err(snapshot_error(
            "legacy retirement stage LOCK is missing; deletion cannot have begun before Staged",
        ));
    }
    Ok(stage)
}

fn resume_stage(stage_path: &Path, intent: &LegacyRetirementIntent) -> StorageResult<()> {
    capture_present_stage(stage_path, intent)?.finish_blocking()
}

fn capture_present_stage(
    stage_path: &Path,
    intent: &LegacyRetirementIntent,
) -> StorageResult<LegacyRetirementStage> {
    #[cfg(windows)]
    {
        capture_present_stage_windows(stage_path, intent)
    }
    #[cfg(not(windows))]
    {
        capture_present_stage_unix(stage_path, intent)
    }
}

#[cfg(windows)]
fn capture_present_stage_windows(
    stage_path: &Path,
    intent: &LegacyRetirementIntent,
) -> StorageResult<LegacyRetirementStage> {
    let directory =
        astrid_core::platform_fs::CapturedDirectory::open(stage_path).map_err(snapshot_error)?;
    let actual = LegacyCapturedIdentity::from_windows_directory(directory.identity());
    if &actual != intent.captured_root() {
        return Err(snapshot_error(
            "legacy retirement stage identity does not match captured source",
        ));
    }
    let clone = directory
        .try_clone_directory_file()
        .map_err(snapshot_error)?;
    let capability = PrivateDirectory::from_std_directory_file(clone, stage_path.to_path_buf())?;
    let lock = acquire_stage_lock(&capability, intent)?;
    drop(capability);
    Ok(LegacyRetirementStage {
        captured: CapturedSource::Handle { directory },
        fence: lock.map(Arc::new),
        path: stage_path.to_path_buf(),
    })
}

#[cfg(not(windows))]
fn capture_present_stage_unix(
    stage_path: &Path,
    intent: &LegacyRetirementIntent,
) -> StorageResult<LegacyRetirementStage> {
    let parent = staging_parent(stage_path)?;
    let name = stage_file_name(stage_path)?;
    let installed = parent.open_child(Path::new(&name))?;
    if &unix_directory_identity(&installed) != intent.captured_root() {
        return Err(snapshot_error(
            "legacy retirement stage identity does not match captured source",
        ));
    }
    let lock = acquire_stage_lock(&installed, intent)?;
    drop(installed);
    Ok(LegacyRetirementStage {
        captured: CapturedSource::ParentRelative {
            parent,
            name,
            identity: intent.captured_root().clone(),
            path: stage_path.to_path_buf(),
        },
        fence: lock.map(Arc::new),
    })
}

fn acquire_stage_lock(
    directory: &PrivateDirectory,
    intent: &LegacyRetirementIntent,
) -> StorageResult<Option<std::fs::File>> {
    let Some(expected) = intent.captured_lock() else {
        return Ok(None);
    };
    if !directory.contains(Path::new("LOCK"))? {
        return Ok(None);
    }
    let lock = directory.open_file(Path::new("LOCK"))?;
    let actual = super::owner::lock_identity(&lock)?;
    if &actual != expected {
        return Err(snapshot_error(
            "legacy retirement stage LOCK identity does not match captured source",
        ));
    }
    lock.try_lock_shared().map_err(snapshot_error)?;
    #[cfg(windows)]
    let lock = super::source_lock::handoff(lock).map_err(snapshot_error)?;
    Ok(Some(lock))
}

fn directory_present(path: &Path) -> StorageResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(snapshot_error(format!(
                "legacy retirement path is redirected or not a directory: {}",
                path.display()
            )))
        },
        Ok(_) => {
            astrid_core::platform_fs::verify_no_redirects(path).map_err(snapshot_error)?;
            Ok(true)
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(snapshot_error(error)),
    }
}

#[cfg(not(windows))]
fn staging_parent(stage_path: &Path) -> StorageResult<PrivateDirectory> {
    let parent = stage_path.parent().ok_or_else(|| {
        snapshot_error(format!(
            "legacy retirement stage {} has no parent",
            stage_path.display()
        ))
    })?;
    PrivateDirectory::open(parent)
}

#[cfg(not(windows))]
fn stage_file_name(stage_path: &Path) -> StorageResult<std::ffi::OsString> {
    stage_path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .ok_or_else(|| {
            snapshot_error(format!(
                "legacy retirement stage {} has no name",
                stage_path.display()
            ))
        })
}

#[cfg(not(windows))]
fn unix_directory_identity(directory: &PrivateDirectory) -> LegacyCapturedIdentity {
    let (volume, inode) = directory.raw_identity();
    LegacyCapturedIdentity::from_unix(volume, inode)
}
