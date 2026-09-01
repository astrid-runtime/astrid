//! Crash-safe physical reclamation for the hosted volume adapter.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use fs2::FileExt as _;

use super::{
    ContainerState, HostedFileVolume, Operation, RegionState, VOLUME_MAGIC, overlay_extent,
};

// Reclaim closes the old inode before swapping the active path. Tests pause
// at that narrow boundary to prove a concurrent opener cannot acquire the
// retired inode while the swap is in flight. This hook is test-only.
#[cfg(test)]
type UnlockHook = Box<dyn FnOnce() + Send + 'static>;

#[cfg(test)]
static UNLOCK_HOOK: OnceLock<Mutex<Option<(PathBuf, UnlockHook)>>> = OnceLock::new();

#[cfg(test)]
pub(super) fn set_test_unlock_hook(path: PathBuf, hook: UnlockHook) {
    *UNLOCK_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("hosted reclaim test hook lock") = Some((path, hook));
}

#[cfg(test)]
fn run_test_unlock_hook(path: &Path) {
    let mut hook = UNLOCK_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("hosted reclaim test hook lock");
    if hook.as_ref().is_some_and(|(target, _)| target == path)
        && let Some((_, hook)) = hook.take()
    {
        hook();
    }
}

#[cfg(not(test))]
#[inline]
fn run_test_unlock_hook(_path: &Path) {}

pub(super) fn temp_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.compacting", path.display()))
}

pub(super) fn previous_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.previous", path.display()))
}

pub(super) fn recover_artifacts(path: &Path) -> io::Result<()> {
    let temporary = temp_path(path);
    let previous = previous_path(path);
    let active = std::fs::symlink_metadata(path).is_ok();
    if !active {
        if std::fs::symlink_metadata(&temporary).is_ok() {
            std::fs::rename(&temporary, path)?;
        } else if std::fs::symlink_metadata(&previous).is_ok() {
            std::fs::rename(&previous, path)?;
        }
    }
    if std::fs::symlink_metadata(path).is_ok() {
        if std::fs::symlink_metadata(&temporary).is_ok() {
            std::fs::remove_file(&temporary)?;
        }
        if std::fs::symlink_metadata(&previous).is_ok() {
            std::fs::remove_file(&previous)?;
        }
    }
    Ok(())
}

fn create_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn read_region(
    state: &mut ContainerState,
    region: &RegionState,
    offset: u64,
    buffer: &mut [u8],
) -> io::Result<()> {
    buffer.fill(0);
    let end = offset
        .checked_add(
            u64::try_from(buffer.len())
                .map_err(|_| io::Error::other("volume reclaim buffer length overflow"))?,
        )
        .ok_or_else(|| io::Error::other("volume reclaim range overflow"))?;
    for (start, extent) in region.extents.range(..end) {
        if extent.logical_end <= offset {
            continue;
        }
        let copy_start = (*start).max(offset);
        let copy_end = extent.logical_end.min(end);
        if copy_start >= copy_end {
            continue;
        }
        let physical = extent
            .physical_offset
            .checked_add(copy_start.saturating_sub(*start))
            .ok_or_else(|| io::Error::other("volume reclaim extent overflow"))?;
        let destination = usize::try_from(copy_start.saturating_sub(offset))
            .map_err(|_| io::Error::other("volume reclaim destination overflow"))?;
        let length = usize::try_from(copy_end.saturating_sub(copy_start))
            .map_err(|_| io::Error::other("volume reclaim extent length overflow"))?;
        let destination_end = destination
            .checked_add(length)
            .ok_or_else(|| io::Error::other("volume reclaim destination range overflow"))?;
        state.file.seek(SeekFrom::Start(physical))?;
        state
            .file
            .read_exact(&mut buffer[destination..destination_end])?;
    }
    Ok(())
}

pub(super) fn reclaim(volume: &HostedFileVolume) -> io::Result<()> {
    let _open_guard = volume.open_lock.lock();
    volume.verify_owner_proved_reclaim()?;
    let mut state = volume.state.lock();
    let temporary = temp_path(&volume.path);
    let previous = previous_path(&volume.path);
    if std::fs::symlink_metadata(&temporary).is_ok() {
        std::fs::remove_file(&temporary)?;
    }
    if std::fs::symlink_metadata(&previous).is_ok() {
        std::fs::remove_file(&previous)?;
    }
    let temporary_file = create_file(&temporary)?;
    let mut rebuilt = ContainerState {
        file: temporary_file,
        sequence: 0,
        valid_len: 0,
        durable_len: 0,
        last_commit_offset: 0,
        last_commit_has_snapshot: false,
        boundary_pending: false,
        footer_pending: true,
        regions: BTreeMap::new(),
    };
    rebuilt.file.write_all(&VOLUME_MAGIC)?;
    rebuilt.valid_len = u64::try_from(VOLUME_MAGIC.len())
        .map_err(|_| io::Error::other("volume header length overflow"))?;
    let source_regions = state.regions.clone();
    for (region, source) in &source_regions {
        HostedFileVolume::append(&mut rebuilt, Operation::Create, region, 0, &[])?;
        rebuilt
            .regions
            .insert(region.clone(), RegionState::default());
        let mut offset = 0_u64;
        while offset < source.length {
            let remaining = source
                .length
                .checked_sub(offset)
                .ok_or_else(|| io::Error::other("volume reclaim source range underflow"))?;
            let length = usize::try_from(remaining.min(64 * 1024))
                .map_err(|_| io::Error::other("volume reclaim chunk length overflow"))?;
            let mut bytes = vec![0_u8; length];
            read_region(&mut state, source, offset, &mut bytes)?;
            let (physical, _) =
                HostedFileVolume::append(&mut rebuilt, Operation::Write, region, offset, &bytes)?;
            let end = offset
                .checked_add(
                    u64::try_from(length)
                        .map_err(|_| io::Error::other("volume reclaim write length overflow"))?,
                )
                .ok_or_else(|| io::Error::other("volume reclaim write range overflow"))?;
            let destination = rebuilt
                .regions
                .get_mut(region)
                .ok_or_else(|| io::Error::other("rebuilt volume region disappeared"))?;
            overlay_extent(&mut destination.extents, offset, end, physical);
            destination.length = destination.length.max(end);
            offset = end;
        }
    }
    HostedFileVolume::make_durable(&mut rebuilt)?;
    let rebuilt_regions = rebuilt.regions.clone();
    let rebuilt_sequence = rebuilt.sequence;
    let rebuilt_len = rebuilt.valid_len;
    let rebuilt_commit_offset = rebuilt.last_commit_offset;
    let rebuilt_has_snapshot = rebuilt.last_commit_has_snapshot;
    rebuilt.file.sync_all()?;
    drop(rebuilt);

    // Close the old locked inode before replacement. Recovery of the sibling
    // artifacts handles a process crash between either rename.
    let placeholder = OpenOptions::new().read(true).write(true).open(&temporary)?;
    let old_file = std::mem::replace(&mut state.file, placeholder);
    old_file.unlock()?;
    drop(old_file);
    run_test_unlock_hook(&volume.path);
    std::fs::rename(&volume.path, &previous)?;
    if let Err(error) = std::fs::rename(&temporary, &volume.path) {
        let _ = std::fs::rename(&previous, &volume.path);
        return Err(error);
    }
    let replacement = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&volume.path)?;
    replacement.try_lock_exclusive()?;
    let placeholder = std::mem::replace(&mut state.file, replacement);
    drop(placeholder);
    state.sequence = rebuilt_sequence;
    state.valid_len = rebuilt_len;
    state.durable_len = rebuilt_len;
    state.last_commit_offset = rebuilt_commit_offset;
    state.last_commit_has_snapshot = rebuilt_has_snapshot;
    state.boundary_pending = false;
    state.footer_pending = false;
    state.regions = rebuilt_regions;
    std::fs::remove_file(previous)?;
    Ok(())
}
