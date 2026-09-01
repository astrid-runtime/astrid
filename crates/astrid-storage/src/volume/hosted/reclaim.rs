//! Crash-safe physical reclamation for the hosted volume adapter.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use fs2::FileExt as _;

use super::recover::FOOTER_BYTES;
use super::{
    ContainerState, HostedFileVolume, Operation, PhysicalTail, RegionState, RootSlot, VOLUME_MAGIC,
    overlay_extent,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReclaimStage {
    BoundImagePublished,
    RootPublished,
    ReplacementDurable,
    FinalImageDurable,
    FinalRootPublished,
    Truncated,
}

#[cfg(test)]
type StageHook = Box<dyn FnMut(ReclaimStage) -> io::Result<()> + Send>;

#[cfg(test)]
static STAGE_HOOK: std::sync::OnceLock<std::sync::Mutex<BTreeMap<PathBuf, StageHook>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
pub(super) fn set_stage_hook(path: PathBuf, hook: StageHook) {
    STAGE_HOOK
        .get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
        .lock()
        .expect("hosted reclaim stage hook lock")
        .insert(path, hook);
}

#[cfg(test)]
fn run_stage(path: &Path, stage: ReclaimStage) -> io::Result<()> {
    let mut hooks = STAGE_HOOK
        .get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
        .lock()
        .expect("hosted reclaim stage hook lock");
    if let Some(hook) = hooks.get_mut(path) {
        hook(stage)?;
    }
    Ok(())
}

#[cfg(not(test))]
#[allow(clippy::unnecessary_wraps)]
#[inline]
fn run_stage(_path: &Path, _stage: ReclaimStage) -> io::Result<()> {
    Ok(())
}

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

fn finish_image(state: &mut ContainerState) -> io::Result<u64> {
    let commit_region = super::VolumeRegion::new(super::COMMIT_REGION)?;
    let snapshot = super::recover::encode_region_snapshot(&state.regions)?;
    let commit_offset = state.valid_len;
    HostedFileVolume::append(state, Operation::Commit, &commit_region, 0, &snapshot)?;
    state.last_commit_offset = commit_offset;
    state.durable_len = state.valid_len;
    state.last_commit_has_snapshot = true;
    state.boundary_pending = true;
    super::recover::write_footer(
        &mut state.file,
        state.last_commit_offset,
        state.durable_len,
        state.sequence,
    )?;
    state.file.sync_all()?;
    state
        .durable_len
        .checked_add(FOOTER_BYTES as u64)
        .ok_or_else(|| io::Error::other("volume reclaim authority overflow"))
}

fn build_image(
    source: &mut ContainerState,
    start: u64,
    generation: u64,
    root_base: u64,
    limit: u64,
) -> io::Result<ContainerState> {
    let mut rebuilt = ContainerState {
        file: source.file.try_clone()?,
        generation,
        root_base,
        root_slot: source.root_slot,
        sequence: 0,
        valid_len: start,
        durable_len: start,
        last_commit_offset: 0,
        last_commit_has_snapshot: false,
        boundary_pending: true,
        footer_pending: false,
        physical_tail: PhysicalTail::PreserveSelected,
        regions: BTreeMap::new(),
    };
    let source_regions = source.regions.clone();
    for (region, source_region) in &source_regions {
        if rebuilt.valid_len > limit {
            return Err(io::Error::other("volume reclaim replacement exceeds bound"));
        }
        HostedFileVolume::append(&mut rebuilt, Operation::Create, region, 0, &[])?;
        rebuilt
            .regions
            .insert(region.clone(), RegionState::default());
        let mut offset = 0_u64;
        while offset < source_region.length {
            let remaining = source_region
                .length
                .checked_sub(offset)
                .ok_or_else(|| io::Error::other("volume reclaim source range underflow"))?;
            let length = usize::try_from(remaining.min(64 * 1024))
                .map_err(|_| io::Error::other("volume reclaim chunk length overflow"))?;
            let mut bytes = vec![0_u8; length];
            read_region(source, source_region, offset, &mut bytes)?;
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
    Ok(rebuilt)
}

fn publish_root(
    path: &Path,
    state: &mut ContainerState,
    generation: u64,
    root_base: u64,
    footer_offset: u64,
) -> io::Result<()> {
    let first_slot = state.root_slot == RootSlot::Second;
    super::recover::write_root_pointer(
        &mut state.file,
        generation,
        root_base,
        footer_offset,
        first_slot,
    )?;
    state.file.sync_all()?;
    state.generation = generation;
    state.root_base = root_base;
    state.root_slot = if first_slot {
        RootSlot::Second
    } else {
        RootSlot::First
    };
    if root_base == super::ROOT_BYTES as u64 && generation > 1 {
        run_stage(path, ReclaimStage::FinalRootPublished)?;
    } else if generation == 1 {
        run_stage(path, ReclaimStage::BoundImagePublished)?;
    } else {
        run_stage(path, ReclaimStage::RootPublished)?;
    }
    super::recover::write_root_pointer(
        &mut state.file,
        generation,
        root_base,
        footer_offset,
        !first_slot,
    )?;
    state.file.sync_all()?;
    state.root_slot = if first_slot {
        RootSlot::First
    } else {
        RootSlot::Second
    };
    Ok(())
}

fn reset_to_generation_zero(state: &mut ContainerState) -> io::Result<()> {
    state.generation = 0;
    state.root_base = u64::try_from(VOLUME_MAGIC.len())
        .map_err(|_| io::Error::other("volume header length overflow"))?;
    state.root_slot = RootSlot::First;
    state.physical_tail = PhysicalTail::TruncateToValid;
    Ok(())
}

fn install_image(state: &mut ContainerState, image: ContainerState) {
    let ContainerState {
        file,
        sequence,
        valid_len,
        durable_len,
        last_commit_offset,
        last_commit_has_snapshot,
        boundary_pending,
        footer_pending,
        regions,
        ..
    } = image;
    state.file = file;
    state.sequence = sequence;
    state.valid_len = valid_len;
    state.durable_len = durable_len;
    state.last_commit_offset = last_commit_offset;
    state.last_commit_has_snapshot = last_commit_has_snapshot;
    state.boundary_pending = boundary_pending;
    state.footer_pending = footer_pending;
    state.regions = regions;
}

fn bind_generation_zero(
    path: &Path,
    state: &mut ContainerState,
    physical_len: u64,
) -> io::Result<()> {
    if physical_len <= VOLUME_MAGIC.len() as u64 {
        if state.regions.is_empty()
            && state.valid_len == VOLUME_MAGIC.len() as u64
            && state.last_commit_offset == 0
        {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hosted volume is too small for inode-stable publication",
        ));
    }
    let bound_base = physical_len;
    let mut bound = build_image(state, bound_base, 1, bound_base, u64::MAX)?;
    let bound_end = finish_image(&mut bound)?;
    let bound_footer = bound_end
        .checked_sub(FOOTER_BYTES as u64)
        .ok_or_else(|| io::Error::other("volume bound authority underflow"))?;
    publish_root(path, state, 1, bound_base, bound_footer)?;
    install_image(state, bound);
    Ok(())
}

pub(super) fn reclaim_same_inode(volume: &HostedFileVolume) -> io::Result<()> {
    let _open_guard = volume.open_lock.lock();
    let mut state = volume.state.lock();
    let path = volume.path.clone();
    HostedFileVolume::make_durable(&mut state)?;
    let physical_len = state.file.metadata()?.len();
    if state.generation == 0 {
        bind_generation_zero(&path, &mut state, physical_len)?;
        if state.generation == 0 {
            return Ok(());
        }
    }
    let root_generation = state.generation;
    let replacement_base = state.file.metadata()?.len();
    let replacement_generation = root_generation
        .checked_add(1)
        .ok_or_else(|| io::Error::other("Astrid volume generation exhausted"))?;
    let mut replacement = build_image(
        &mut state,
        replacement_base,
        replacement_generation,
        replacement_base,
        u64::MAX,
    )?;
    let replacement_end = finish_image(&mut replacement)?;
    run_stage(&volume.path, ReclaimStage::ReplacementDurable)?;
    publish_root(
        &path,
        &mut state,
        replacement_generation,
        replacement_base,
        replacement_end
            .checked_sub(FOOTER_BYTES as u64)
            .ok_or_else(|| io::Error::other("volume reclaim authority underflow"))?,
    )?;
    install_image(&mut state, replacement);

    let candidate_base = replacement_base;
    let final_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| io::Error::other("Astrid volume generation exhausted"))?;
    let mut finalized = build_image(
        &mut state,
        super::ROOT_BYTES as u64,
        final_generation,
        super::ROOT_BYTES as u64,
        candidate_base,
    )?;
    let final_end = finish_image(&mut finalized)?;
    if final_end > candidate_base {
        return Err(io::Error::other("volume reclaim did not shrink the image"));
    }
    run_stage(&volume.path, ReclaimStage::FinalImageDurable)?;
    publish_root(
        &path,
        &mut state,
        final_generation,
        super::ROOT_BYTES as u64,
        final_end
            .checked_sub(FOOTER_BYTES as u64)
            .ok_or_else(|| io::Error::other("volume reclaim authority underflow"))?,
    )?;
    install_image(&mut state, finalized);

    state.file.set_len(final_end)?;
    state.file.sync_all()?;
    run_stage(&volume.path, ReclaimStage::Truncated)?;
    Ok(())
}

pub(super) fn reclaim(volume: &HostedFileVolume) -> io::Result<()> {
    let _open_guard = volume.open_lock.lock();
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
        generation: 0,
        root_base: VOLUME_MAGIC.len() as u64,
        root_slot: RootSlot::First,
        sequence: 0,
        valid_len: 0,
        durable_len: 0,
        last_commit_offset: 0,
        last_commit_has_snapshot: false,
        boundary_pending: false,
        footer_pending: true,
        physical_tail: PhysicalTail::TruncateToValid,
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
    reset_to_generation_zero(&mut state)?;
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
