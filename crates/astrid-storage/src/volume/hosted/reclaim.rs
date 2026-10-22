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

// Tests pause immediately before atomic publication, with both inode locks
// held.
#[cfg(test)]
type SwapHook = Box<dyn FnOnce() + Send + 'static>;

#[cfg(test)]
static SWAP_HOOK: OnceLock<Mutex<BTreeMap<PathBuf, SwapHook>>> = OnceLock::new();

#[cfg(test)]
pub(super) fn set_test_swap_hook(path: PathBuf, hook: SwapHook) {
    SWAP_HOOK
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .expect("hosted reclaim test hook lock")
        .insert(path, hook);
}

#[cfg(test)]
fn run_test_swap_hook(path: &Path) {
    let hook = SWAP_HOOK
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .expect("hosted reclaim test hook lock")
        .remove(path);
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
#[inline]
fn run_test_swap_hook(_path: &Path) {}

pub(super) fn temp_path(path: &Path) -> PathBuf {
    sibling_path(path, ".compacting")
}

pub(super) fn previous_path(path: &Path) -> PathBuf {
    sibling_path(path, ".previous")
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

pub(super) fn recover_artifacts(path: &Path) -> io::Result<File> {
    let temporary = temp_path(path);
    let previous = previous_path(path);
    let active = std::fs::symlink_metadata(path).is_ok();
    if !active {
        let candidate = if std::fs::symlink_metadata(&temporary).is_ok() {
            &temporary
        } else {
            &previous
        };
        if std::fs::symlink_metadata(candidate).is_ok() {
            let file = super::open::open_regular(candidate, false)?;
            lock_active(&file)?;
            super::open::require_current(&file, candidate)?;
            // No overwrite: a concurrent opener may have just created or
            // promoted the active path. Keep the locked source until recovery
            // validates the active container and removes obsolete artifacts.
            match promote(candidate, path) {
                Ok(()) => {},
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
                Err(error) => return Err(error),
            }
            super::open::require_current(&file, path)?;
            // Transfer the locked descriptor itself. Closing and reopening
            // creates a lock handoff gap; a concurrent fork can also retain
            // the old open description until its exec closes inherited FDs.
            return Ok(file);
        }
    }
    let file = super::open::open_regular(path, !active)?;
    lock_active(&file)?;
    Ok(file)
}

fn lock_active(file: &File) -> io::Result<()> {
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(io::ErrorKind::WouldBlock, "Astrid volume is already open")
        } else {
            error
        }
    })
}

// Only after the active container has recovered successfully, while holding
// the verified active inode lock, may obsolete swap artifacts be removed.
pub(super) fn cleanup_artifacts(path: &Path) -> io::Result<()> {
    let temporary = temp_path(path);
    let previous = previous_path(path);
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
    file: &mut File,
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
    let first = region
        .extents
        .range(..=offset)
        .next_back()
        .map_or(offset, |(start, _)| *start);
    for (start, extent) in region.extents.range(first..end) {
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
        file.seek(SeekFrom::Start(physical))?;
        file.read_exact(&mut buffer[destination..destination_end])?;
    }
    Ok(())
}

pub(super) fn reclaim(volume: &HostedFileVolume) -> io::Result<()> {
    let _open_guard = volume.open_lock.lock();
    let mut state = volume.state.lock();
    reclaim_locked(&volume.path, &mut state)
}

pub(super) fn reclaim_locked(path: &Path, state: &mut ContainerState) -> io::Result<()> {
    finish_publication(path, state)?;
    let temporary = temp_path(path);
    let previous = previous_path(path);
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
        last_snapshot_end: 0,
        boundary_pending: false,
        footer_pending: true,
        flush_state: super::FlushState::Required,
        publication_pending: false,
        regions: BTreeMap::new(),
    };
    rebuilt.file.write_all(&VOLUME_MAGIC)?;
    rebuilt.valid_len = u64::try_from(VOLUME_MAGIC.len())
        .map_err(|_| io::Error::other("volume header length overflow"))?;
    for (region, source) in &state.regions {
        HostedFileVolume::append(&mut rebuilt, Operation::Create, region, 0, &[])?;
        rebuilt
            .regions
            .insert(region.clone(), RegionState::default());
        if source.length != 0 {
            let mut reader = RegionReader {
                file: &mut state.file,
                region: source,
                offset: 0,
            };
            let (physical, _) = super::stream::append_from(
                &mut rebuilt,
                Operation::Write,
                region,
                0,
                source.length,
                &mut reader,
            )?;
            let destination = rebuilt
                .regions
                .get_mut(region)
                .ok_or_else(|| io::Error::other("rebuilt volume region disappeared"))?;
            overlay_extent(&mut destination.extents, 0, source.length, physical);
            destination.length = source.length;
        }
    }
    HostedFileVolume::make_durable(&mut rebuilt)?;
    rebuilt.file.sync_all()?;
    rebuilt.file.try_lock_exclusive()?;
    run_test_swap_hook(path);
    // Atomic replacement leaves the old state usable on failure. Both inode
    // handles stay locked through publication; open verifies inode identity after locking
    // before performing recovery or cleanup. Install state before any fallible operation.
    publish(&temporary, path)?;
    rebuilt.flush_state = super::FlushState::Required;
    rebuilt.publication_pending = true;
    *state = rebuilt;
    finish_publication(path, state)
}

pub(super) fn finish_publication(path: &Path, state: &mut ContainerState) -> io::Result<()> {
    if state.publication_pending {
        sync_parent(path)?;
        state.publication_pending = false;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    pub(super) static FAIL_DIRECTORY_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
        return Err(io::Error::other("injected directory flush failure"));
    }
    #[cfg(unix)]
    {
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    }
    #[cfg(windows)]
    {
        // Both replacement and artifact promotion use MoveFileExW with
        // MOVEFILE_WRITE_THROUGH: its documented contract completes the move
        // on disk before returning. There is no deferred parent flush here.
        let _ = path;
    }
    #[cfg(not(any(unix, windows)))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "volume publication durability is unsupported",
    ));
    Ok(())
}

struct RegionReader<'a> {
    file: &'a mut File,
    region: &'a RegionState,
    offset: u64,
}

impl Read for RegionReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.region.length.saturating_sub(self.offset);
        let length = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("volume reclaim read length overflow"))?;
        if length == 0 {
            return Ok(0);
        }
        read_region(self.file, self.region, self.offset, &mut buffer[..length])?;
        self.offset = self.offset.strict_add(length as u64);
        Ok(length)
    }
}

#[cfg(unix)]
fn publish(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn publish(source: &Path, destination: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    rename_windows(
        source,
        destination,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
    )
}

#[cfg(windows)]
fn promote(source: &Path, destination: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH;
    rename_windows(source, destination, MOVEFILE_WRITE_THROUGH)
}

#[cfg(unix)]
fn promote(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::hard_link(source, destination)?;
    sync_parent(destination)
}

#[cfg(windows)]
fn rename_windows(source: &Path, destination: &Path, flags: u32) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
    let wide = |path: &Path| -> io::Result<Vec<u16>> {
        let mut value: Vec<_> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "volume path contains NUL",
            ));
        }
        value.push(0);
        Ok(value)
    };
    let source = wide(source)?;
    let destination = wide(destination)?;
    // SAFETY: both NUL-terminated buffers remain live for this call. No
    // cross-volume copy fallback is allowed; staging is a sibling file.
    #[allow(unsafe_code)]
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn publish(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic volume publication is unsupported",
    ))
}

#[cfg(not(any(unix, windows)))]
fn promote(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "volume artifact promotion is unsupported",
    ))
}
