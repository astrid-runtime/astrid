//! Crash-safe physical reclamation for the hosted volume adapter.

use super::IndexCheckpoint;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
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

pub(super) fn recover_artifacts(
    path: &Path,
    #[cfg(windows)] runtime_private: bool,
) -> io::Result<File> {
    let temporary = temp_path(path);
    let previous = previous_path(path);
    let active = std::fs::symlink_metadata(path).is_ok();
    if !active {
        // During a failed Windows replacement the live owner can still
        // hold the old inode at .previous after the rebuilt handle drops.
        // Prefer that inode: its lock fences recovery throughout rollback.
        let candidate = if std::fs::symlink_metadata(&previous).is_ok() {
            &previous
        } else {
            &temporary
        };
        if std::fs::symlink_metadata(candidate).is_ok() {
            let file = super::open::open_regular(
                candidate,
                false,
                #[cfg(windows)]
                runtime_private,
            )?;
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
    let file = super::open::open_regular(
        path,
        !active,
        #[cfg(windows)]
        runtime_private,
    )?;
    lock_active(&file)?;
    Ok(file)
}

pub(super) fn lock_active(file: &File) -> io::Result<()> {
    file.try_lock_exclusive().map_err(|error| {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
            || error.kind() == io::ErrorKind::WouldBlock
        {
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

fn create_file(path: &Path, #[cfg(windows)] runtime_private: bool) -> io::Result<File> {
    #[cfg(windows)]
    if runtime_private {
        return astrid_core::platform_fs::create_new_private_file_shared(path);
    }
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

pub(super) fn reclaim(volume: &HostedFileVolume) -> io::Result<()> {
    let _open_guard = volume.open_lock.lock();
    let mut state = volume.state.lock();
    reclaim_locked(
        &volume.path,
        &mut state,
        #[cfg(windows)]
        volume._retained_root.is_some(),
    )
}

pub(super) fn reclaim_locked(
    path: &Path,
    state: &mut ContainerState,
    #[cfg(windows)] runtime_private: bool,
) -> io::Result<()> {
    finish_publication(path, state)?;
    let temporary = temp_path(path);
    let previous = previous_path(path);
    if std::fs::symlink_metadata(&temporary).is_ok() {
        std::fs::remove_file(&temporary)?;
    }
    if std::fs::symlink_metadata(&previous).is_ok() {
        std::fs::remove_file(&previous)?;
    }
    let temporary_file = create_file(
        &temporary,
        #[cfg(windows)]
        runtime_private,
    )?;
    let mut rebuilt = ContainerState {
        checkpoint_format: state.checkpoint_format,
        index_checkpoint: IndexCheckpoint::NotPrepared,
        file: temporary_file,
        sequence: 0,
        valid_len: 0,
        durable_len: 0,
        last_commit_offset: 0,
        last_snapshot_end: 0,
        boundary_pending: false,
        footer_pending: true,
        physical_tail: super::PhysicalTail::Exact,
        flush_state: super::FlushState::Required,
        publication_pending: false,
        #[cfg(windows)]
        restore: super::RestoreState::NotRequired,
        regions: BTreeMap::new(),
    };
    // Magic is a file mutation: mark uncertain before the write, Exact only after
    // valid_len catches up to the published header.
    rebuilt.physical_tail = super::PhysicalTail::MayExceed;
    rebuilt.file.write_all(&VOLUME_MAGIC)?;
    rebuilt.valid_len = u64::try_from(VOLUME_MAGIC.len())
        .map_err(|_| io::Error::other("volume header length overflow"))?;
    rebuilt.physical_tail = super::PhysicalTail::Exact;
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
    // Both inode handles stay locked through publication. Unix replacement is
    // atomic; Windows uses durable staged moves with a mandatory restore on
    // failure. Open verifies inode identity before recovery or cleanup. After success,
    // install state before any further fallible operation.
    #[cfg(windows)]
    if let Err(error) = publish(&temporary, path, state, &rebuilt.file) {
        if super::open::require_current(&rebuilt.file, path).is_ok() {
            // The move happened but its durability barrier failed. Adopt the
            // current locked descriptor, preserve the error, and require a
            // successful publication flush before any later acknowledgement.
            rebuilt.flush_state = super::FlushState::Required;
            rebuilt.publication_pending = true;
            *state = rebuilt;
        }
        return Err(error);
    }
    #[cfg(not(windows))]
    publish(&temporary, path, state, &rebuilt.file)?;
    rebuilt.flush_state = super::FlushState::Required;
    rebuilt.publication_pending = true;
    *state = rebuilt;
    finish_publication(path, state)
}

pub(super) fn finish_publication(path: &Path, state: &mut ContainerState) -> io::Result<()> {
    #[cfg(windows)]
    if state.restore == super::RestoreState::Required {
        if super::open::require_current(&state.file, path).is_err() {
            super::open::require_current(&state.file, &previous_path(path))?;
            restore_name(path, state)?;
        }
        flush_publication(&state.file)?;
        if temp_path(path).exists() {
            std::fs::remove_file(temp_path(path))?;
        }
        state.restore = super::RestoreState::NotRequired;
    }
    if state.publication_pending {
        sync_publication(path, &state.file)?;
        #[cfg(windows)]
        if previous_path(path).exists() {
            std::fs::remove_file(previous_path(path))?;
        }
        state.publication_pending = false;
    }
    Ok(())
}

#[cfg(windows)]
fn restore_name(path: &Path, state: &ContainerState) -> io::Result<()> {
    if let Err(error) = promote(&previous_path(path), path)
        && super::open::require_current(&state.file, path).is_err()
    {
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
fn flush_publication(file: &File) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_PUBLICATION_FLUSH.with(|fail| fail.replace(false)) {
        return Err(io::Error::other("injected publication flush failure"));
    }
    file.sync_all()
}

#[cfg(test)]
thread_local! {
    pub(super) static FAIL_DIRECTORY_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn sync_publication(path: &Path, file: &File) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
        return Err(io::Error::other("injected directory flush failure"));
    }
    #[cfg(windows)]
    {
        let _ = path;
        flush_publication(file)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        sync_parent(path)
    }
}

#[cfg(not(windows))]
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
    }
    #[cfg(not(unix))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "volume publication durability is unsupported",
    ))
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
        super::region_io::read(self.file, self.region, self.offset, &mut buffer[..length])?;
        self.offset = self.offset.strict_add(length as u64);
        Ok(length)
    }
}

#[cfg(unix)]
fn publish(
    source: &Path,
    destination: &Path,
    _state: &mut ContainerState,
    _rebuilt: &File,
) -> io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(all(test, windows))]
thread_local! {
    pub(super) static FAIL_PROMOTIONS: std::cell::RefCell<std::collections::VecDeque<bool>> = const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
    pub(super) static FAIL_AFTER_PROMOTIONS: std::cell::RefCell<std::collections::VecDeque<bool>> = const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
    pub(super) static FAIL_PUBLICATION_FLUSH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static AFTER_DETACH: std::cell::RefCell<Option<SwapHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(windows)]
fn publish(
    source: &Path,
    destination: &Path,
    state: &mut ContainerState,
    rebuilt: &File,
) -> io::Result<()> {
    // Windows rejects replacing an exclusively locked destination. Detach its
    // name without replacing an inode, keeping both locks through the move.
    // Every prefix has a fully flushed old or rebuilt recovery candidate.
    let previous = previous_path(destination);
    if let Err(error) = promote(destination, &previous) {
        // A failed write-through move may have changed the namespace before
        // reporting its flush error. Only a verified old active inode permits
        // the unchanged-state path; otherwise restoration remains mandatory.
        state.restore = if super::open::require_current(&state.file, destination).is_ok() {
            super::RestoreState::NotRequired
        } else {
            super::RestoreState::Required
        };
        return Err(error);
    }
    state.restore = super::RestoreState::Required;
    #[cfg(test)]
    if let Some(hook) = AFTER_DETACH.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
    if let Err(error) = promote(source, destination) {
        // Restore the old namespace before allowing a later successful sync.
        // If restoration also fails, finish_publication retries it; no flush
        // acknowledgement or Drop flush may bypass the unresolved move.
        if super::open::require_current(rebuilt, destination).is_err() {
            let _ = finish_publication(destination, state);
        }
        return Err(error);
    }
    state.restore = super::RestoreState::NotRequired;
    Ok(())
}

#[cfg(windows)]
fn promote(source: &Path, destination: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH;
    #[cfg(test)]
    if FAIL_PROMOTIONS.with(|fail| fail.borrow_mut().pop_front().unwrap_or(false)) {
        return Err(io::Error::other("injected Windows promotion failure"));
    }
    rename_windows(source, destination, MOVEFILE_WRITE_THROUGH)?;
    #[cfg(test)]
    if FAIL_AFTER_PROMOTIONS.with(|fail| fail.borrow_mut().pop_front().unwrap_or(false)) {
        return Err(io::Error::other("injected post-move Windows flush failure"));
    }
    Ok(())
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
fn publish(
    _source: &Path,
    _destination: &Path,
    _state: &mut ContainerState,
    _rebuilt: &File,
) -> io::Result<()> {
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
