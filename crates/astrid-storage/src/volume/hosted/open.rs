//! Serialized open and reclaim coordination for hosted volume containers.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock, Weak};

use parking_lot::{Mutex, MutexGuard};

use super::{ContainerState, HostedFileVolume, VOLUME_MAGIC, reclaim, recover};

type SharedOpenReclaimLock = Mutex<()>;

static OPEN_LOCKS: OnceLock<RwLock<BTreeMap<PathBuf, Weak<SharedOpenReclaimLock>>>> =
    OnceLock::new();

/// Process-local serialization shared by open and physical reclaim for one
/// canonical parent plus final path component.
pub(super) struct OpenReclaimLock(Arc<SharedOpenReclaimLock>);

impl OpenReclaimLock {
    fn for_path(path: &Path) -> io::Result<Self> {
        let parent = path.parent().unwrap_or(Path::new("/"));
        let canonical_parent = std::fs::canonicalize(parent)?;
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Astrid volume path has no file name",
            )
        })?;
        let key = canonical_parent.join(file_name);
        let registry = OPEN_LOCKS.get_or_init(|| RwLock::new(BTreeMap::new()));
        if let Some(lock) = registry
            .read()
            .expect("Astrid volume open-lock registry")
            .get(&key)
            .and_then(Weak::upgrade)
        {
            return Ok(Self(lock));
        }
        let mut guards = registry.write().expect("Astrid volume open-lock registry");
        if let Some(lock) = guards.get(&key).and_then(Weak::upgrade) {
            return Ok(Self(lock));
        }
        guards.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        guards.insert(key, Arc::downgrade(&lock));
        Ok(Self(lock))
    }

    pub(super) fn lock(&self) -> MutexGuard<'_, ()> {
        self.0.lock()
    }
}

impl HostedFileVolume {
    /// Open or create one hosted Astrid volume container.
    ///
    /// # Errors
    ///
    /// Returns an error for a lock conflict, invalid header, interior corrupt
    /// framing, invalid region name, or host I/O failure. An incomplete final
    /// record is treated as an uncommitted tail and truncated. Once a footer
    /// exists, recovery reads the footer, the named snapshot commit, and a
    /// bounded tail of later records ending at that footer sequence.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let open_lock = OpenReclaimLock::for_path(&path)?;
        let swap_guard = open_lock.lock();
        let mut file = reclaim::recover_artifacts(&path)?;
        // A descriptor opened before replacement may acquire the retired
        // inode lock after publication. It must never become a writer.
        require_current(&file, &path)?;
        let length = file.metadata()?.len();
        if length == 0 {
            file.write_all(&VOLUME_MAGIC)?;
            file.sync_all()?;
        } else {
            let mut magic = [0_u8; VOLUME_MAGIC.len()];
            file.read_exact(&mut magic)?;
            if magic != VOLUME_MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Astrid volume header",
                ));
            }
        }
        let recovery = recover::recover_container(&mut file)?;
        if file.metadata()?.len() != recovery.valid_len && !recovery.footer_present {
            file.set_len(recovery.valid_len)?;
            file.sync_all()?;
        }
        let footer_pending = !recovery.footer_present;
        let mut state = ContainerState {
            file,
            sequence: recovery.sequence,
            valid_len: recovery.valid_len,
            durable_len: recovery.durable_len,
            last_commit_offset: recovery.last_commit_offset,
            last_snapshot_end: recovery.last_snapshot_end,
            boundary_pending: false,
            footer_pending,
            flush_state: super::FlushState::Required,
            publication_pending: false,
            #[cfg(windows)]
            restore: super::RestoreState::NotRequired,
            regions: recovery.regions,
        };
        if footer_pending {
            // A header-only recovery is immediately upgraded so the next boot
            // can use the footer even when no caller performs an explicit sync.
            if recover::snapshot_bytes(&state.regions)? > recover::MAX_COMMIT_SNAPSHOT_BYTES {
                reclaim::reclaim_locked(&path, &mut state)?;
            }
            HostedFileVolume::make_durable(&mut state)?;
        }
        reclaim::cleanup_artifacts(&path)?;
        drop(swap_guard);
        Ok(Arc::new(Self {
            path,
            open_lock,
            state: Mutex::new(state),
        }))
    }
}

pub(super) fn open_regular(path: &Path, create: bool) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create);
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
    let file = match options.open(path) {
        Ok(file) => file,
        // Another process can win first creation after absence was observed.
        // Open its inode without creation and let the common lock/identity
        // checks decide ownership. Never truncate or retry creation.
        Err(error) if create && error.kind() == io::ErrorKind::AlreadyExists => {
            return open_regular(path, false);
        },
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Astrid volume is not a regular file",
        ));
    }
    Ok(file)
}

pub(super) fn require_current(file: &std::fs::File, path: &Path) -> io::Result<()> {
    let current = open_regular(path, false)?;
    if same_file::Handle::from_file(file.try_clone()?)? != same_file::Handle::from_file(current)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Astrid volume inode changed while opening",
        ));
    }
    Ok(())
}
