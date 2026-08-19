//! Serialized open and reclaim coordination for hosted volume containers.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock, Weak};

use fs2::FileExt as _;
use parking_lot::{Mutex, MutexGuard};

use super::{ContainerState, HostedFileVolume, VOLUME_MAGIC, reclaim, recover_container};

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
    /// record, invalid region name, or host I/O failure. An incomplete final
    /// record is treated as an uncommitted tail and truncated.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let open_lock = OpenReclaimLock::for_path(&path)?;
        let swap_guard = open_lock.lock();
        reclaim::recover_artifacts(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
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
        let mut file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Astrid volume is not a regular file",
            ));
        }
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(io::ErrorKind::WouldBlock, "Astrid volume is already open")
            } else {
                error
            }
        })?;
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
        let (regions, sequence, valid_len, durable_len) = recover_container(&mut file)?;
        if file.metadata()?.len() != valid_len {
            file.set_len(valid_len)?;
            file.sync_all()?;
        }
        drop(swap_guard);
        Ok(Arc::new(Self {
            path,
            open_lock,
            state: Mutex::new(ContainerState {
                file,
                sequence,
                valid_len,
                durable_len,
                boundary_pending: false,
                regions,
            }),
        }))
    }
}
