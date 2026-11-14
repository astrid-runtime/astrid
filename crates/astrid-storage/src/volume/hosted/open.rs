//! Serialized open and reclaim coordination for hosted volume containers.

use super::IndexCheckpoint;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock, Weak};

use parking_lot::{Mutex, MutexGuard};

use super::{ContainerState, HostedFileVolume, VOLUME_MAGIC, reclaim, recover};

type SharedOpenReclaimLock = Mutex<()>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum OpenMode {
    Ordinary,
    ExistingCanonical,
}

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
    /// bounded tail of later records ending at that footer sequence. Paged
    /// checkpoints additionally verify every referenced immutable metadata
    /// page with bounded working memory before exposing the namespace.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Arc<Self>> {
        Self::open_with_retained(
            path,
            OpenMode::Ordinary,
            #[cfg(windows)]
            None,
        )
    }

    /// Open a volume file under an already-admitted Windows runtime root.
    ///
    /// `path` must be a direct child of the retained root (root-level media).
    /// Recovery/reclaim algorithms match [`Self::open`].
    #[cfg(windows)]
    pub(crate) fn open_runtime(
        retained_root: std::sync::Arc<
            astrid_core::platform_fs::directory_capability::RetainedPrivateRoot,
        >,
        path: impl AsRef<Path>,
    ) -> io::Result<Arc<Self>> {
        let path = std::path::absolute(path.as_ref())?;
        if path.parent() != Some(retained_root.path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Astrid volume path is outside the admitted runtime root",
            ));
        }
        Self::open_with_retained(path, OpenMode::Ordinary, Some(retained_root))
    }

    /// Recover only the named, already-existing canonical inode.
    ///
    /// Unlike ordinary open this cannot create media or promote/clean swap
    /// artifacts. Physical container recovery remains shared; logical authority
    /// must be authenticated by the caller before ordinary assembly begins.
    pub(crate) fn open_existing_canonical(
        path: impl AsRef<Path>,
        #[cfg(windows)] retained_root: std::sync::Arc<
            astrid_core::platform_fs::directory_capability::RetainedPrivateRoot,
        >,
    ) -> io::Result<Arc<Self>> {
        Self::open_with_retained(
            path,
            OpenMode::ExistingCanonical,
            #[cfg(windows)]
            Some(retained_root),
        )
    }

    /// Release obsolete swap artifacts after recovery authority is accepted.
    pub(crate) fn finish_canonical_recovery(&self) -> io::Result<()> {
        let _guard = self.open_lock.lock();
        require_current(&self.state.lock().file, &self.path)?;
        reclaim::cleanup_artifacts(&self.path)
    }

    fn open_with_retained(
        path: impl AsRef<Path>,
        mode: OpenMode,
        #[cfg(windows)] retained_root: Option<
            std::sync::Arc<astrid_core::platform_fs::directory_capability::RetainedPrivateRoot>,
        >,
    ) -> io::Result<Arc<Self>> {
        // Capture relative-path ownership once; later sync and reclaim must
        // still target this volume if the process changes its directory.
        let path = std::path::absolute(path.as_ref())?;
        let existing_only = mode == OpenMode::ExistingCanonical;
        #[cfg(windows)]
        if let Some(root) = &retained_root
            && path.parent() != Some(root.path())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Astrid volume path is outside the admitted runtime root",
            ));
        }
        #[cfg(windows)]
        let runtime_private = retained_root.is_some();
        #[cfg(not(windows))]
        let create_parent = true;
        #[cfg(windows)]
        let create_parent = !runtime_private;
        if !existing_only
            && create_parent
            && let Some(parent) = path.parent()
        {
            std::fs::create_dir_all(parent)?;
        }
        let open_lock = OpenReclaimLock::for_path(&path)?;
        let swap_guard = open_lock.lock();
        let mut file = open_locked_media(
            &path,
            mode,
            #[cfg(windows)]
            runtime_private,
        )?;
        let length = file.metadata()?.len();
        if length == 0 && existing_only {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "existing Astrid volume is empty",
            ));
        }
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
            checkpoint_format: recovery.checkpoint_format,
            index_checkpoint: IndexCheckpoint::NotPrepared,
            file,
            sequence: recovery.sequence,
            valid_len: recovery.valid_len,
            durable_len: recovery.durable_len,
            last_commit_offset: recovery.last_commit_offset,
            last_snapshot_end: recovery.last_snapshot_end,
            boundary_pending: false,
            footer_pending,
            physical_tail: if recovery.footer_present {
                super::PhysicalTail::Footer
            } else {
                super::PhysicalTail::Exact
            },
            flush_state: super::FlushState::Required,
            // A process may have exited after replacing this inode but before
            // flushing the directory. A valid footer cannot prove that the
            // directory entry is durable; the first sync must confirm it.
            publication_pending: cfg!(unix),
            #[cfg(windows)]
            restore: super::RestoreState::NotRequired,
            regions: recovery.regions,
        };
        if footer_pending {
            // A header-only recovery is immediately upgraded so the next boot
            // can use the footer even when no caller performs an explicit sync.
            HostedFileVolume::make_durable(&mut state)?;
        }
        if !existing_only {
            reclaim::cleanup_artifacts(&path)?;
        }
        drop(swap_guard);
        Ok(Arc::new(Self {
            path,
            open_lock,
            state: Mutex::new(state),
            #[cfg(windows)]
            retained_root,
        }))
    }
}

fn open_locked_media(
    path: &Path,
    mode: OpenMode,
    #[cfg(windows)] runtime_private: bool,
) -> io::Result<std::fs::File> {
    let file = match mode {
        OpenMode::ExistingCanonical => {
            astrid_core::platform_fs::validate_private_file(path)?;
            let file = open_regular(
                path,
                false,
                #[cfg(windows)]
                runtime_private,
            )?;
            reclaim::lock_active(&file)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                let metadata = file.metadata()?;
                if metadata.uid() != nix::unistd::getuid().as_raw()
                    || metadata.mode() & 0o777 != 0o600
                    || metadata.nlink() != 1
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "existing canonical volume handle is not private single-link media",
                    ));
                }
            }
            file
        },
        OpenMode::Ordinary => reclaim::recover_artifacts(
            path,
            #[cfg(windows)]
            runtime_private,
        )?,
    };
    // A descriptor opened before replacement may acquire the retired inode
    // lock after publication. It must never become a writer.
    require_current(&file, path)?;
    Ok(file)
}

pub(super) fn open_regular(
    path: &Path,
    create: bool,
    #[cfg(windows)] runtime_private: bool,
) -> io::Result<std::fs::File> {
    #[cfg(windows)]
    if runtime_private {
        return open_private_regular(path, create);
    }
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
            return open_regular(
                path,
                false,
                #[cfg(windows)]
                false,
            );
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
    let current = open_regular(
        path,
        false,
        #[cfg(windows)]
        false,
    )?;
    if same_file::Handle::from_file(file.try_clone()?)? != same_file::Handle::from_file(current)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Astrid volume inode changed while opening",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn open_private_regular(path: &Path, create: bool) -> io::Result<std::fs::File> {
    if create {
        match astrid_core::platform_fs::create_new_private_file_shared(path) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error),
        }
    }
    // Validate the opened inode itself. Never repair an untrusted existing
    // volume, or close/reopen a new inode to change its sharing contract.
    let file = open_regular(path, false, false)?;
    astrid_core::platform_fs::validate_private_file_handle(&file)?;
    Ok(file)
}
